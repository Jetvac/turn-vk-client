//go:build windows

package split

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	getExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID    = 1 // UDP_TABLE_OWNER_PID
	procTTL             = 10 * time.Second
	treeTTL             = 2 * time.Second
)

type tcpSock struct{ local, remote netip.AddrPort }

type udpSock struct {
	addr netip.Addr
	pid  uint32
}

type procEntry struct {
	path    string
	created int64 // FILETIME as an integer; 0: unknown
	checked time.Time
}

// winOwner reads Windows' tables of sockets (the same as netstat -ano).
type winOwner struct {
	mu     sync.Mutex
	tcp    map[tcpSock]uint32
	tcpAt  time.Time
	udp    map[uint16][]udpSock
	udpAt  time.Time
	procs  map[uint32]*procEntry
	ppid   map[uint32]uint32
	treeAt time.Time
	buf    []byte
}

// NewOwner returns the Windows owner lookup.
func NewOwner() Owner {
	return &winOwner{procs: map[uint32]*procEntry{}}
}

func (o *winOwner) Lookup(proto uint8, local, remote netip.AddrPort, parents bool) *Proc {
	o.mu.Lock()
	defer o.mu.Unlock()
	pid, ok := o.find(proto, local, remote)
	if !ok {
		return nil
	}
	p := &Proc{PID: pid}
	e := o.proc(pid)
	if e == nil {
		return p
	}
	p.Path = e.path
	if parents {
		p.Parents = o.parents(pid, e)
	}
	return p
}

// find looks the socket up, reading the table again when it is not there
// (a new socket) and the table is not brand new.
func (o *winOwner) find(proto uint8, local, remote netip.AddrPort) (uint32, bool) {
	for try := 0; try < 2; try++ {
		switch proto {
		case protoTCP:
			if pid, ok := o.tcp[tcpSock{local, remote}]; ok {
				return pid, true
			}
			if try == 0 && time.Since(o.tcpAt) > time.Millisecond {
				o.readTCP()
				continue
			}
		case protoUDP:
			for _, s := range o.udp[local.Port()] {
				if s.addr == local.Addr() || s.addr.IsUnspecified() {
					return s.pid, true
				}
			}
			if try == 0 && time.Since(o.udpAt) > time.Millisecond {
				o.readUDP()
				continue
			}
		}
		break
	}
	return 0, false
}

// table calls GetExtended{Tcp,Udp}Table, growing the buffer as asked.
func (o *winOwner) table(proc *windows.LazyProc, class uintptr) []byte {
	size := uint32(len(o.buf))
	for i := 0; i < 4; i++ {
		if size == 0 {
			size = 64 << 10
		}
		if uint32(len(o.buf)) < size {
			o.buf = make([]byte, size)
		}
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&o.buf[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, class, 0)
		switch r {
		case 0:
			return o.buf[:size]
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			size += 16 << 10
			continue
		default:
			return nil
		}
	}
	return nil
}

func addrPort(b []byte) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[0:4])), binary.BigEndian.Uint16(b[4:6]))
}

func (o *winOwner) readTCP() {
	o.tcpAt = time.Now()
	b := o.table(getExtendedTcpTable, tcpTableOwnerPIDAll)
	if len(b) < 4 {
		return
	}
	n := int(binary.LittleEndian.Uint32(b))
	m := make(map[tcpSock]uint32, n)
	const row = 24 // MIB_TCPROW_OWNER_PID
	for i := 0; i < n && 4+(i+1)*row <= len(b); i++ {
		r := b[4+i*row:]
		m[tcpSock{addrPort(r[4:]), addrPort(r[12:])}] = binary.LittleEndian.Uint32(r[20:])
	}
	o.tcp = m
}

func (o *winOwner) readUDP() {
	o.udpAt = time.Now()
	b := o.table(getExtendedUdpTable, udpTableOwnerPID)
	if len(b) < 4 {
		return
	}
	n := int(binary.LittleEndian.Uint32(b))
	m := make(map[uint16][]udpSock, n)
	const row = 12 // MIB_UDPROW_OWNER_PID
	for i := 0; i < n && 4+(i+1)*row <= len(b); i++ {
		r := b[4+i*row:]
		ap := addrPort(r)
		m[ap.Port()] = append(m[ap.Port()], udpSock{ap.Addr(), binary.LittleEndian.Uint32(r[8:])})
	}
	o.udp = m
}

// proc returns the path and start time of a process, cached for a while
// and checked against the start time (process IDs are reused).
func (o *winOwner) proc(pid uint32) *procEntry {
	if pid == 0 || pid == 4 {
		return nil // idle, the kernel
	}
	e := o.procs[pid]
	if e != nil && time.Since(e.checked) < procTTL {
		return e
	}
	path, created := procInfo(pid)
	if e != nil && e.created == created && created != 0 {
		e.checked = time.Now()
		return e
	}
	if path == "" && created == 0 {
		delete(o.procs, pid)
		return nil
	}
	if len(o.procs) > 4096 {
		for k, v := range o.procs {
			if time.Since(v.checked) > procTTL {
				delete(o.procs, k)
			}
		}
	}
	e = &procEntry{path: path, created: created, checked: time.Now()}
	o.procs[pid] = e
	return e
}

func procInfo(pid uint32) (string, int64) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", 0
	}
	defer windows.CloseHandle(h)
	var created int64
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
		created = int64(c.HighDateTime)<<32 | int64(c.LowDateTime)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return "", created
	}
	return windows.UTF16ToString(buf[:n]), created
}

// parents walks up the process tree, checking that each parent started
// before its child (a parent that has exited may have left its ID to an
// unrelated process).
func (o *winOwner) parents(pid uint32, e *procEntry) []string {
	if _, ok := o.ppid[pid]; !ok || time.Since(o.treeAt) > treeTTL {
		o.readTree()
	}
	var out []string
	seen := map[uint32]bool{pid: true}
	child := e
	for len(out) < 8 {
		pp, ok := o.ppid[pid]
		if !ok || pp == 0 || seen[pp] {
			break
		}
		seen[pp] = true
		pe := o.proc(pp)
		if pe == nil || pe.path == "" || (pe.created != 0 && child.created != 0 && pe.created > child.created) {
			break
		}
		out = append(out, pe.path)
		pid, child = pp, pe
	}
	return out
}

func (o *winOwner) readTree() {
	o.treeAt = time.Now()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	m := make(map[uint32]uint32, len(o.ppid))
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		m[pe.ProcessID] = pe.ParentProcessID
	}
	o.ppid = m
}

var flushDNS = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// FlushDNS empties Windows' DNS cache, so programs ask again and get the
// answers the current rules give (placeholders for sites sent direct, real
// addresses once the rules are off or TurnVK is disconnected).
func FlushDNS() {
	if flushDNS.Find() == nil {
		flushDNS.Call()
	}
}
