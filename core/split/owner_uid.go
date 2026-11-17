package split

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UIDOwner finds the app behind a connection on Android, where apps are
// told apart by their user ID: Proc.PID is the UID, Proc.Path the app's
// package and Proc.Alt the other packages sharing that UID.
type UIDOwner struct {
	// UID asks the system (Android 10+: ConnectivityManager.
	// getConnectionOwnerUid); a negative answer means unknown, and the
	// kernel's tables (/proc/net, readable before Android 10) are tried.
	UID func(proto uint8, local, remote netip.AddrPort) int
	// Names returns the packages with a UID.
	Names func(uid int) []string

	mu    sync.Mutex
	names map[int]uidNames
}

type uidNames struct {
	names []string
	at    time.Time
}

const uidNamesTTL = time.Minute

func (o *UIDOwner) Lookup(proto uint8, local, remote netip.AddrPort, _ bool) *Proc {
	uid := -1
	if o.UID != nil {
		uid = o.UID(proto, local, remote)
	}
	if uid < 0 {
		uid = procNetUID(proto, local, remote)
	}
	if uid < 0 {
		return nil
	}
	p := &Proc{PID: uint32(uid)}
	if n := o.namesOf(uid); len(n) > 0 {
		p.Path, p.Alt = n[0], n[1:]
	}
	return p
}

func (o *UIDOwner) namesOf(uid int) []string {
	o.mu.Lock()
	e, ok := o.names[uid]
	o.mu.Unlock()
	if ok && time.Since(e.at) < uidNamesTTL {
		return e.names
	}
	var n []string
	if o.Names != nil {
		n = o.Names(uid)
	}
	o.mu.Lock()
	if o.names == nil || len(o.names) > 2048 {
		o.names = map[int]uidNames{}
	}
	o.names[uid] = uidNames{n, time.Now()}
	o.mu.Unlock()
	return n
}

// procNetUID finds a socket's owner in /proc/net/{tcp,udp}[6] (-1: not
// found or not readable, as on Android 10 and later).
func procNetUID(proto uint8, local, remote netip.AddrPort) int {
	var files []string
	switch proto {
	case protoTCP:
		files = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	case protoUDP:
		files = []string{"/proc/net/udp", "/proc/net/udp6"}
	default:
		return -1
	}
	for _, f := range files {
		if uid := scanProcNet(f, proto, local, remote); uid >= 0 {
			return uid
		}
	}
	return -1
}

func scanProcNet(path string, proto uint8, local, remote netip.AddrPort) int {
	f, err := os.Open(path)
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	best := -1
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 8 {
			continue
		}
		la, ok1 := parseProcAddr(fs[1])
		ra, ok2 := parseProcAddr(fs[2])
		if !ok1 || !ok2 || la.Port() != local.Port() {
			continue
		}
		if !la.Addr().IsUnspecified() && la.Addr() != local.Addr() {
			continue
		}
		uid, err := strconv.Atoi(fs[7])
		if err != nil {
			continue
		}
		if proto == protoTCP {
			if ra == remote {
				return uid
			}
			continue
		}
		// UDP: a connected socket to this remote, else any on the port.
		if ra == remote {
			return uid
		}
		if ra.Port() == 0 {
			best = uid
		}
	}
	return best
}

// parseProcAddr reads "0100007F:0035" (IPv4) or the 32-digit IPv6 form,
// both in the kernel's byte order per 32-bit word. IPv4-mapped IPv6
// addresses come back as IPv4.
func parseProcAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i+4 <= len(b); i += 4 { // little-endian words
		binary.BigEndian.PutUint32(b[i:], binary.LittleEndian.Uint32(b[i:]))
	}
	var a netip.Addr
	if len(b) == 4 {
		a = netip.AddrFrom4([4]byte(b))
	} else {
		a = netip.AddrFrom16([16]byte(b)).Unmap()
	}
	return netip.AddrPortFrom(a, uint16(port)), true
}
