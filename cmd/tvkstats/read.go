package main

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The records a TurnVK server writes (wdtt-router internal/wdtt/stats.go):
// "client" holds a client's report as it sent it (core/engine/stats.go),
// "device" the server's own view of a device each minute.

type record struct {
	Type string          `json:"type"`
	Dev  string          `json:"dev"`
	T    int64           `json:"t"`
	R    json.RawMessage `json:"r"`
}

type report struct {
	Client string   `json:"client"`
	Power  string   `json:"power"`
	Seq    int      `json:"seq"`
	Run    uint32   `json:"run"`
	Part   int      `json:"part"`
	M      []minute `json:"m"`
	Ev     []event  `json:"ev"`
	Lost   *struct {
		N    int   `json:"n"`
		From int64 `json:"from"`
		To   int64 `json:"to"`
	} `json:"lost"`
}

type lat struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	Max float64 `json:"max"`
}

type netState struct {
	Kind    string `json:"kind"`
	Cell    string `json:"cell"`
	RSSI    int    `json:"rssi"`
	Bars    *int   `json:"bars"`
	Q       int    `json:"q"`
	Mbps    int    `json:"mbps"`
	MHz     int    `json:"mhz"`
	Changes int    `json:"chg"`
}

type minute struct {
	T          int64     `json:"t"`
	State      string    `json:"state"`
	Rx         uint64    `json:"rx"`
	Tx         uint64    `json:"tx"`
	Routes     int       `json:"routes"`
	Fresh      int       `json:"fresh"`
	Target     int       `json:"target"`
	RTT        int       `json:"rtt"`
	Lost       uint64    `json:"lost"`
	RxPk       uint64    `json:"rx_pk"`
	Reconnects uint64    `json:"reconnects"`
	Slept      bool      `json:"slept"`
	Gap        int       `json:"gap"`
	Quiet      uint64    `json:"quiet"`
	Light      uint64    `json:"light"`
	Ping       *lat      `json:"ping"`
	Net        *netState `json:"net"`

	at     time.Time
	client string
}

type event struct {
	T  int64  `json:"t"`
	M  string `json:"m"`
	N  int    `json:"n"`
	T2 int64  `json:"t2"`
	M2 string `json:"m2"`

	at time.Time
}

// device: what the archive holds about one device.
type device struct {
	id       string
	versions []string // in the order they appeared
	mins     []*minute
	events   []*event
	lost     int // reports the client's queue let go
}

type archive struct {
	devs map[string]*device
}

func (a *archive) list() []*device {
	out := make([]*device, 0, len(a.devs))
	for _, d := range a.devs {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// find: the device whose id starts with prefix.
func (a *archive) find(prefix string) (*device, error) {
	var hit []*device
	for _, d := range a.list() {
		if strings.HasPrefix(d.id, prefix) {
			hit = append(hit, d)
		}
	}
	switch len(hit) {
	case 1:
		return hit[0], nil
	case 0:
		return nil, fmt.Errorf("no device %q in the archive", prefix)
	}
	var ids []string
	for _, d := range hit {
		ids = append(ids, d.id)
	}
	return nil, fmt.Errorf("%q matches %s", prefix, strings.Join(ids, ", "))
}

// load reads a zip from the panel, a folder of hourly files, or one file.
func load(path string) (*archive, error) {
	a := &archive{devs: map[string]*device{}}
	seenMin := map[string]bool{}
	seenEv := map[string]bool{}
	add := func(r io.Reader, name string) error {
		if strings.HasSuffix(name, ".gz") {
			zr, err := gzip.NewReader(r)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			defer zr.Close()
			r = zr
		}
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1<<20), 1<<22)
		for sc.Scan() {
			var rec record
			if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Type != "client" {
				continue
			}
			var rep report
			if json.Unmarshal(rec.R, &rep) != nil {
				continue
			}
			d := a.devs[rec.Dev]
			if d == nil {
				d = &device{id: rec.Dev}
				a.devs[rec.Dev] = d
			}
			if rep.Client != "" && (len(d.versions) == 0 || d.versions[len(d.versions)-1] != rep.Client) {
				d.versions = append(d.versions, rep.Client)
			}
			if rep.Lost != nil {
				d.lost += rep.Lost.N
			}
			for i := range rep.M {
				m := &rep.M[i]
				// A report sent again (its acknowledgement lost) counts once.
				k := fmt.Sprint(rec.Dev, m.T)
				if seenMin[k] {
					continue
				}
				seenMin[k] = true
				m.at, m.client = time.UnixMilli(m.T), rep.Client
				d.mins = append(d.mins, m)
			}
			for i := range rep.Ev {
				e := &rep.Ev[i]
				k := fmt.Sprint(rec.Dev, e.T, e.M)
				if seenEv[k] {
					continue
				}
				seenEv[k] = true
				e.at = time.UnixMilli(e.T)
				d.events = append(d.events, e)
			}
		}
		return sc.Err()
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	switch {
	case st.IsDir():
		files, _ := filepath.Glob(filepath.Join(path, "*.jsonl*"))
		for _, f := range files {
			if err := addFile(f, add); err != nil {
				return nil, err
			}
		}
	case strings.HasSuffix(strings.ToLower(path), ".zip"):
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		for _, f := range zr.File {
			if !strings.Contains(f.Name, ".jsonl") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			err = add(rc, f.Name)
			rc.Close()
			if err != nil {
				return nil, err
			}
		}
	default:
		if err := addFile(path, add); err != nil {
			return nil, err
		}
	}
	for _, d := range a.devs {
		sort.Slice(d.mins, func(i, j int) bool { return d.mins[i].T < d.mins[j].T })
		sort.Slice(d.events, func(i, j int) bool { return d.events[i].T < d.events[j].T })
	}
	return a, nil
}

func addFile(path string, add func(io.Reader, string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return add(f, path)
}
