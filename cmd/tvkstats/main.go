// Command tvkstats reads the statistics TurnVK clients send to a TurnVK
// server (the archive the server's panel downloads) and tells what
// happened to a device: a timeline, its events and its user's marks, and
// for each stretch that went badly whose side the trouble was on, by
// comparing the device with the other devices at the same time.
//
//	tvkstats stats.zip                       the devices in the archive
//	tvkstats -dev d4f5 stats.zip             one device, every 10 minutes
//	tvkstats -dev d4f5 -at 08:30 stats.zip   minute by minute around 08:30
//	tvkstats -dev d4f5 -from "11-21 07:00" -to 10:00 -every 5m stats.zip
//
// Times are local (or -tz, such as +3); the archive's are UTC.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	dev := flag.String("dev", "", "device id, or its first characters")
	fromS := flag.String("from", "", `start: "2006-01-02 15:04", "01-02 15:04" or "15:04"`)
	toS := flag.String("to", "", "end, as -from")
	atS := flag.String("at", "", "a moment to look at minute by minute (±15 minutes), as -from")
	every := flag.Duration("every", 10*time.Minute, "timeline step")
	tzS := flag.String("tz", "", "time zone as hours from UTC, such as +3 (default: this computer's)")
	all := flag.Bool("all", false, "routine events too (idle mode, credentials, probes)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tvkstats [flags] stats.zip | folder | file.jsonl[.gz]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	tz := time.Local
	if *tzS != "" {
		h, err := strconv.ParseFloat(strings.TrimPrefix(*tzS, "UTC"), 64)
		if err != nil {
			fail(fmt.Errorf("-tz %q: %w", *tzS, err))
		}
		tz = time.FixedZone(*tzS, int(h*3600))
	}
	a, err := load(flag.Arg(0))
	if err != nil {
		fail(err)
	}
	if *dev == "" {
		overview(os.Stdout, a, tz)
		return
	}
	d, err := a.find(*dev)
	if err != nil {
		fail(err)
	}
	if len(d.mins) == 0 {
		fail(fmt.Errorf("%s sent no minutes", d.id))
	}
	last := d.mins[len(d.mins)-1].at.In(tz)
	from, to := d.mins[0].at, last.Add(time.Minute)
	if *atS != "" {
		at, err := parseTime(*atS, last, tz)
		if err != nil {
			fail(err)
		}
		from, to, *every = at.Add(-15*time.Minute), at.Add(15*time.Minute), time.Minute
	}
	if *fromS != "" {
		if from, err = parseTime(*fromS, last, tz); err != nil {
			fail(err)
		}
	}
	if *toS != "" {
		// A bare time is on -from's day, or the next.
		if to, err = parseTime(*toS, from.In(tz), tz); err != nil {
			fail(err)
		}
		if !to.After(from) && !strings.Contains(*toS, "-") {
			to = to.AddDate(0, 0, 1)
		}
	}
	if !to.After(from) || *every < time.Minute {
		fail(fmt.Errorf("nothing to show: from %s to %s every %s", from.In(tz), to.In(tz), *every))
	}
	show(os.Stdout, a, d, from, to, *every, tz, *all)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tvkstats:", err)
	os.Exit(1)
}

// parseTime reads a time in tz; the date or year left out are those of
// ref (the device's last minute).
func parseTime(s string, ref time.Time, tz *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, f := range []string{"2006-01-02 15:04", "01-02 15:04", "15:04"} {
		t, err := time.ParseInLocation(f, s, tz)
		if err != nil {
			continue
		}
		switch f {
		case "01-02 15:04":
			t = time.Date(ref.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, tz)
		case "15:04":
			t = time.Date(ref.Year(), ref.Month(), ref.Day(), t.Hour(), t.Minute(), 0, 0, tz)
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("time %q: want 2006-01-02 15:04, 01-02 15:04 or 15:04", s)
}

func stamp(t time.Time, tz *time.Location) string { return t.In(tz).Format("01-02 15:04") }

// overview lists the devices.
func overview(w io.Writer, a *archive, tz *time.Location) {
	base := bases(a)
	newest := ""
	for _, d := range a.devs {
		if len(d.versions) > 0 && newer(d.versions[len(d.versions)-1], newest) {
			newest = d.versions[len(d.versions)-1]
		}
	}
	fmt.Fprintf(w, "%-22s %-24s %-23s %6s %6s %6s %7s %5s\n", "device", "version", "reports (local time)", "min", "ping", "loss", "trouble", "marks")
	for _, d := range a.list() {
		if len(d.mins) == 0 {
			continue
		}
		var g agg
		for _, m := range d.mins {
			g.add(m)
		}
		troubles, marks := 0, 0
		for _, e := range d.events {
			if isTrouble(e.M) {
				troubles += max(e.N, 1)
			}
			if isMark(e.M) {
				marks++
			}
		}
		v := d.versions[len(d.versions)-1]
		short := strings.TrimPrefix(v, "TurnVK ")
		if newest != "" && newer(newest, v) {
			short += " (old)"
		}
		fmt.Fprintf(w, "%-22s %-24s %-23s %6d %4d ms %6s %7d %5d\n", d.id, short,
			stamp(d.mins[0].at, tz)+" – "+d.mins[len(d.mins)-1].at.In(tz).Format("15:04"),
			g.n, base[d.id], lossText(g.loss()), troubles, marks)
	}
	fmt.Fprintln(w, "\nOne device: tvkstats -dev <first characters of its id> <archive>")
}

// newer: version a ("TurnVK 0.9.1 windows") is newer than b.
func newer(a, b string) bool {
	pa, pb := vparts(a), vparts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func vparts(s string) [3]int {
	var p [3]int
	f := strings.Fields(s)
	if len(f) < 2 {
		return p
	}
	for i, x := range strings.SplitN(f[1], ".", 3) {
		p[i], _ = strconv.Atoi(x)
	}
	return p
}

func lossText(l float64) string {
	if l < 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", l)
}

// bases: each device's usual ping.
func bases(a *archive) map[string]int {
	b := map[string]int{}
	for _, d := range a.devs {
		b[d.id] = usual(d.mins)
	}
	return b
}

// show prints one device from from to to.
func show(w io.Writer, a *archive, d *device, from, to time.Time, every time.Duration, tz *time.Location, all bool) {
	base := bases(a)
	mins := between(d.mins, from, to)
	evs := between(d.events, from, to)
	fmt.Fprintf(w, "%s: %s\n", d.id, strings.Join(d.versions, " → "))
	fmt.Fprintf(w, "%s – %s (UTC%s), %d minutes reported, usual ping %d ms", stamp(from, tz), stamp(to, tz), from.In(tz).Format("-07:00"), len(mins), base[d.id])
	if d.lost > 0 {
		fmt.Fprintf(w, ", %d reports lost in the client's queue", d.lost)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "\n%-11s %-10s %6s %13s %6s %-22s %-28s %s\n", "time", "state", "routes", "ping (p95)", "loss", "others: ping loss (n)", "network", "")
	type bad struct {
		from, to time.Time
		why      string
	}
	var bads []bad
	for t := from; t.Before(to); t = t.Add(every) {
		end := t.Add(every)
		var g agg
		for _, m := range between(mins, t, end) {
			g.add(m)
		}
		bev := between(evs, t, end)
		// A dozing phone reports no minutes, but its events count: a stall
		// on waking is judged on them alone.
		if g.n == 0 && !anyTrouble(bev) {
			if why := gapReason(d, t, end); why != "" {
				fmt.Fprintf(w, "%-11s %s\n", stamp(t, tz), why)
			}
			continue
		}
		o := compare(a, d, base, t, end)
		v := verdict(&g, base[d.id], bev, o)
		if v != "" {
			if n := len(bads); n > 0 && bads[n-1].why == v && !bads[n-1].to.Before(t) {
				bads[n-1].to = end
			} else {
				bads = append(bads, bad{t, end, v})
			}
		}
		fmt.Fprintln(w, row(stamp(t, tz), &g, o, bev, v))
	}

	fmt.Fprintln(w, "\nEvents")
	shown := 0
	for _, e := range evs {
		if !all && isRoutine(e.M) {
			continue
		}
		shown++
		line := e.at.In(tz).Format("01-02 15:04:05") + "  " + e.M
		if e.N > 1 {
			line += fmt.Sprintf("  ×%d, last at %s", e.N, time.UnixMilli(e.T2).In(tz).Format("15:04:05"))
			if e.M2 != "" {
				line += ": " + e.M2
			}
		}
		fmt.Fprintln(w, line)
	}
	if shown == 0 {
		fmt.Fprintln(w, "none")
	}

	for _, e := range evs {
		if !isMark(e.M) {
			continue
		}
		fmt.Fprintf(w, "\nThe user's mark at %s: %s\n", e.at.In(tz).Format("15:04:05"), strings.TrimPrefix(e.M, "user mark: "))
		start := e.at.Truncate(time.Minute).Add(-5 * time.Minute)
		var g agg
		for t := start; t.Before(start.Add(11 * time.Minute)); t = t.Add(time.Minute) {
			var mg agg
			for _, m := range between(mins, t, t.Add(time.Minute)) {
				mg.add(m)
				g.add(m)
			}
			if mg.n > 0 {
				fmt.Fprintln(w, row(t.In(tz).Format("15:04"), &mg, compare(a, d, base, t, t.Add(time.Minute)), between(evs, t, t.Add(time.Minute)), ""))
			}
		}
		v := verdict(&g, base[d.id], between(evs, start, start.Add(11*time.Minute)), compare(a, d, base, start, start.Add(11*time.Minute)))
		if v == "" {
			v = "the tunnel was fine around then: look at the app or the site itself"
		}
		fmt.Fprintln(w, "→", v)
	}

	fmt.Fprintln(w, "\nVerdict")
	if len(bads) == 0 {
		fmt.Fprintln(w, "no trouble in this time")
	}
	for _, b := range bads {
		fmt.Fprintf(w, "%s – %s  %s\n", stamp(b.from, tz), b.to.In(tz).Format("15:04"), b.why)
	}
}

// anyTrouble: some event among evs means the connection had a problem.
func anyTrouble(evs []*event) bool {
	for _, e := range evs {
		if isTrouble(e.M) {
			return true
		}
	}
	return false
}

func row(when string, g *agg, o others, evs []*event, v string) string {
	state := "connected"
	if g.notUp > 0 {
		state = "down " + strconv.Itoa(g.notUp) + "m"
	}
	if g.light >= uint64(30*g.n) {
		state = "light"
	}
	if g.quiet >= uint64(30*g.n) {
		state = "idle"
	}
	if g.n == 0 {
		state = "asleep"
	}
	if g.slept {
		state += " zz"
	}
	ping := "—"
	if r := g.rtt(); r > 0 {
		ping = fmt.Sprintf("%d (%.0f)", r, g.p95)
	}
	net := netText(g.net)
	if g.netChanges > 0 {
		net += fmt.Sprintf(" ↻%d", g.netChanges)
	}
	n := 0
	for _, e := range evs {
		if isTrouble(e.M) || isMark(e.M) {
			n += max(e.N, 1)
		}
	}
	extra := ""
	if n > 0 {
		extra = fmt.Sprintf("%d ev", n)
	}
	if v != "" {
		extra += " → " + v
	}
	return fmt.Sprintf("%-11s %-10s %6s %13s %6s %-22s %-28s %s", when, state, fmt.Sprintf("%d/%d", g.fresh, g.want), ping, lossText(g.loss()), o, net, strings.TrimSpace(extra))
}

// gapReason explains minutes without reports ("" to leave them out).
func gapReason(d *device, from, to time.Time) string {
	i := sort.Search(len(d.mins), func(i int) bool { return !d.mins[i].at.Before(to) })
	if i == len(d.mins) || i == 0 {
		return ""
	}
	next := d.mins[i]
	if next.Gap > 0 && next.at.Add(-time.Duration(next.Gap+60)*time.Second).Before(to) {
		return "asleep: the engine paused"
	}
	for _, e := range between(d.events, from, next.at.Add(time.Minute)) {
		if strings.Contains(e.M, "without a connection") || strings.HasPrefix(e.M, "stopped:") {
			return "not connected"
		}
	}
	return "no reports (not connected, or reports lost)"
}
