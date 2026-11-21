package engine

// The log lines a report carries (stats.go). A failure logs many lines at
// once, and those are the lines that explain it, so they must not be the
// ones lost: lines of one kind (the same text but for numbers) within a
// minute become one entry with a count, the time of the last and its text;
// when there are still too many, routine lines (idle mode, credentials,
// probes) go before the rest, and the user's marks go last of all.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Jetvac/turn-vk-client/core/redact"
)

type statsEvent struct {
	T   int64  `json:"t"` // unix ms
	Msg string `json:"m"`
	// N: lines of this kind in the minute (with the first, Msg); the last
	// one came at Last, and read Msg2 when its text differed.
	N    int    `json:"n,omitempty"`
	Last int64  `json:"t2,omitempty"`
	Msg2 string `json:"m2,omitempty"`

	key   string
	level int
}

// Levels of the lines: what goes first when a report is full.
const (
	evRoutine = iota
	evNormal
	evMark // the user's marks (Mark)
)

// routineLines: lines that come in the normal course of things.
var routineLines = []string{
	"idle: ", "traffic again", "TURN credentials", "answer a probe", "joining as new guest",
	"moves to guest", "last minute:",
}

func eventLevel(msg string) int {
	for _, s := range routineLines {
		if strings.Contains(msg, s) {
			return evRoutine
		}
	}
	return evNormal
}

// moreLike: the note the engine's own log limiter adds (offline.go).
var moreLike = regexp.MustCompile(` \(and (\d+) more like it\)$`)

// StatsEvent adds a line to the next report (the apps' own events, such
// as the check after connecting).
func StatsEvent(format string, args ...any) {
	noteEvent(fmt.Sprintf(format, args...))
}

func noteEvent(msg string) { addEvent(msg, eventLevel(msg), time.Now()) }

func addEvent(msg string, level int, now time.Time) {
	msg = cutEvent(redact.String(msg), level)
	n := 1
	if m := moreLike.FindStringSubmatchIndex(msg); m != nil {
		more, _ := strconv.Atoi(msg[m[2]:m[3]])
		n += more
		msg = msg[:m[0]]
	}
	at := now.UnixMilli()
	key := ""
	if level != evMark {
		key = logTemplate(msg)
	}
	statsQ.mu.Lock()
	defer statsQ.mu.Unlock()
	if key != "" {
		for i := range statsQ.events {
			ev := &statsQ.events[i]
			if ev.key != key {
				continue
			}
			ev.N = max(ev.N, 1) + n
			ev.Last = at
			if msg != ev.Msg {
				ev.Msg2 = msg
			} else {
				ev.Msg2 = ""
			}
			return
		}
	}
	ev := statsEvent{T: at, Msg: msg, key: key, level: level}
	if n > 1 {
		ev.N = n
	}
	if len(statsQ.events) >= statsEventsMax {
		// Room for it: the least important line goes, if one is less
		// important than this one.
		if least := leastEvent(statsQ.events); statsQ.events[least].level < level {
			statsQ.events = append(statsQ.events[:least], statsQ.events[least+1:]...)
			statsQ.dropped++
		} else {
			statsQ.dropped++
			return
		}
	}
	statsQ.events = append(statsQ.events, ev)
}

// cutEvent shortens a long line; a mark may be twice as long (the user's
// words and the state).
func cutEvent(msg string, level int) string {
	limit := statsEventLen
	if level == evMark {
		limit *= 2
	}
	if len(msg) <= limit {
		return msg
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(msg[cut]) { // not inside a character
		cut--
	}
	return msg[:cut] + "…"
}

// leastEvent: the oldest of the least important events.
func leastEvent(events []statsEvent) int {
	j := 0
	for i, ev := range events {
		if ev.level < events[j].level {
			j = i
		}
	}
	return j
}

// dropLeast leaves out k events, the least important and oldest first,
// keeping the order of the rest.
func dropLeast(events []statsEvent, k int) []statsEvent {
	out := append([]statsEvent(nil), events...)
	for ; k > 0 && len(out) > 0; k-- {
		i := leastEvent(out)
		out = append(out[:i], out[i+1:]...)
	}
	return out
}

// Downtime: a connection ended, and until the next one is up there is
// nothing to report. The next one says for how long and why, so a gap in
// the reports is not a mystery.

// noteDown records that the connection ended (the first end counts: a
// failed attempt after it does not move it).
func noteDown(why string, now time.Time) {
	statsQ.mu.Lock()
	defer statsQ.mu.Unlock()
	if statsQ.down.IsZero() {
		statsQ.down, statsQ.downWhy = now, why
	}
}

// takeDown returns the line for a connection that came up after one
// that ended, once.
func takeDown(now time.Time) (string, bool) {
	statsQ.mu.Lock()
	defer statsQ.mu.Unlock()
	if statsQ.down.IsZero() {
		return "", false
	}
	d, why := now.Sub(statsQ.down), statsQ.downWhy
	statsQ.down, statsQ.downWhy = time.Time{}, ""
	return fmt.Sprintf("connected again after %s without a connection (the previous one: %s)", d.Round(time.Second), why), true
}

// Mark notes that the user says something is wrong right now, with what
// they wrote (may be empty) and the state of the connection (e may be
// nil: not connected). The line goes to the next report and is never
// dropped for other lines; the apps also put it into their own logs.
func Mark(e *Engine, note string) string {
	note = strings.Join(strings.Fields(note), " ")
	if r := []rune(note); len(r) > 200 {
		note = string(r[:200]) + "…"
	}
	var b strings.Builder
	b.WriteString("user mark: something is wrong now")
	if note != "" {
		fmt.Fprintf(&b, ": «%s»", note)
	}
	if e == nil {
		b.WriteString(" (not connected)")
	} else {
		st := e.Status()
		fresh := 0
		for _, p := range st.Paths {
			if p.Fresh {
				fresh++
			}
		}
		fmt.Fprintf(&b, " (%s, %d of %d routes answer, ping %d ms", st.State, fresh, len(st.Paths), st.RTT)
		if st.Quiet {
			b.WriteString(", idle mode")
		}
		if _, _, hs, ok := e.wgStats(); ok && !hs.IsZero() {
			fmt.Fprintf(&b, ", WireGuard handshake %s ago", time.Since(hs).Round(time.Second))
		}
		b.WriteString(")")
	}
	line := b.String()
	addEvent(line, evMark, time.Now())
	return line
}
