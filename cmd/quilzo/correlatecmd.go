// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/quilzo/quilzo/internal/correlate"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Detections that are about several events rather than one.
//
// Sigma version 2 defines four, and they are the four questions a single
// event cannot answer: how many times, how many different things, did these
// happen together, did they happen in this order.
//
// The part every implementation gets wrong is when a window closes. The
// obvious answer is the clock and it is wrong, because events arrive late —
// a proxy buffers, an agent reconnects, a cloud export lands in five-minute
// batches. A window closed by the clock never sees them, nothing reports an
// error, and the only evidence is an absence.
//
// `correlate demo` runs the same events past both and shows the difference.

func cmdCorrelate(args []string) error {
	if len(args) == 0 {
		args = []string{"demo"}
	}
	switch args[0] {
	case "demo":
		return correlateDemo(args[1:])
	default:
		return fmt.Errorf("unknown correlate command %q; try demo", args[0])
	}
}

func correlateDemo(args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	lateBy := fs.Duration("late", 12*time.Minute,
		"how late the straggling event arrives")
	if err := fs.Parse(flags); err != nil {
		return err
	}

	src := []byte(exampleCorrelations)
	if len(pos) == 1 {
		b, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		src = b
	} else {
		w.Human("%sno path given, so this reads built-in rules%s\n\n",
			dim, reset)
	}

	rules, err := correlate.Read(src)
	if err != nil {
		return err
	}
	at := time.Now().UTC().Truncate(time.Hour)

	w.Human("%s%d correlation(s)%s\n", bold, len(rules), reset)
	for _, r := range rules {
		w.Human("  %s%-16s%s %s %sover %v, every %s%s\n", dim, r.Type,
			reset, r.Title, dim, r.Rules, plainClockSpan(r.Timespan), reset)
		if why, broad := r.Broad(); broad {
			w.Human("    %s%s%s\n", yellow, wrapAt(why, 62, "    "), reset)
		}
	}
	w.Human("\n")

	// Five failures inside the window — the threshold exactly — of which
	// the last happened inside it and arrived after the clock had moved
	// past the window's end.
	count := rules[0]
	events := []struct {
		rule string
		min  int
	}{
		{"failed_logon", 1}, {"failed_logon", 2}, {"failed_logon", 3},
		{"failed_logon", 4}, {"failed_logon", 5},
	}

	run := func(label string, watermark func(time.Time) time.Time) int {
		e, err := correlate.New(count)
		if err != nil {
			return -1
		}
		var fired int
		for i, s := range events {
			when := at.Add(time.Duration(s.min) * time.Minute)
			arrived := when
			if i == len(events)-1 {
				arrived = when.Add(*lateBy) // the straggler
			}
			if err := e.Observe(correlate.Seen{
				Rule: s.rule, Event: failure(when, "ada")},
				watermark(arrived)); err != nil {
				return -1
			}
			fired += len(e.Close(watermark(arrived)))
		}
		fired += len(e.Flush())
		_ = label
		return fired
	}

	// The clock: a window is closed as soon as wall time passes its end.
	byClock := run("clock", func(now time.Time) time.Time { return now })
	// The watermark: nothing is complete until the lateness has elapsed.
	byMark := run("watermark", func(now time.Time) time.Time {
		return correlate.Watermark(now, correlate.Safe)
	})

	w.Human("%sfive failures in a fifteen-minute window — exactly the "+
		"threshold —\nwith the last arriving %s after it happened%s\n", bold,
		plainClockSpan(*lateBy), reset)
	w.Human("  %sclosed by the clock     %s%d alert(s)%s\n", dim,
		firedColour(byClock), byClock, reset)
	w.Human("  %sclosed by the watermark %s%d alert(s)%s\n", dim,
		firedColour(byMark), byMark, reset)
	w.Human("\n  %sthe clock has already closed the window when the last "+
		"event\n  arrives, so the count stops at four and nothing fires. "+
		"Nothing\n  reports an error either: the only evidence is an "+
		"absence%s\n\n", dim, reset)

	// And the ordered correlation, which is what separates a coincidence
	// from a technique.
	var ordered correlate.Rule
	for _, r := range rules {
		if r.Type == correlate.TemporalOrdered {
			ordered = r
		}
	}
	w.Human("%s%s%s\n", bold, ordered.Title, reset)
	for _, seq := range [][]string{{"recon", "execution"},
		{"execution", "recon"}} {
		e, err := correlate.New(ordered)
		if err != nil {
			return err
		}
		for i, rule := range seq {
			x := failure(at.Add(time.Duration(i+1)*time.Minute), "ada")
			if err := e.Observe(correlate.Seen{Rule: rule, Event: x},
				at); err != nil {
				return err
			}
		}
		hits := e.Flush()
		mark, colour := "no", dim
		if len(hits) > 0 {
			mark, colour = "fires", green
		}
		w.Human("  %s%-22s%s %s%s%s\n", dim,
			seq[0]+" then "+seq[1], reset, colour, mark, reset)
	}
	w.Human("  %smost backends do not implement the ordered form. It is "+
		"the\n  difference between these things happened and this "+
		"sequence\n  happened%s\n", dim, reset)
	return nil
}

func firedColour(n int) string {
	if n > 0 {
		return green
	}
	return yellow
}

func failure(at time.Time, user string) telemetry.Event {
	return telemetry.Event{
		Time: at, Received: at, Source: "windows/security",
		Class: telemetry.ClassAuthentication, Activity: 1,
		Severity: telemetry.SeverityLow,
		Raw:      map[string]string{"User": user, "Host": "ws-1"},
	}
}

func plainClockSpan(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

const exampleCorrelations = `
title: Many failed logons for one account
id: corr-count
correlation:
    type: event_count
    rules:
        - failed_logon
    group-by:
        - raw.User
    timespan: 15m
    condition:
        gte: 5
level: high
---
title: One account touching many hosts
id: corr-value
correlation:
    type: value_count
    rules:
        - logon
    group-by:
        - raw.User
    field: raw.Host
    timespan: 1h
    condition:
        gte: 5
level: high
---
title: Recon anywhere near execution
id: corr-temporal
correlation:
    type: temporal
    rules:
        - recon
        - execution
    group-by:
        - raw.Host
    timespan: 30m
level: high
---
title: Recon before execution on one host
id: corr-ordered
correlation:
    type: temporal_ordered
    rules:
        - recon
        - execution
    group-by:
        - raw.Host
    timespan: 30m
level: critical
`
