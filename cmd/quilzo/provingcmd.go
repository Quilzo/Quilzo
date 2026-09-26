// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/proving"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Where a detection goes before it goes live.
//
// On 19 July 2024 CrowdStrike shipped Channel File 291 — a content update,
// not code — that took down around eight and a half million Windows
// machines. The root cause analysis says the mismatch evaded multiple
// layers of build validation and testing, and gives the reason: the tests
// used wildcard matching criteria for the field that was wrong.
//
// A rule tested only against inputs it was written to match proves nothing.
// `proving demo` puts a candidate through the rings against recorded
// telemetry and shows what each gate refuses.

func cmdProving(args []string) error {
	if len(args) == 0 {
		args = []string{"demo"}
	}
	switch args[0] {
	case "demo":
		return provingDemo(args[1:])
	default:
		return fmt.Errorf("unknown proving command %q; try demo", args[0])
	}
}

// recorded builds a week of ordinary telemetry with a few real hits in it.
func recorded(n, hits int, at time.Time) []telemetry.Event {
	out := make([]telemetry.Event, 0, n)
	every := max(1, n/max(1, hits))
	const week = 7 * 24 * time.Hour
	blobs := []string{"SQBFAFgA", "dGVzdA", "cG93ZXI"}
	for i := range n {
		cmd := fmt.Sprintf("ordinary activity %d", i)
		if i%every == 0 {
			cmd = "powershell -enc " + blobs[(i/every)%len(blobs)]
		}
		// Computed in floating point rather than as i*week/n, which
		// overflows an int64 duration well before twenty thousand events
		// and silently stretches the window.
		when := at.Add(-week +
			time.Duration(float64(i)/float64(n)*float64(week)))
		out = append(out, telemetry.Event{
			Source: "windows/process_creation",
			Time:   when, Received: when,
			Class: telemetry.ClassProcessActivity, Activity: 1,
			Severity: telemetry.SeverityLow,
			Message:  cmd,
			Raw:      map[string]string{"cmd": cmd},
		})
	}
	return out
}

func candidateRule(id, needle string) detect.Rule {
	at := time.Now().UTC()
	fixture := func(cmd string, match bool, name string) detect.Fixture {
		return detect.Fixture{Name: name, Match: match,
			Event: telemetry.Event{
				Source: "windows/process_creation",
				Time:   at, Received: at,
				Class: telemetry.ClassProcessActivity, Activity: 1,
				Severity: telemetry.SeverityLow,
				Raw:      map[string]string{"cmd": cmd},
			}}
	}
	return detect.Rule{
		ID: id, Title: "Encoded PowerShell command line",
		Why:     "a base64 command is how a script gets past a log review",
		Blind:   "anything that does not spell the flag this way",
		Sources: []string{"windows/process_creation"},
		When: detect.Predicate{Match: &detect.Match{
			Field: "raw.cmd", Op: detect.Contains,
			Values: []string{needle}}},
		Severity: telemetry.SeverityHigh,
		Fixtures: []detect.Fixture{
			fixture("powershell -enc SQBFAFgA", true, "the encoded form"),
			fixture("powershell -File c:\\ok.ps1", false,
				"powershell doing something ordinary"),
		},
	}
}

func provingDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	events := fs.Int("events", 20000, "how much recorded telemetry to use")
	if err := fs.Parse(args); err != nil {
		return err
	}
	at := time.Now().UTC()
	soaked := at.Add(proving.MinSoak + time.Hour)
	later := soaked.Add(proving.MinSoak + time.Hour)
	week := recorded(*events, 60, at)

	e := &proving.Estate{}

	// A rule a model proposed.
	r := candidateRule("enc-ps", "-enc ")
	c, err := proving.Propose(r, proving.Origin{
		Kind: proving.ByAgent, Who: "assistant", Asked: "ada", At: at}, at)
	if err != nil {
		return err
	}
	e.Add(c)
	w.Human("%sa rule the assistant proposed%s\n", bold, reset)
	w.Human("  %s%s · %s%s\n\n", dim, c.Rule.Title, c.Ring, reset)

	w.Human("%spromoting it with nothing replayed%s\n", bold, reset)
	if err := c.May(proving.Canary, "grace", soaked); err != nil {
		w.Human("  %srefused%s %s\n\n", green, reset,
			wrapAt(firstLine(err), 64, "          "))
	} else {
		return fmt.Errorf("promoted with no replay")
	}

	// Replay it over the week.
	p := proving.Run(c.Rule, week, "last week", at)
	if err := c.Prove(p); err != nil {
		return err
	}
	w.Human("%swhat it would have done last week%s\n", bold, reset)
	w.Human("  %s%s%s\n", dim, wrapAt(p.Why(), 66, "  "), reset)
	for _, s := range p.Samples[:min(2, len(p.Samples))] {
		w.Human("    %s%s%s\n", dim, s, reset)
	}
	w.Human("\n")

	w.Human("%sthe person who asked for it tries to accept it%s\n", bold,
		reset)
	if err := c.May(proving.Canary, "ada", soaked); err != nil {
		w.Human("  %srefused%s %s\n\n", green, reset,
			wrapAt(firstLine(err), 64, "          "))
	} else {
		return fmt.Errorf("the requester accepted their own proposal")
	}

	w.Human("%ssomebody else does, after the soak%s\n", bold, reset)
	if err := c.Promote(proving.Canary, "grace", "volume is fine",
		soaked); err != nil {
		return err
	}
	last := c.Promotions[len(c.Promotions)-1]
	w.Human("  %s%s → %s by %s, accepting %.1f alert(s) a day%s\n", dim,
		last.From, last.To, last.By, last.Volume, reset)
	w.Human("  %sthe volume is recorded against the promotion, so \"we did\n"+
		"  not know it would do that\" is not available afterwards%s\n\n",
		dim, reset)

	// The Channel File 291 shape.
	w.Human("%sa rule that matches nearly everything%s\n", bold, reset)
	wide := candidateRule("wide", "activity")
	wide.Fixtures[0] = detect.Fixture{Name: "the thing it looks for",
		Match: true, Event: week[1]}
	wc, err := proving.Propose(wide, proving.Origin{
		Kind: proving.ByFeed, Who: "somefeed", Version: "r2026-09-20",
		At: at}, at)
	if err != nil {
		return err
	}
	e.Add(wc)
	wp := proving.Run(wide, week, "last week", at)
	if err := wc.Prove(wp); err != nil {
		return err
	}
	w.Human("  %smatched %.0f%% of the week%s\n", dim, wp.Share()*100, reset)
	if err := wc.May(proving.Canary, "grace", soaked); err != nil {
		w.Human("  %srefused%s %s\n\n", green, reset,
			wrapAt(firstLine(err), 64, "          "))
	} else {
		return fmt.Errorf("a rule matching everything was promoted")
	}

	// A tuning change that is really a narrowing.
	w.Human("%stuning it%s\n", bold, reset)
	tuned := candidateRule("enc-ps", "-enc SQBFAFgA")
	ch := proving.Compare(c.Rule, tuned, week, "last week", at)
	w.Human("  %s%s%s\n", dim, wrapAt(ch.Why(), 66, "  "), reset)
	w.Human("\n")

	// Recall a whole feed release.
	w.Human("%srecalling the bad release%s\n", bold, reset)
	gone, err := e.Recall("somefeed", "r2026-09-20", "ada",
		"the release matched everything", at)
	if err != nil {
		return err
	}
	w.Human("  %s%d rule(s) from somefeed r2026-09-20 retired at once%s\n",
		dim, len(gone), reset)
	w.Human("  %sa bad batch is found as a batch. The alternative is "+
		"working out\n  which of four hundred new rules arrived together "+
		"at three in the\n  morning%s\n\n", dim, reset)

	// And what the estate costs.
	if err := c.Promote(proving.Live, "grace", "", later); err != nil {
		return err
	}
	n := e.Noise()
	if w.JSON(map[string]any{"noise": n, "replay": p, "change": ch}) {
		return nil
	}
	w.Human("%swhat the live estate costs an analyst%s\n", bold, reset)
	w.Human("  %s%.1f alert(s) a day from %d rule(s)", dim, n.PerDay,
		n.Rules)
	if n.Worst != "" {
		w.Human(", worst is %q at %.1f", n.Worst, n.WorstAt)
	}
	w.Human("%s\n", reset)
	w.Human("  %sthe number a detection estate is judged by and that "+
		"nobody\n  computes, because it lives across as many dashboards as "+
		"there\n  are tools%s\n", dim, reset)
	return nil
}
