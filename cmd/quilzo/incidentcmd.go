// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/incident"
)

// Who has to be told, how soon, and what starts the clock.
//
// Every reporting deadline runs from a decision rather than from the end of
// an investigation. GDPR's seventy-two hours run from awareness that a
// breach has likely occurred. DORA's four hours run from classifying an
// incident as major. The SEC's four business days run from determining
// materiality. NIS2's twenty-four hours run from awareness of a significant
// incident.
//
// So one incident has several clocks starting at different moments, and the
// failure worth building against is not missing a deadline. It is a team
// that never formally made one of those calls, believes no clock is
// running, is right, and is three weeks into something a regulator will say
// was plainly reportable on day one.

func cmdIncident(args []string) error {
	if len(args) == 0 {
		args = []string{"demo"}
	}
	switch args[0] {
	case "demo":
		return incidentDemo(args[1:])
	case "duties":
		return incidentDuties()
	default:
		return fmt.Errorf("unknown incident command %q; try demo or duties",
			args[0])
	}
}

func incidentDuties() error {
	if w.JSON(map[string]any{"obligations": incident.Obligations}) {
		return nil
	}
	w.Human("%swho has to be told, and what starts the clock%s\n\n", bold,
		reset)
	for _, o := range incident.Obligations {
		within := "no deadline"
		if o.Within > 0 {
			within = plainClockSpan(o.Within)
			if o.Business {
				within += " (business days)"
			}
		}
		w.Human("  %s%-26s%s %s%-10s from %s%s\n", bold, o.Regime, reset,
			dim, within, o.Needs, reset)
		w.Human("    %stell %s: %s%s\n", dim, o.Who, o.What, reset)
		if o.Note != "" {
			w.Human("    %s%s%s\n", yellow, wrapAt(o.Note, 62, "    "),
				reset)
		}
		w.Human("\n")
	}
	w.Human("  %severy one of these runs from an awareness or a "+
		"determination,\n  and none of them runs from the end of an "+
		"investigation. That is\n  the single most expensive "+
		"misunderstanding in this area%s\n", dim, reset)
	w.Human("\n  %sa starting table and not legal advice. Whether a regime "+
		"applies\n  at all, and whether an incident meets its thresholds, "+
		"are\n  judgements somebody makes; the arithmetic on a clock "+
		"somebody\n  has already started is what this does%s\n", dim, reset)
	return nil
}

func incidentDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	at := time.Now().UTC().Truncate(time.Hour)

	i, err := incident.Declare("inc-2026-41",
		"objects read from a customer bucket by an unknown key",
		incident.Sev1, "ada", at, "eu", "nis2", "sec")
	if err != nil {
		return err
	}
	l := incident.Ladder{Name: "security", Rungs: []incident.Rung{
		{Who: []string{"oncall-1"}, After: 5 * time.Minute, Why: "primary"},
		{Who: []string{"oncall-2"}, After: 5 * time.Minute,
			Why: "secondary"},
		{Who: []string{"head-of-security"}, Why: "last resort"},
	}}

	w.Human("%s%s · %s%s\n\n", bold, i.ID, i.Title, reset)

	// Paged, and nobody answers.
	if err := i.Raise(l, at); err != nil {
		return err
	}
	for _, mins := range []int{6, 12} {
		if _, err := i.Escalate(l, at.Add(time.Duration(mins)*
			time.Minute)); err != nil {
			return err
		}
	}
	w.Human("%spaged, twelve minutes in%s\n", bold, reset)
	for _, p := range i.Unanswered() {
		w.Human("  %srung %d → %v%s\n", dim, p.Rung, p.Who, reset)
	}
	for _, tr := range i.Look(l, at.Add(13*time.Minute)) {
		if tr.Weight == incident.NobodyHasIt {
			w.Human("  %s%s%s\n", yellow, tr.What, reset)
			w.Human("    %s%s%s\n", dim, wrapAt(tr.Detail, 62, "    "),
				reset)
		}
	}
	w.Human("\n")

	if err := i.Ack("oncall-2", at.Add(14*time.Minute)); err != nil {
		return err
	}
	if err := i.Assign(incident.Commander, "oncall-2",
		at.Add(15*time.Minute)); err != nil {
		return err
	}
	if err := i.Assign(incident.Scribe, "grace",
		at.Add(16*time.Minute)); err != nil {
		return err
	}

	// Nothing is due, and that is not the same as nothing being owed.
	w.Human("%sbefore anybody has made a call%s\n", bold, reset)
	for _, d := range i.Unstarted(at.Add(20 * time.Minute)) {
		w.Human("  %s%-26s%s %sno clock — needs %q%s\n", dim, d.Regime,
			reset, dim, d.Needs, reset)
	}
	w.Human("  %sthis list is the point. \"Nothing is due\" and \"nobody "+
		"has made\n  the call that makes something due\" look identical on "+
		"a\n  dashboard, and only one of them is a safe place to be%s\n\n",
		dim, reset)

	// The commander decides.
	aware := at.Add(40 * time.Minute)
	if err := i.Decide(incident.Aware, "oncall-2",
		"the access log shows sixty objects read by a key nobody "+
			"recognises", aware); err != nil {
		return err
	}
	w.Human("%sthe commander records awareness%s\n", bold, reset)
	now := aware.Add(25 * time.Hour)
	w.Human("  %stwenty-five hours later:%s\n", dim, reset)
	for _, d := range i.Duties(now) {
		colour, says := dim, d.Says()
		switch {
		case d.Late():
			colour = yellow
		case d.Soon():
			colour = bold
		case !d.Started:
			says = fmt.Sprintf("no clock — needs %q", d.Needs)
		}
		w.Human("    %s%-26s%s %s%s%s\n", bold, d.Regime, reset, colour,
			says, reset)
	}
	w.Human("\n  %sthe NIS2 early warning is late and Article 33 is not, "+
		"because\n  they are different clocks from the same moment. The "+
		"SEC one has\n  not started at all%s\n\n", dim, reset)

	// Discharge and rule out, then close.
	if err := i.Discharge("NIS2 early warning", "oncall-2",
		"sent late with reasons", now); err != nil {
		return err
	}
	for _, r := range []string{"GDPR Article 33", "NIS2 notification",
		"NIS2 final report"} {
		if err := i.Discharge(r, "oncall-2", "sent", now); err != nil {
			return err
		}
	}
	if err := i.Waive("GDPR Article 34", "ada",
		"the objects were encrypted at rest and the key was held "+
			"separately, so Article 34(3)(a) applies", now); err != nil {
		return err
	}
	if err := i.Waive("SEC Item 1.05", "ada",
		"not material: sixty objects of non-financial test data, no "+
			"effect on operations or results", now); err != nil {
		return err
	}

	err = i.Close("oncall-2",
		"a build log printed an environment variable holding a bucket key",
		[]string{"rotate the key", "stop printing env in CI",
			"alert on reads by keys outside the allow list"}, now)
	if err != nil {
		return err
	}
	w.Human("%sclosed%s\n", bold, reset)
	for _, d := range i.Duties(now) {
		mark, colour := "done", green
		if d.Waived {
			mark, colour = "ruled out", dim
		}
		w.Human("  %s%-11s%s %s\n", colour, mark, reset, d.Regime)
	}
	w.Human("\n  %sclosing refuses while anything is neither discharged "+
		"nor ruled\n  out, and the two are different entries: \"we told the "+
		"regulator\"\n  and \"we decided we did not have to\" are not the "+
		"same statement%s\n", dim, reset)

	if w.JSON(map[string]any{"incident": i, "duties": i.Duties(now)}) {
		return nil
	}
	return nil
}
