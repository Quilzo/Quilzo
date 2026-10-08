// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agentwatch"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/automate"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// What agentwatch flags, told to the shield. agentwatch only reports; a
// flag reaches the shield's playbooks the way any other signal does, which
// by default tells the security contact and the agent's sponsor and opens
// a case. Each flag is told once per new strike, so one already acted on
// is not acted on again every sweep.

func watchedPath(root string) string { return filepath.Join(root, "self", "agentwatch.json") }

// tellTheShieldOfFlags signals every flagged agent or app whose newest
// strike is newer than the last one told, and says how many it told.
func tellTheShieldOfFlags(root string, now time.Time) (int, error) {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return 0, err
	}
	// The newest strike told, by the log's handle. An unreadable file is
	// told again rather than kept quiet.
	told := map[string]int64{}
	if b, err := os.ReadFile(watchedPath(root)); err == nil {
		_ = json.Unmarshal(b, &told)
	}
	kept := map[string]int64{}
	var sh *shieldHost
	n := 0
	for _, r := range agentwatch.Flagged(agentwatch.Look(events, now)) {
		latest := r.Latest()
		kept[r.Principal] = max(latest, told[r.Principal])
		if latest <= told[r.Principal] {
			continue
		}
		record(root, audit.Record{Action: "agentwatch.flagged", Resource: "/", Outcome: audit.Success,
			Principal: "quilzo", Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"agent": r.Agent, "app": r.App, "handle": r.Principal,
				"strikes": fmt.Sprint(len(r.Strikes)), "latest": fmt.Sprint(latest), "summary": r.Summary}})
		if sh == nil {
			sh = newShieldHost(root)
		}
		sh.engine.Observe(shield.Signal{Name: "agent-misbehaving", Subject: r.Subject()})
		if r.Agent != "" {
			// What it earned in evaluations, it has now lost in behaviour.
			_ = noteFlagged(root, r.Agent, now)
		}
		n++
	}
	// Only what is still flagged is remembered: one that falls back under
	// the line does so because its strikes aged out, so crossing it again
	// takes new ones.
	if len(kept) != len(told) || n > 0 {
		b, err := json.Marshal(kept)
		if err != nil {
			return n, err
		}
		if err := os.MkdirAll(filepath.Dir(watchedPath(root)), 0o700); err != nil {
			return n, err
		}
		if err := atomicfile.Write(watchedPath(root), b, 0o600); err != nil {
			return n, err
		}
	}
	return n, nil
}

func flaggedPath(root string) string { return filepath.Join(root, "self", "flagged-agents.json") }

// flaggedAgents is when agentwatch last flagged each declared agent.
func flaggedAgents(root string) map[string]time.Time {
	out := map[string]time.Time{}
	if b, err := os.ReadFile(flaggedPath(root)); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func noteFlagged(root, name string, at time.Time) error {
	m := flaggedAgents(root)
	m[name] = at.UTC()
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(flaggedPath(root)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(flaggedPath(root), b, 0o600)
}

// trustLost is the last time something happened that costs an agent the
// autonomy its evaluations earned it: the shield paused it (unless a
// person judged that pause a mistake), or agentwatch flagged it. Only an
// evaluation after that earns the autonomy back.
func trustLost(root, name string) (time.Time, string) {
	var at time.Time
	why := ""
	if st, err := shield.Load(root); err == nil {
		for _, p := range append(append([]shield.Protection(nil), st.Protections...), st.Ended...) {
			if p.Kind == shield.Agent && p.Target == name && p.Verdict != shield.Mistake && p.At.After(at) {
				at, why = p.At, "the shield paused it on "+p.At.UTC().Format("2 January 2006")
			}
		}
	}
	if f := flaggedAgents(root)[name]; f.After(at) {
		at, why = f, "agentwatch flagged it on "+f.UTC().Format("2 January 2006")+" for trying what it was refused"
	}
	return at, why
}

func remindedPath(root string) string { return filepath.Join(root, "self", "renewals-told.json") }

// remindSponsors tells each agent's sponsor, once for each end date, that
// the agent stops within two weeks unless they renew it. The posture says
// the same to administrators; the sponsor is who decides.
func remindSponsors(root string, now time.Time) (int, error) {
	set, err := loadAgents(root)
	if err != nil {
		return 0, err
	}
	told := map[string]string{}
	if b, err := os.ReadFile(remindedPath(root)); err == nil {
		_ = json.Unmarshal(b, &told)
	}
	kept := map[string]string{}
	notify := automationActions(root)["notify"]
	n := 0
	for name, id := range set.Identities {
		until := id.Expires.UTC().Format(time.RFC3339)
		if told[name] == until {
			kept[name] = until
			continue
		}
		left := id.Expires.Sub(now)
		if !strings.Contains(id.Sponsor, "@") || left <= 0 || left > renewalNotice || notify.Run == nil {
			continue
		}
		ev := automate.Event{Kind: "signal", Subject: "agent:" + name, At: now,
			Summary: fmt.Sprintf("The agent %s stops running on %s unless it is renewed. You answer for it: "+
				"renew it if it is still needed (quilzo agent renew %s), or let it end.",
				name, id.Expires.UTC().Format("2 January 2006"), name),
			Fields: map[string]string{"owner": id.Sponsor, "signal": "identity-ending"}}
		detail := map[string]string{"agent": name, "owner": id.Sponsor, "until": until}
		outcome := audit.Success
		if _, err := notify.Run(ev, map[string]string{"to": "person"}); err != nil {
			detail["error"], outcome = err.Error(), audit.Failure
		}
		// Told, or tried and recorded: either way not again every sweep.
		record(root, audit.Record{Action: "agent.renewal-reminded", Resource: "/agents", Outcome: outcome,
			Principal: "quilzo", Kind: audit.KindService, Verified: true, Detail: detail})
		kept[name] = until
		n++
	}
	if n > 0 || len(kept) != len(told) {
		b, err := json.Marshal(kept)
		if err != nil {
			return n, err
		}
		if err := os.MkdirAll(filepath.Dir(remindedPath(root)), 0o700); err != nil {
			return n, err
		}
		if err := atomicfile.Write(remindedPath(root), b, 0o600); err != nil {
			return n, err
		}
	}
	return n, nil
}

// renewalNotice is how far ahead a sponsor is reminded: the posture's
// two weeks.
const renewalNotice = 14 * 24 * time.Hour

// agentwatchJob is the sweep on the server's schedule.
func agentwatchJob(root string) upkeep.Job {
	return upkeep.Job{Name: "agentwatch", Do: func(now time.Time) (int, error) {
		n, err := tellTheShieldOfFlags(root, now)
		m, err2 := remindSponsors(root, now)
		return n + m, errors.Join(err, err2)
	}}
}
