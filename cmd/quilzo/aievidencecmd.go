// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/aievidence"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/posture"
)

// Evidence for AI: the EU AI Act's deployer duties, ISO/IEC 42001's Annex
// A and an AI bill of materials, read from what the agents, chatbots and
// models did. See internal/aievidence.

// aiEvidenceInputs is what the evidence is read from, for the last days.
func aiEvidenceInputs(root string, days int, now time.Time) (aievidence.Inputs, error) {
	cfg := mustConfig(root)
	in := aievidence.Inputs{Name: cfg.Raw("site.name"), Version: version,
		From: now.Add(-time.Duration(days) * 24 * time.Hour), Now: now,
		Sponsors: map[string]string{}, Standing: map[string]bool{}, Uses: map[string][]string{}}
	in.State = Observe(root, "templates", posture.ServerFacts{})
	in.Findings = posture.Scan(in.State, nil).Findings
	set, err := loadAgents(root)
	if err != nil {
		return in, err
	}
	in.Agents = set.Agents
	for name := range set.Agents {
		if id := set.identityOf(name); id != nil {
			in.Sponsors[name], in.Standing[name] = id.Sponsor, hasStanding(root, id.Sponsor) && now.Before(id.Expires)
		}
	}
	if _, gcfg, _ := modelGateway(root); gcfg != nil {
		for _, r := range gcfg.Routes {
			host := ""
			if u, err := url.Parse(r.URL); err == nil {
				host = u.Hostname()
			}
			in.Routes = append(in.Routes, aievidence.Route{Name: r.Name, Model: r.Model, Host: host,
				Personal: r.Personal, Local: hostIsLocal(host)})
		}
	} else if m, err := assist.NewHTTPModel(); err == nil {
		if u, err := url.Parse(m.BaseURL); err == nil {
			in.Direct = u.Hostname()
		}
	}
	disclosed := map[string]bool{}
	for _, b := range in.State.AI.Chatbots {
		disclosed[b.Name] = b.Disclosed
	}
	if bots, err := assistant.Load(assistantsPath(root)); err == nil && bots != nil {
		for _, a := range bots.Assistants {
			in.Chatbots = append(in.Chatbots, aievidence.Chatbot{Name: a.Name, Public: a.Public, Disclosed: disclosed[a.Name],
				UseModel: a.UseModel, KeepInstructions: a.KeepInstructions, Documents: len(a.Documents)})
		}
	}
	if ins, err := loadIntegrations(root); err == nil {
		in.Tools = ins.Declared
	}
	if reg, err := loadFleet(root); err == nil {
		in.External = reg.Agents
	}
	seen := map[string]bool{}
	for _, u := range recentUsage(root, in.From) {
		k := u.Consumer + "|" + u.Route
		if !seen[k] {
			seen[k] = true
			in.Uses[u.Consumer] = append(in.Uses[u.Consumer], u.Route)
		}
	}
	return in, nil
}

// complianceAI is `quilzo compliance ai-act|iso42001 [--days N]` and
// `quilzo compliance aibom [FILE]`.
func complianceAI(root, which string, args []string) error {
	fs := flag.NewFlagSet("compliance "+which, flag.ContinueOnError)
	days := fs.Int("days", 90, "the period the evidence is counted over")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *days < 1 || *days > 3660 {
		return fmt.Errorf("a period of 1 to 3,660 days")
	}
	in, err := aiEvidenceInputs(root, *days, time.Now())
	if err != nil {
		return err
	}
	if which == "aibom" {
		body, err := json.MarshalIndent(aievidence.AIBOM(in), "", "  ")
		if err != nil {
			return err
		}
		if fs.NArg() == 1 {
			if err := os.WriteFile(fs.Arg(0), append(body, '\n'), 0o644); err != nil {
				return err
			}
			w.Human("wrote %s%s%s\n", bold, fs.Arg(0), reset)
			return nil
		}
		_, err = os.Stdout.Write(append(body, '\n'))
		return err
	}
	items, title := aievidence.Deployer(in), "EU AI Act: a deployer's duties"
	if which == "iso42001" {
		items, title = aievidence.Annex(in), "ISO/IEC 42001 Annex A: statement of applicability"
	}
	if w.JSON(items) {
		return nil
	}
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Status]++
	}
	w.Human("%s%s%s, over the last %d days\n", bold, title, reset, *days)
	w.Human("  %d shown here, %d partly, %d yours to show\n\n", counts[aievidence.Shown], counts[aievidence.Partly], counts[aievidence.Yours])
	for _, it := range items {
		colour := green
		switch it.Status {
		case aievidence.Partly:
			colour = yellow
		case aievidence.Yours:
			colour = dim
		}
		w.Human("%s%-7s%s %s%s%s  %s\n", colour, it.Status, reset, bold, it.Ref, reset, it.Title)
		for _, e := range it.Evidence {
			w.Human("          %s\n", e)
		}
		for _, f := range it.Findings {
			w.Human("          %sfinding: %s%s\n", yellow, f, reset)
		}
		if it.Yours != "" {
			w.Human("          %syours: %s%s\n", dim, it.Yours, reset)
		}
	}
	w.Human("\n  %sevidence from the running system, not a certification%s\n", dim, reset)
	return nil
}

// complianceAIName is the subcommands, for the usage line.
var complianceAIName = strings.Join([]string{"ai-act", "iso42001", "aibom"}, ", ")
