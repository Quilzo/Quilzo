// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/incident"
)

// Incidents that outlive the command that declared them.
//
// internal/incident kept the clocks correctly and `incident demo` was the
// only thing that ever ran it, on an incident invented for the run. This
// keeps one file per incident in the store, and everything that changes one
// — from here or from the screen — goes through incident.Apply, is written
// whole, and leaves an audit record.
//
// The incident's own log says what happened in the words of whoever wrote
// it. The audit record says that somebody changed it, and which kind of
// change, under the pseudonym every other record uses; the words stay in
// the incident.

// MaxIncidentFile bounds one stored incident.
const MaxIncidentFile = 8 << 20

// MaxIncidents bounds how many are listed.
const MaxIncidents = 5000

func incidentsDir(root string) string { return filepath.Join(root, "incidents") }

func incidentPath(root, id string) (string, error) {
	if !incident.ValidID(id) {
		return "", fmt.Errorf("%q is not an incident", id)
	}
	return filepath.Join(incidentsDir(root), id+".json"), nil
}

func regimesPath(root string) string {
	return filepath.Join(incidentsDir(root), "regimes.json")
}

// loadRegimes is the sectors and jurisdictions this organisation answers
// to, which a new incident starts with.
func loadRegimes(root string) []string {
	b, err := os.ReadFile(regimesPath(root))
	if err != nil {
		return nil
	}
	var out []string
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return knownScopes(out)
}

// knownScopes keeps the scopes the obligations table has, in its order.
func knownScopes(in []string) []string {
	want := map[string]bool{}
	for _, s := range in {
		want[strings.ToLower(strings.TrimSpace(s))] = true
	}
	var out []string
	for _, s := range incident.Scopes() {
		if want[s] {
			out = append(out, s)
		}
	}
	return out
}

func loadIncident(root, id string) (*incident.Incident, error) {
	path, err := incidentPath(root, id)
	if err != nil {
		return nil, err
	}
	b, err := readBounded(path, MaxIncidentFile)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("there is no incident %s", id)
	}
	if err != nil {
		return nil, err
	}
	var i incident.Incident
	if err := json.Unmarshal(b, &i); err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	if i.ID != id {
		return nil, fmt.Errorf("the file for %s holds %q", id, i.ID)
	}
	i.Restore()
	return &i, nil
}

func saveIncident(root string, i *incident.Incident) error {
	path, err := incidentPath(root, i.ID)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	if len(b) > MaxIncidentFile {
		return fmt.Errorf("%s has grown past %d bytes", i.ID, MaxIncidentFile)
	}
	if err := os.MkdirAll(incidentsDir(root), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// listIncidents reads every incident: open first, then watched, then
// closed, newest first within each.
func listIncidents(root string) ([]*incident.Incident, error) {
	entries, err := os.ReadDir(incidentsDir(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*incident.Incident
	for _, e := range entries {
		id, isJSON := strings.CutSuffix(e.Name(), ".json")
		if !isJSON || !incident.ValidID(id) || !e.Type().IsRegular() {
			continue
		}
		i, err := loadIncident(root, id)
		if err != nil {
			// One unreadable incident is said, not skipped: a list that
			// quietly omits one is a list that says it is not happening.
			return nil, err
		}
		out = append(out, i)
		if len(out) >= MaxIncidents {
			break
		}
	}
	rank := map[incident.State]int{incident.Open: 0, incident.Watching: 1,
		incident.Closed: 2}
	sort.SliceStable(out, func(a, b int) bool {
		if rank[out[a].State] != rank[out[b].State] {
			return rank[out[a].State] < rank[out[b].State]
		}
		return out[a].Declared.After(out[b].Declared)
	})
	return out, nil
}

// lockIncidents serialises changes. One lock for all of them: they are
// changed by people, a few times an hour at worst.
func lockIncidents(root string) (func(), error) {
	if err := os.MkdirAll(incidentsDir(root), 0o700); err != nil {
		return nil, err
	}
	unlock, err := finding.Lock(filepath.Join(incidentsDir(root), "write"))
	if err != nil {
		return nil, fmt.Errorf("somebody else is changing an incident " +
			"this moment; try again")
	}
	return unlock, nil
}

// declareIncident opens one and stores it.
func declareIncident(root string, caller *Caller, title string,
	grade incident.Grade, regimes, findings []string,
	now time.Time) (*incident.Incident, error) {

	if caller.Kind == audit.KindAI {
		return nil, fmt.Errorf("an incident is declared by a person. A " +
			"model that declares one has decided, on somebody's behalf, " +
			"that the organisation knows")
	}
	if len(title) > 200 {
		return nil, fmt.Errorf("a title is a line, not an account")
	}
	var raw [3]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	id, err := incident.NewID(now, hex.EncodeToString(raw[:]))
	if err != nil {
		return nil, err
	}
	i, err := incident.Declare(id, title, grade, caller.Name, now,
		knownScopes(regimes)...)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if err := checkFinding(root, f, now); err != nil {
			return nil, err
		}
		if err := i.Link(f, caller.Name, now); err != nil {
			return nil, err
		}
	}
	unlock, err := lockIncidents(root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := saveIncident(root, i); err != nil {
		return nil, err
	}
	if err := recordE(root, audit.Record{Action: "incident.declared",
		Resource: "/incidents/" + i.ID, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"grade": string(i.Grade),
			"regimes":  strings.Join(i.Regimes, ","),
			"findings": fmt.Sprint(len(i.Findings))}}); err != nil {
		return nil, err
	}
	return i, nil
}

// checkFinding refuses a link to a finding the register does not hold.
func checkFinding(root, id string, now time.Time) error {
	q, err := loadQueue(root, now)
	if err != nil {
		return err
	}
	for _, f := range q {
		if f.ID == id {
			return nil
		}
	}
	return fmt.Errorf("there is no finding %s", id)
}

// actOnIncident does one thing to a stored incident.
func actOnIncident(root, id string, caller *Caller, a incident.Action,
	now time.Time) (*incident.Incident, error) {

	if caller.Kind == audit.KindAI {
		// All of it, not only the decisions. The record of an incident is
		// what people said while it happened; a model's account of it is
		// a different document.
		return nil, fmt.Errorf("an incident's record is written by the " +
			"people working it")
	}
	if a.Do == "link" {
		if err := checkFinding(root, strings.TrimSpace(a.Finding), now); err != nil {
			return nil, err
		}
	}
	unlock, err := lockIncidents(root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	i, err := loadIncident(root, id)
	if err != nil {
		return nil, err
	}
	if err := i.Apply(a, caller.Name, now); err != nil {
		return nil, err
	}
	if err := saveIncident(root, i); err != nil {
		return nil, err
	}
	detail := map[string]string{}
	switch a.Do {
	case "decide":
		detail["trigger"] = string(a.Trigger)
	case "discharge", "waive":
		detail["regime"] = a.Regime
	case "assign":
		detail["role"] = string(a.Role)
	case "link", "unlink":
		detail["finding"] = a.Finding
	}
	return i, recordE(root, audit.Record{Action: "incident." + a.Do,
		Resource: "/incidents/" + i.ID, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: detail})
}

func incidentRegimes(root string, args []string) error {
	if len(args) == 0 {
		cur := loadRegimes(root)
		if w.JSON(map[string]any{"regimes": cur, "known": incident.Scopes()}) {
			return nil
		}
		if len(cur) == 0 {
			w.Human("%sNo regime is set%s, so a new incident starts with "+
				"no obligations and no clocks. quilzo incident regimes %s\n",
				bold, reset, strings.Join(incident.Scopes(), " "))
			return nil
		}
		w.Human("%s%s%s\n", bold, strings.Join(cur, " "), reset)
		return nil
	}
	set := knownScopes(args)
	if len(set) != len(args) {
		return fmt.Errorf("the regimes are %s",
			strings.Join(incident.Scopes(), ", "))
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	b, _ := json.Marshal(set)
	if err := os.MkdirAll(incidentsDir(root), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(regimesPath(root), b, 0o600); err != nil {
		return err
	}
	record(root, audit.Record{Action: "incident.regimes",
		Resource: "/incidents", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"regimes": strings.Join(set, ",")}})
	if !w.JSON(map[string]any{"regimes": set}) {
		w.Human("new incidents start under %s%s%s\n", bold,
			strings.Join(set, ", "), reset)
	}
	return nil
}

func incidentDeclare(root string, args []string) error {
	fs := flag.NewFlagSet("declare", flag.ContinueOnError)
	title := fs.String("title", "", "what is wrong, in a line")
	grade := fs.String("grade", "sev3", "sev1 to sev4")
	regimes := fs.String("regimes", "", "comma-separated; by default the "+
		"ones quilzo incident regimes set")
	var findings multiFlag
	fs.Var(&findings, "finding", "a finding this is about; may repeat")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	under := loadRegimes(root)
	if strings.TrimSpace(*regimes) != "" {
		under = strings.Split(*regimes, ",")
		if len(knownScopes(under)) != len(under) {
			return fmt.Errorf("the regimes are %s",
				strings.Join(incident.Scopes(), ", "))
		}
	}
	i, err := declareIncident(root, caller, *title, incident.Grade(*grade),
		under, findings, time.Now().UTC())
	if err != nil {
		return err
	}
	if w.JSON(i) {
		return nil
	}
	w.Human("%s%s%s declared, %s\n", bold, i.ID, reset, i.Grade)
	printIncidentState(i, time.Now().UTC())
	return nil
}

// printIncidentState is what needs attention, the same after every change.
func printIncidentState(i *incident.Incident, now time.Time) {
	if len(i.Regimes) == 0 {
		w.Human("  %sunder no regime, so nothing here will say a "+
			"notification is due%s\n", yellow, reset)
	}
	for _, t := range i.Look(incident.Ladder{}, now) {
		colour := yellow
		if t.Weight >= incident.Overdue {
			colour = red
		}
		w.Human("  %s%s%s\n", colour, t.What, reset)
	}
}

func incidentList(root string) error {
	all, err := listIncidents(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"incidents": all}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("No incident has been declared.\n")
		return nil
	}
	now := time.Now().UTC()
	for _, i := range all {
		next := ""
		if d, ok := i.Next(now); ok {
			next = d.Regime + ": " + d.Says()
		} else if n := len(i.Unstarted(now)); n > 0 && i.State != incident.Closed {
			next = fmt.Sprintf("%d clock(s) nobody has started", n)
		}
		w.Human("%s%s%s  %-8s %-5s %s\n", bold, i.ID, reset, i.State,
			i.Grade, i.Title)
		if next != "" {
			w.Human("    %s%s%s\n", dim, next, reset)
		}
	}
	return nil
}

func incidentShow(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo incident show ID")
	}
	i, err := loadIncident(root, args[0])
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if w.JSON(map[string]any{"incident": i, "duties": i.Duties(now)}) {
		return nil
	}
	w.Human("%s%s · %s%s  %s, %s\n", bold, i.ID, i.Title, reset, i.Grade,
		i.State)
	printIncidentState(i, now)
	w.Human("\n")
	for _, d := range i.Duties(now) {
		w.Human("  %s%-26s%s %s\n", bold, d.Regime, reset, d.Says())
	}
	if len(i.Findings) > 0 {
		w.Human("\n  findings: %s\n", strings.Join(i.Findings, ", "))
	}
	w.Human("\n")
	for _, e := range i.Timeline() {
		w.Human("  %s%s %s%s  %s\n", dim, e.At.Format("2 Jan 15:04"), e.By,
			reset, e.What)
	}
	return nil
}

// incidentDo is every subcommand that changes a stored incident.
func incidentDo(root, do string, args []string) error {
	positional := map[string]int{"note": 2, "assign": 3, "decide": 2,
		"discharge": 2, "waive": 2, "link": 2, "unlink": 2, "watch": 1,
		"reopen": 1, "close": 1}[do]
	pos, flags := leadingArgs(args, positional)
	fs := flag.NewFlagSet(do, flag.ContinueOnError)
	because := fs.String("because", "", "the reason, the cause, or how it was met")
	var actions multiFlag
	fs.Var(&actions, "action", "what changes as a result; may repeat")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	usage := map[string]string{
		"note":      `ID "what happened"`,
		"assign":    "ID commander|comms|scribe WHO",
		"decide":    `ID aware|major|material|personal|health --because "…"`,
		"discharge": `ID "REGIME" --because "how it was met"`,
		"waive":     `ID "REGIME" --because "why it does not apply"`,
		"link":      "ID FINDING",
		"unlink":    "ID FINDING",
		"watch":     `ID --because "what makes it look fixed"`,
		"reopen":    `ID --because "what came back"`,
		"close":     `ID --because "the cause" --action "what changes"`,
	}[do]
	if len(pos) != positional {
		return fmt.Errorf("usage: quilzo incident %s %s", do, usage)
	}
	a := incident.Action{Do: do, Text: strings.TrimSpace(*because),
		Actions: actions}
	switch do {
	case "note":
		a.Text = pos[1]
	case "assign":
		a.Role, a.Who = incident.Role(pos[1]), pos[2]
	case "decide":
		a.Trigger = incident.Trigger(pos[1])
	case "discharge", "waive":
		a.Regime = pos[1]
	case "link", "unlink":
		a.Finding = pos[1]
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	now := time.Now().UTC()
	i, err := actOnIncident(root, pos[0], caller, a, now)
	if err != nil {
		return err
	}
	if w.JSON(i) {
		return nil
	}
	w.Human("%s%s%s  %s, %s\n", bold, i.ID, reset, i.Grade, i.State)
	printIncidentState(i, now)
	return nil
}
