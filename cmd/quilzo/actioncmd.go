// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/action"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/incident"
)

// Actions: the playbook step this program carries out itself.
//
// Everything else here reads. An action writes to somebody else's tool, so
// it is off until installed, has a credential of its own, and is only ever
// sent from inside an incident:
//
//   - to an account the incident is already about — the entity of one of
//     its findings, or another identifier of the same person — so an action
//     cannot be pointed at anybody by typing their name;
//   - after somebody other than the requester, or the commander, approved
//     the exact call;
//   - with the approval written down before the call and the answer after.
//
// A model takes none of these steps.

func actionsDir(root string) string { return filepath.Join(root, "actions") }

func loadActions(root string) ([]action.Action, error) {
	entries, err := os.ReadDir(actionsDir(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []action.Action
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := readBounded(filepath.Join(actionsDir(root), e.Name()), 64<<10)
		if err != nil {
			return nil, err
		}
		var a action.Action
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if a.Name+".json" != e.Name() {
			return nil, fmt.Errorf("%s holds the action %s", e.Name(), a.Name)
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func findAction(root, name string) (action.Action, error) {
	all, err := loadActions(root)
	if err != nil {
		return action.Action{}, err
	}
	for _, a := range all {
		if a.Name == name {
			return a, nil
		}
	}
	return action.Action{}, fmt.Errorf("no action called %q is installed; "+
		"quilzo action catalogue lists what ships", name)
}

// actionSender is what sends an action's request.
type actionSender interface {
	Do(*http.Request) (*http.Response, error)
}

// actionDoer sends an action. A test points it at a stand-in.
var actionDoer = func() actionSender {
	return egress.Client("action", 30*time.Second)
}

// sendAction makes the call and returns the tool's status. The body is read
// and dropped: what a tool says back is not kept.
func sendAction(root string, a action.Action, target string, undo bool) (int, error) {
	held, err := loadSecrets(root)
	if err != nil {
		return 0, err
	}
	secret := held[a.Secret]
	if secret == "" {
		return 0, fmt.Errorf("no credential called %q. QUILZO_CONNECT_SECRET=… "+
			"quilzo connect secret %s", a.Secret, a.Secret)
	}
	_, value, _ := strings.Cut(target, ":")
	req, err := a.Build(value, undo)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", a.Scheme+" "+secret)
	res, err := actionDoer().Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	return res.StatusCode, nil
}

// actionTargets is what an incident may act on with one action: the
// entities of its findings, and the other identifiers of the same people,
// that are this action's kind of thing.
func actionTargets(root string, i *incident.Incident, a action.Action,
	now time.Time) ([]string, error) {

	q, err := loadQueue(root, now)
	if err != nil {
		return nil, err
	}
	linked := map[string]bool{}
	for _, f := range i.Findings {
		linked[f] = true
	}
	aliases, err := loadAliases(root)
	if err != nil {
		return nil, err
	}
	people := peopleOf(aliases)
	set := map[string]bool{}
	add := func(id string) {
		issuer, value, ok := strings.Cut(id, ":")
		if ok && issuer == a.Target.Issuer && a.Accepts(value) == nil {
			set[id] = true
		}
	}
	for _, f := range q {
		if !linked[f.ID] || f.Entity.Zero() {
			continue
		}
		add(f.Entity.String())
		person := aliases[f.Entity.String()].Person
		if f.Entity.Issuer == "person" {
			person = f.Entity.Value
		}
		if person == "" {
			continue
		}
		for _, other := range people[person] {
			add(other)
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// requestAct asks for an action inside an incident.
func requestAct(root, id string, caller *Caller, name, target, why string,
	now time.Time) error {

	a, err := findAction(root, name)
	if err != nil {
		return err
	}
	i, err := loadIncident(root, id)
	if err != nil {
		return err
	}
	allowed, err := actionTargets(root, i, a, now)
	if err != nil {
		return err
	}
	ok := false
	for _, t := range allowed {
		ok = ok || t == target
	}
	if !ok {
		return fmt.Errorf("%s is not something this incident is about. An "+
			"action is taken on an account one of the incident's findings "+
			"names, or another identifier of the same person — link the "+
			"finding first", target)
	}
	_, value, _ := strings.Cut(target, ":")
	spec := incident.Act{Action: a.Name, Title: a.Title, Target: target,
		Reversible: a.Reversible(), Says: a.Says(value, false)}
	_, err = actOnIncident(root, id, caller, incident.Action{Do: "act-request",
		Act: &spec, Text: why}, now)
	return err
}

// approveAct approves one act and sends it. The approval is stored before
// the call and the answer after, so a crash between the two leaves a
// record that says the outcome is not known.
func approveAct(root, id string, caller *Caller, actID int, now time.Time) (int, error) {
	if caller.Kind == audit.KindAI {
		return 0, fmt.Errorf("an action on somebody's account is approved " +
			"by a person")
	}
	i, err := loadIncident(root, id)
	if err != nil {
		return 0, err
	}
	var pending *incident.Act
	for n := range i.Acts {
		if i.Acts[n].ID == actID {
			pending = &i.Acts[n]
		}
	}
	if pending == nil {
		return 0, fmt.Errorf("there is no act %d", actID)
	}
	a, err := findAction(root, pending.Action)
	if err != nil {
		return 0, err
	}
	// Everything that can be refused is refused before anything is
	// recorded as approved: the credential, and that the call is still the
	// one that was shown.
	held, err := loadSecrets(root)
	if err != nil {
		return 0, err
	}
	if held[a.Secret] == "" {
		return 0, fmt.Errorf("no credential called %q, so nothing could be "+
			"sent. QUILZO_CONNECT_SECRET=… quilzo connect secret %s",
			a.Secret, a.Secret)
	}
	_, value, _ := strings.Cut(pending.Target, ":")
	if a.Says(value, false) != pending.Says {
		return 0, fmt.Errorf("the action has changed since this was "+
			"requested: it would now %s, and what was shown was %s. "+
			"Withdraw it and ask again", a.Says(value, false), pending.Says)
	}
	target, name := pending.Target, a.Name

	unlock, err := lockIncidents(root)
	if err != nil {
		return 0, err
	}
	i, err = loadIncident(root, id)
	if err != nil {
		unlock()
		return 0, err
	}
	if _, err := i.ApproveAct(actID, caller.Name, now); err != nil {
		unlock()
		return 0, err
	}
	err = saveIncident(root, i)
	unlock()
	if err != nil {
		return 0, err
	}
	if err := recordE(root, audit.Record{Action: "incident.act-approve",
		Resource: "/incidents/" + id, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"action": name, "subject": target,
			"act": strconv.Itoa(actID)}}); err != nil {
		return 0, err
	}

	code, sendErr := sendAction(root, a, target, false)
	ok2xx := sendErr == nil && code >= 200 && code < 300
	return code, finishAct(root, id, actID, name, target, ok2xx, code, false,
		sendErr)
}

// finishAct records what a tool answered.
func finishAct(root, id string, actID int, name, target string, ok bool,
	code int, undo bool, sendErr error) error {

	unlock, err := lockIncidents(root)
	if err != nil {
		return err
	}
	defer unlock()
	i, err := loadIncident(root, id)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if undo {
		err = i.FinishUndo(actID, ok, code, now)
	} else {
		err = i.FinishAct(actID, ok, code, now)
	}
	if err != nil {
		return err
	}
	if err := saveIncident(root, i); err != nil {
		return err
	}
	outcome := audit.Success
	if !ok {
		outcome = audit.Failure
	}
	did := "action.sent"
	if undo {
		did = "action.undone"
	}
	if err := recordE(root, audit.Record{Action: did,
		Resource: "/incidents/" + id, Outcome: outcome,
		Principal: "quilzo", Kind: audit.KindService, Verified: true,
		Detail: map[string]string{"action": name, "subject": target,
			"code": strconv.Itoa(code)}}); err != nil {
		return err
	}
	if sendErr != nil {
		return fmt.Errorf("%s was not sent: %w", name, sendErr)
	}
	if !ok {
		return fmt.Errorf("%s was refused by the tool, which answered %d. "+
			"Nothing changed there", name, code)
	}
	return nil
}

// undoAct reverses a done act.
func undoAct(root, id string, caller *Caller, actID int, why string,
	now time.Time) (int, error) {

	if caller.Kind == audit.KindAI {
		return 0, fmt.Errorf("an action is undone by a person")
	}
	unlock, err := lockIncidents(root)
	if err != nil {
		return 0, err
	}
	i, err := loadIncident(root, id)
	if err != nil {
		unlock()
		return 0, err
	}
	act, err := i.UndoAct(actID, caller.Name, why, now)
	if err != nil {
		unlock()
		return 0, err
	}
	a, err := findAction(root, act.Action)
	if err != nil {
		unlock()
		return 0, err
	}
	err = saveIncident(root, i)
	unlock()
	if err != nil {
		return 0, err
	}
	if err := recordE(root, audit.Record{Action: "incident.act-undo",
		Resource: "/incidents/" + id, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"action": a.Name, "subject": act.Target,
			"act": strconv.Itoa(actID)}}); err != nil {
		return 0, err
	}
	code, sendErr := sendAction(root, a, act.Target, true)
	ok := sendErr == nil && code >= 200 && code < 300
	return code, finishAct(root, id, actID, a.Name, act.Target, ok, code, true,
		sendErr)
}

func cmdAction(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "catalogue":
		c, err := action.Catalogue()
		if err != nil {
			return err
		}
		if w.JSON(map[string]any{"actions": c}) {
			return nil
		}
		for _, n := range action.Names(c) {
			e := c[n]
			w.Human("%s%s%s  %s\n  %s%s%s\n  %sdoes: %s%s\n  %sput back: %s%s\n\n",
				bold, n, reset, e.Action.Title, dim, e.About, reset, dim,
				e.Action.Effect, reset, dim, e.Action.Reverts, reset)
		}
		w.Human("  %snone is installed until you install it, and each has a "+
			"credential of its own%s\n", dim, reset)
		return nil
	case "list":
		all, err := loadActions(root)
		if err != nil {
			return err
		}
		if w.JSON(map[string]any{"actions": all}) {
			return nil
		}
		if len(all) == 0 {
			w.Human("No action is installed, so this program can change " +
				"nothing in any other tool. quilzo action catalogue lists " +
				"what ships.\n")
			return nil
		}
		for _, a := range all {
			w.Human("%s%s%s  %s\n  %s%s%s\n", bold, a.Name, reset, a.Title,
				dim, a.Says("{"+a.Target.What+"}", false), reset)
		}
		return nil
	case "add":
		return actionAdd(root, args[1:])
	case "remove":
		return actionRemove(root, args[1:])
	default:
		return fmt.Errorf("unknown action command %q; try catalogue, list, "+
			"add or remove", args[0])
	}
}

func actionAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	org := fs.String("org", "", "the organisation's subdomain")
	region := fs.String("region", "", "where the account lives")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo action add NAME --org ORG")
	}
	c, err := action.Catalogue()
	if err != nil {
		return err
	}
	e, ok := c[pos[0]]
	if !ok {
		return fmt.Errorf("no action called %q ships", pos[0])
	}
	a, err := e.For(*region, *org)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("an action is installed by a person")
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(actionsDir(root), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(filepath.Join(actionsDir(root),
		a.Name+".json"), append(b, '\n'), 0o600); err != nil {
		return err
	}
	record(root, audit.Record{Action: "action.installed",
		Resource: "/actions/" + a.Name, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"host": a.Host}})
	if !w.JSON(a) {
		w.Human("%s%s%s is installed: %s\n", bold, a.Name, reset,
			a.Says("{"+a.Target.What+"}", false))
		w.Human("  %sneeds %s: %s%s\n", dim, a.Secret, e.Credential, reset)
		w.Human("  QUILZO_CONNECT_SECRET=… quilzo connect secret %s\n", a.Secret)
	}
	return nil
}

func actionRemove(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo action remove NAME")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	if _, err := findAction(root, args[0]); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(actionsDir(root), args[0]+".json")); err != nil {
		return err
	}
	record(root, audit.Record{Action: "action.removed",
		Resource: "/actions/" + args[0], Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified})
	if !w.JSON(map[string]any{"removed": args[0]}) {
		w.Human("removed. Its credential is still held until it is " +
			"replaced or the store's secrets are cleared\n")
	}
	return nil
}

// incidentAct is the incident subcommands that ask for, approve, withdraw
// and undo an action.
func incidentAct(root, do string, args []string) error {
	positional := map[string]int{"act": 3, "act-approve": 2, "act-undo": 2,
		"act-withdraw": 2}[do]
	pos, flags := leadingArgs(args, positional)
	fs := flag.NewFlagSet(do, flag.ContinueOnError)
	because := fs.String("because", "", "why")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != positional {
		return fmt.Errorf("usage: quilzo incident %s %s", do, map[string]string{
			"act":          `ID ACTION ISSUER:VALUE --because "…"`,
			"act-approve":  "ID N",
			"act-undo":     `ID N --because "…"`,
			"act-withdraw": `ID N --because "…"`}[do])
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	now := time.Now().UTC()
	if do == "act" {
		if err := requestAct(root, pos[0], caller, pos[1], pos[2], *because, now); err != nil {
			return err
		}
		if !w.JSON(map[string]any{"requested": pos[1]}) {
			w.Human("requested. Nothing has been sent: somebody else, or " +
				"the commander, approves it\n")
		}
		return nil
	}
	n, err := strconv.Atoi(pos[1])
	if err != nil {
		return fmt.Errorf("an act is named by its number")
	}
	switch do {
	case "act-approve":
		code, err := approveAct(root, pos[0], caller, n, now)
		if err != nil {
			return err
		}
		if !w.JSON(map[string]any{"code": code}) {
			w.Human("%ssent%s: the tool answered %d\n", bold, reset, code)
		}
	case "act-undo":
		code, err := undoAct(root, pos[0], caller, n, *because, now)
		if err != nil {
			return err
		}
		if !w.JSON(map[string]any{"code": code}) {
			w.Human("%sundone%s: the tool answered %d\n", bold, reset, code)
		}
	case "act-withdraw":
		if _, err := actOnIncident(root, pos[0], caller, incident.Action{
			Do: "act-withdraw", ActID: n, Text: *because}, now); err != nil {
			return err
		}
		if !w.JSON(map[string]any{"withdrawn": n}) {
			w.Human("withdrawn\n")
		}
	}
	return nil
}
