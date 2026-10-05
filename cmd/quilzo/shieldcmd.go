// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/shield"
)

// The shield from the command line on the machine.
//
// This is the way out of anything the shield does. The servers check every
// request against it; this command does not go through any of that, so a
// wrong block, a lockdown nobody can get past or a damaged record is undone
// here: `quilzo shield lift all`, `quilzo shield repair`.

func cmdShield(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return shieldStatus(root)
	case "list":
		return shieldList(root, args[1:])
	case "block", "feature", "lockdown", "freeze", "pause":
		return shieldApply(root, args[0], args[1:])
	case "lift":
		return shieldLift(root, args[1:])
	case "judge":
		return shieldJudge(root, args[1:])
	case "trust":
		return shieldTrust(root, args[1:])
	case "decoy":
		return shieldDecoy(root, args[1:])
	case "playbook", "playbooks":
		return shieldPlaybook(root, args[1:])
	case "hold":
		return shieldHold(root, args[1:])
	case "release":
		return shieldRelease(root, args[1:])
	case "dry-run":
		return shieldDryRun(root, args[1:])
	case "repair":
		return shieldRepair(root)
	default:
		return fmt.Errorf("unknown shield command %q; try status, list, block, feature, "+
			"lockdown, freeze, pause, lift, judge, trust, decoy, playbook, hold, "+
			"release, dry-run or repair", args[0])
	}
}

// shieldBy is who a change from here is recorded as.
func shieldBy(root string) (*Caller, string) {
	c := resolveCaller(root, flagToken)
	return c, c.Name
}

func shieldAudit(root string, c *Caller, action string, outcome audit.Outcome, detail map[string]string) {
	record(root, c.auditRecord(action, "/security/shield", outcome, detail))
}

func shieldStatus(root string) error {
	st, err := shield.Load(root)
	if err != nil {
		return fmt.Errorf("%w\n  quilzo shield repair sets the unreadable record aside", err)
	}
	bk, berr := shield.LoadBook(root)
	if berr != nil {
		bk = &shield.Book{}
	}
	now := time.Now()
	active := st.Active(now)
	pbs := bk.InForce()
	recs := shield.Records(st)
	if w.JSON(map[string]any{"active": active, "watching": st.Watching, "trusted": st.Trusted,
		"decoys": len(st.Decoys), "vouched": len(st.Vouched), "playbooks": pbs,
		"pending": bk.Pending, "records": recs, "problems": bk.Problems()}) {
		return nil
	}
	if st.Watching != nil {
		w.Human("%severy playbook is held to watching%s since %s, by %s: %s\n"+
			"  %sletting them act again takes a second administrator: quilzo shield release%s\n\n",
			yellow, reset, st.Watching.At.UTC().Format("2 Jan 15:04 UTC"), st.Watching.By,
			st.Watching.Reason, dim, reset)
	}
	if len(active) == 0 {
		w.Human("%snothing is in force%s\n", green, reset)
	} else {
		w.Human("%s%s in force%s\n", bold, countWord(len(active), "protection", "protections"), reset)
		for _, p := range active {
			shieldLine(p, now)
		}
	}
	w.Human("\n%splaybooks%s\n", bold, reset)
	byName := map[string]shield.Record{}
	for _, r := range recs {
		byName[r.Playbook] = r
	}
	for _, pb := range pbs {
		mode := pb.Mode
		switch mode {
		case "act":
			mode = green + "acts" + reset
		case "watch":
			mode = yellow + "watches" + reset
		}
		w.Human("  %-24s %-16s %s\n", pb.Name, mode, pb.Title)
		if r, ok := byName[pb.Name]; ok {
			w.Human("    %s%s%s\n", dim, precisionWords(r), reset)
		}
	}
	for _, p := range bk.Pending {
		w.Human("\n%swaiting for a second administrator%s %s: %s, by %s — quilzo shield playbook approve %s\n",
			yellow, reset, p.ID, proposalWords(p), p.By, p.ID)
	}
	for _, pr := range bk.Problems() {
		w.Human("\n%snot run%s %s\n", red, reset, pr)
	}
	if len(st.Trusted) > 0 {
		w.Human("\n%snever blocked%s %s, and anything on the inside\n", bold, reset, strings.Join(st.Trusted, ", "))
	}
	w.Human("\n%s%s planted; %s an administrator signed in from strongly in the last 30 days%s\n",
		dim, countWord(len(st.Decoys), "decoy", "decoys"), countWord(len(st.Vouched), "source", "sources"), reset)
	return nil
}

func countWord(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func precisionWords(r shield.Record) string {
	rate, low, high, enough := r.Precision()
	s := fmt.Sprintf("%s applied", countWord(r.Applied, "protection", "protections"))
	switch {
	case r.Right+r.Mistakes == 0:
		s += "; none judged yet"
	case !enough:
		s += fmt.Sprintf("; %d right, %d mistakes: not enough verdicts to say (%d needed)",
			r.Right, r.Mistakes, shield.MinVerdicts)
	default:
		s += fmt.Sprintf("; right %.0f%% of the time (95%%: %.0f–%.0f%%)", rate*100, low*100, high*100)
	}
	if r.LiftedEarly > 0 {
		s += fmt.Sprintf("; %d lifted early without a verdict", r.LiftedEarly)
	}
	return s
}

func proposalWords(p shield.Proposal) string {
	switch {
	case p.Release:
		return "let every playbook act again"
	case p.Remove:
		return "remove " + p.Playbook.Name
	}
	return fmt.Sprintf("%s to %s", p.Playbook.Name, p.Playbook.Mode)
}

func shieldLine(p shield.Protection, now time.Time) {
	who := p.By
	if p.Auto {
		who = "playbook " + p.Playbook
	}
	w.Human("  %s%s%s  %s\n    %s%s; ends %s; %s%s\n", bold, p.ID, reset, shield.Describe(p),
		dim, p.Reason, p.Until.UTC().Format("2 Jan 15:04 UTC"), who, reset)
}

func shieldList(root string, args []string) error {
	fs := flag.NewFlagSet("shield list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include what has ended")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := shield.Load(root)
	if err != nil {
		return err
	}
	now := time.Now()
	list := st.Active(now)
	if *all {
		list = append(append([]shield.Protection(nil), st.Ended...), st.Protections...)
		sort.SliceStable(list, func(i, j int) bool { return list[i].At.After(list[j].At) })
	}
	if w.JSON(map[string]any{"protections": list, "responses": st.Responses}) {
		return nil
	}
	if len(list) == 0 {
		w.Human("%snothing%s\n", dim, reset)
	}
	for _, p := range list {
		shieldLine(p, now)
		state := "in force"
		switch {
		case p.ReplacedBy != "":
			state = "replaced by " + p.ReplacedBy
		case !p.Lifted.IsZero():
			state = "lifted by " + p.LiftedBy
		case !p.ActiveAt(now):
			state = "ended"
		}
		if p.Verdict != "" {
			state += "; judged " + p.Verdict + " by " + p.VerdictBy
		}
		w.Human("    %s%s%s\n", dim, state, reset)
	}
	return nil
}

// shieldApply puts a protection in force by hand.
func shieldApply(root, kind string, args []string) error {
	fs := flag.NewFlagSet("shield "+kind, flag.ContinueOnError)
	where := fs.String("where", shield.All, "admin, site or all (block)")
	level := fs.String("level", shield.Off, "off, or limited for a chatbot (feature)")
	dur := fs.Duration("for", time.Hour, "how long, at most a week")
	reason := fs.String("reason", "", "why (required)")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	c, by := shieldBy(root)
	now := time.Now()
	p := shield.Protection{Reason: *reason, By: by, Until: now.Add(*dur)}
	target := strings.TrimSpace(strings.Join(pos, " "))
	switch kind {
	case "block":
		p.Kind, p.Where = shield.Block, *where
		switch {
		case strings.HasPrefix(target, "p_"):
			p.Target = "source:" + target
		case strings.Contains(target, "/"):
			p.Target = "net:" + target
		case strings.HasPrefix(strings.ToUpper(target), "AS"):
			p.Target = "asn:" + strings.TrimPrefix(strings.ToUpper(target), "AS")
		default:
			return errors.New("block a source by its handle (p_…, from the audit log), a network (203.0.113.0/24) or a provider (AS64500)")
		}
	case "feature":
		p.Kind, p.Target, p.Level = shield.Feature, target, *level
	case "lockdown":
		p.Kind = shield.Lockdown
		if !canSignInStrongly(root) {
			w.Human("%sNobody here has a passkey or single sign-on: until this is lifted, the admin refuses every "+
				"token made before it, yours included. This command line still works.%s\n", yellow, reset)
		}
	case "freeze":
		p.Kind = shield.Freeze
	case "pause":
		p.Kind, p.Target = shield.Agent, target
	}
	applied, fresh, err := shield.Apply(root, p, now)
	if err != nil {
		shieldAudit(root, c, "shield.applied", audit.Denied, map[string]string{"kind": kind, "target": p.Target, "error": err.Error()})
		return err
	}
	shieldAudit(root, c, "shield.applied", audit.Success, map[string]string{"id": applied.ID, "kind": applied.Kind,
		"target": applied.Target, "where": applied.Where, "until": applied.Until.UTC().Format(time.RFC3339), "reason": applied.Reason})
	if w.JSON(applied) {
		return nil
	}
	verb := "applied"
	if !fresh {
		verb = "already in force; now"
	}
	w.Human("%s%s%s %s %s\n", green, verb, reset, applied.ID, shield.Describe(applied))
	return nil
}

func shieldLift(root string, args []string) error {
	fs := flag.NewFlagSet("shield lift", flag.ContinueOnError)
	mistake := fs.Bool("mistake", false, "it should not have been applied: counts against its playbook")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo shield lift ID|all [--mistake]")
	}
	c, by := shieldBy(root)
	now := time.Now()
	lifted, err := shield.Lift(root, pos[0], by, now)
	if err != nil {
		return err
	}
	for _, p := range lifted {
		detail := map[string]string{"id": p.ID, "what": shield.Describe(p)}
		if *mistake {
			if _, jerr := shield.Judge(root, p.ID, shield.Mistake, by, now); jerr == nil {
				detail["verdict"] = shield.Mistake
			}
		}
		shieldAudit(root, c, "shield.lifted", audit.Success, detail)
	}
	if w.JSON(lifted) {
		return nil
	}
	if len(lifted) == 0 {
		w.Human("%snothing was in force%s\n", dim, reset)
	}
	for _, p := range lifted {
		w.Human("%slifted%s %s %s\n", green, reset, p.ID, shield.Describe(p))
	}
	return nil
}

func shieldJudge(root string, args []string) error {
	if len(args) != 2 || (args[1] != shield.Mistake && args[1] != shield.Right) {
		return errors.New("usage: quilzo shield judge ID mistake|right")
	}
	c, by := shieldBy(root)
	p, err := shield.Judge(root, args[0], args[1], by, time.Now())
	if err != nil {
		return err
	}
	shieldAudit(root, c, "shield.judged", audit.Success, map[string]string{"id": p.ID, "verdict": p.Verdict, "playbook": p.Playbook})
	if w.JSON(p) {
		return nil
	}
	w.Human("%s%s%s judged %s\n", green, p.ID, reset, p.Verdict)
	return nil
}

func shieldTrust(root string, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		st, err := shield.Load(root)
		if err != nil {
			return err
		}
		if w.JSON(st.Trusted) {
			return nil
		}
		if len(st.Trusted) == 0 {
			w.Human("%sno networks declared; anything on the inside is never blocked anyway%s\n", dim, reset)
		}
		for _, t := range st.Trusted {
			w.Human("  %s\n", t)
		}
		return nil
	}
	if len(args) != 2 || (args[0] != "add" && args[0] != "remove") {
		return errors.New("usage: quilzo shield trust [list] | add CIDR | remove CIDR")
	}
	c, _ := shieldBy(root)
	if err := shield.Trust(root, args[1], args[0] == "add", time.Now()); err != nil {
		return err
	}
	shieldAudit(root, c, "shield.trust-"+args[0], audit.Success, map[string]string{"network": args[1]})
	w.Human("%s%s%s %s\n", green, map[string]string{"add": "never blocked:", "remove": "no longer trusted:"}[args[0]], reset, args[1])
	return nil
}

func shieldDecoy(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	c, by := shieldBy(root)
	now := time.Now()
	switch args[0] {
	case "list":
		st, err := shield.Load(root)
		if err != nil {
			return err
		}
		if w.JSON(st.Decoys) {
			return nil
		}
		if len(st.Decoys) == 0 {
			w.Human("%sno decoys planted%s\n", dim, reset)
		}
		for _, d := range st.Decoys {
			w.Human("  %s%s%s  %s %s(by %s, %s)%s\n", bold, d.ID, reset, d.Note, dim, d.By, d.At.UTC().Format("2 Jan 2006"), reset)
		}
		return nil
	case "add":
		fs := flag.NewFlagSet("shield decoy add", flag.ContinueOnError)
		note := fs.String("where", "", "where it will be planted (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		secret, d, err := shield.AddDecoy(root, *note, by, now)
		if err != nil {
			return err
		}
		shieldAudit(root, c, "shield.decoy-planted", audit.Success, map[string]string{"decoy": d.ID, "planted": d.Note})
		if w.JSON(map[string]string{"id": d.ID, "decoy": secret, "where": d.Note}) {
			return nil
		}
		w.Human("%s%s%s, for %s:\n\n  %s\n\n%sShown once. It opens nothing; anybody presenting it is shut out and a case is opened.%s\n",
			green, d.ID, reset, d.Note, secret, dim, reset)
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: quilzo shield decoy remove ID")
		}
		if err := shield.RemoveDecoy(root, args[1], now); err != nil {
			return err
		}
		shieldAudit(root, c, "shield.decoy-removed", audit.Success, map[string]string{"decoy": args[1]})
		w.Human("%sremoved%s %s\n", green, reset, args[1])
		return nil
	}
	return errors.New("usage: quilzo shield decoy [list] | add --where TEXT | remove ID")
}

func shieldPlaybookNamed(bk *shield.Book, name string) (shield.Playbook, bool) {
	for _, pb := range bk.InForce() {
		if pb.Name == name {
			return pb, true
		}
	}
	return shield.Playbook{}, false
}

func shieldPlaybook(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	bk, err := shield.LoadBook(root)
	if err != nil {
		return err
	}
	c, by := shieldBy(root)
	now := time.Now()
	switch args[0] {
	case "list":
		pbs := bk.InForce()
		if w.JSON(pbs) {
			return nil
		}
		for _, pb := range pbs {
			w.Human("  %-24s %-6s %s\n", pb.Name, pb.Mode, pb.Title)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return errors.New("usage: quilzo shield playbook show NAME")
		}
		pb, ok := shieldPlaybookNamed(bk, args[1])
		if !ok {
			return fmt.Errorf("there is no playbook %s", args[1])
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(pb)
	case "mode":
		// The common change, without writing a file.
		fs := flag.NewFlagSet("shield playbook mode", flag.ContinueOnError)
		why := fs.String("why", "", "why (required)")
		onMachine := fs.Bool("now", false, "apply it here, on the machine, without a second administrator")
		pos, err := parseAnywhere(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) != 2 {
			return errors.New("usage: quilzo shield playbook mode NAME act|watch|off --why TEXT [--now]")
		}
		pb, ok := shieldPlaybookNamed(bk, pos[0])
		if !ok {
			return fmt.Errorf("there is no playbook %s", pos[0])
		}
		pb.Mode = pos[1]
		return shieldPropose(root, c, by, pb, false, *why, *onMachine, now)
	case "propose", "set":
		fs := flag.NewFlagSet("shield playbook "+args[0], flag.ContinueOnError)
		file := fs.String("file", "", "the playbook as it will be, as JSON")
		remove := fs.String("remove", "", "a playbook added here, to remove")
		why := fs.String("why", "", "why (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var pb shield.Playbook
		if *remove != "" {
			pb.Name = *remove
		} else {
			b, err := os.ReadFile(*file)
			if err != nil {
				return fmt.Errorf("--file: %w", err)
			}
			dec := json.NewDecoder(strings.NewReader(string(b)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&pb); err != nil {
				return fmt.Errorf("%s: %w", *file, err)
			}
		}
		return shieldPropose(root, c, by, pb, *remove != "", *why, args[0] == "set", now)
	case "approve", "decline":
		if len(args) != 2 {
			return fmt.Errorf("usage: quilzo shield playbook %s ID", args[0])
		}
		p, err := shield.Decide(root, args[1], by, args[0] == "approve", onlyAdministrator(root, by), now)
		if err != nil {
			return err
		}
		shieldAudit(root, c, "shield.playbook-"+p.Outcome, audit.Success, map[string]string{
			"proposal": p.ID, "change": proposalWords(p), "proposed_by": p.By, "alone": strconv.FormatBool(p.Alone)})
		w.Human("%s%s%s %s\n", green, p.Outcome, reset, proposalWords(p))
		return nil
	case "withdraw":
		if len(args) != 2 {
			return errors.New("usage: quilzo shield playbook withdraw ID")
		}
		p, err := shield.Withdraw(root, args[1], by, now)
		if err != nil {
			return err
		}
		shieldAudit(root, c, "shield.playbook-withdrawn", audit.Success, map[string]string{"proposal": p.ID})
		w.Human("%swithdrawn%s %s\n", green, reset, proposalWords(p))
		return nil
	}
	return errors.New("usage: quilzo shield playbook list | show NAME | mode NAME act|watch|off --why TEXT [--now] | " +
		"propose --file F --why TEXT | set --file F --why TEXT | approve ID | decline ID | withdraw ID")
}

func shieldPropose(root string, c *Caller, by string, pb shield.Playbook, remove bool, why string, onMachine bool, now time.Time) error {
	var p shield.Proposal
	var err error
	if onMachine {
		p, err = shield.SetOnMachine(root, pb, remove, why, by, now)
	} else {
		p, err = shield.Propose(root, pb, remove, why, by, now)
	}
	if err != nil {
		return err
	}
	shieldAudit(root, c, map[bool]string{true: "shield.playbook-set", false: "shield.playbook-proposed"}[onMachine],
		audit.Success, map[string]string{"proposal": p.ID, "change": proposalWords(p), "why": why})
	if w.JSON(p) {
		return nil
	}
	if onMachine {
		w.Human("%sapplied on the machine%s %s\n", green, reset, proposalWords(p))
		return nil
	}
	w.Human("%sproposed%s %s (%s); another administrator approves it with\n  quilzo shield playbook approve %s\n",
		yellow, reset, proposalWords(p), p.ID, p.ID)
	return nil
}

// onlyAdministrator reports whether this person is the only one who could
// approve: an install with one administrator is not left unable to change
// anything, and the history says the change was made alone.
func onlyAdministrator(root, by string) bool {
	pol, err := loadPolicy(root)
	if err != nil {
		return false
	}
	admins := map[string]bool{}
	for _, b := range pol.Bindings {
		if b.Role == "admin" && (b.Resource == "/" || b.Resource == "") && !b.Deny {
			admins[strings.ToLower(b.Principal)] = true
		}
	}
	return len(admins) <= 1 && (len(admins) == 0 || admins[strings.ToLower(by)])
}

func shieldHold(root string, args []string) error {
	fs := flag.NewFlagSet("shield hold", flag.ContinueOnError)
	why := fs.String("why", "", "why (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, by := shieldBy(root)
	if err := shield.HoldAll(root, by, *why, time.Now()); err != nil {
		return err
	}
	shieldAudit(root, c, "shield.held", audit.Success, map[string]string{"why": *why})
	w.Human("%severy playbook now watches%s; letting them act again takes a second administrator\n", yellow, reset)
	return nil
}

func shieldRelease(root string, args []string) error {
	fs := flag.NewFlagSet("shield release", flag.ContinueOnError)
	why := fs.String("why", "", "why (required)")
	now := fs.Bool("now", false, "let them act here, on the machine, without a second administrator")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, by := shieldBy(root)
	var p shield.Proposal
	var err error
	if *now {
		p, err = shield.ReleaseOnMachine(root, *why, by, time.Now())
	} else {
		p, err = shield.ProposeRelease(root, *why, by, time.Now())
	}
	if err != nil {
		return err
	}
	shieldAudit(root, c, map[bool]string{true: "shield.released", false: "shield.release-proposed"}[*now],
		audit.Success, map[string]string{"proposal": p.ID, "why": *why})
	if *now {
		w.Human("%sthe playbooks act again%s\n", green, reset)
		return nil
	}
	w.Human("%sproposed%s; another administrator approves it with\n  quilzo shield playbook approve %s\n", yellow, reset, p.ID)
	return nil
}

func shieldRepair(root string) error {
	c, _ := shieldBy(root)
	aside, err := shield.Repair(root, time.Now())
	if err != nil {
		return err
	}
	shieldAudit(root, c, "shield.repaired", audit.Success, map[string]string{"set_aside": aside})
	w.Human("%sset aside%s the unreadable record as %s; the shield starts again empty\n", green, reset, aside)
	return nil
}

// history is the signals the audit log holds, over the last days, for a
// dry run. The site records each source's signals once per ten minutes,
// with how many and about how many different things, so this is close to
// what the engine saw rather than the same: the run says so.
func history(root string, days int, now time.Time) ([]shield.Signal, error) {
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	since := now.Add(-time.Duration(days) * 24 * time.Hour)
	var out []shield.Signal
	for _, e := range evs {
		at, err := time.Parse(time.RFC3339, e.At)
		if err != nil || at.Before(since) {
			continue
		}
		n, _ := strconv.Atoi(e.Detail["count"])
		distinct, _ := strconv.Atoi(e.Detail["distinct"])
		name := ""
		switch e.Action {
		case "site.admin-hunt", "site.conversation-guess", "site.chatbot-injection", "site.form-spam":
			name = strings.TrimPrefix(e.Action, "site.")
		case "auth.failures":
			name = "signin-failures"
			n, _ = strconv.Atoi(e.Detail["failures"])
		case "shield.decoy-touched":
			name, n = "decoy", 1
		case "agent.evaluated":
			if h, _ := strconv.Atoi(e.Detail["hijacked"]); h > 0 {
				out = append(out, shield.Signal{Name: "agent-hijacked", Subject: e.Detail["agent"], At: at})
			}
			continue
		default:
			continue
		}
		if n < 1 {
			n = 1
		}
		if n > 1000 {
			n = 1000
		}
		if distinct < 1 {
			distinct = 1
		}
		for i := 0; i < n; i++ {
			out = append(out, shield.Signal{Name: name, Handle: e.Principal,
				Subject: fmt.Sprint("history-", i%distinct), At: at})
		}
	}
	return out, nil
}

func shieldDryRun(root string, args []string) error {
	fs := flag.NewFlagSet("shield dry-run", flag.ContinueOnError)
	days := fs.Int("days", 30, "how far back to look")
	file := fs.String("file", "", "a playbook to try, as JSON, instead of one in force")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if *days < 1 || *days > 400 {
		return errors.New("--days is 1 to 400")
	}
	bk, err := shield.LoadBook(root)
	if err != nil {
		return err
	}
	var pbs []shield.Playbook
	switch {
	case *file != "":
		b, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var pb shield.Playbook
		if err := json.Unmarshal(b, &pb); err != nil {
			return err
		}
		if err := pb.Validate(); err != nil {
			return err
		}
		pbs = []shield.Playbook{pb}
	case len(pos) == 1:
		pb, ok := shieldPlaybookNamed(bk, pos[0])
		if !ok {
			return fmt.Errorf("there is no playbook %s", pos[0])
		}
		pbs = []shield.Playbook{pb}
	default:
		pbs = bk.InForce()
	}
	now := time.Now()
	sigs, err := history(root, *days, now)
	if err != nil {
		return err
	}
	st, _ := shield.Load(root)
	runs := shield.Try(pbs, sigs, st, now)
	if w.JSON(map[string]any{"days": *days, "signals": len(sigs), "runs": runs,
		"note": "the log holds each source once per ten minutes with a count, so this is close to what the playbooks would have seen, not the same"}) {
		return nil
	}
	w.Human("%sover the last %d days%s: %s in the log\n", bold, *days, reset, countWord(len(sigs), "signal", "signals"))
	w.Human("%sthe log keeps each source once per ten minutes, with a count: close to what the playbooks would have seen, not the same%s\n\n", dim, reset)
	for _, r := range runs {
		w.Human("  %s%-24s%s %s\n", bold, r.Playbook, reset, r.Summary)
		for _, ex := range r.Examples {
			w.Human("    %s%s%s\n", dim, ex, reset)
		}
	}
	return nil
}

// parseAnywhere parses flags wherever they are among the arguments, so
// `shield lift ID --mistake` reads as it is written, and returns the rest.
func parseAnywhere(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}
