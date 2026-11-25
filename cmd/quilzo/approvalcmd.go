// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/register"
)

// `quilzo approval`: the approvals of the security record, from a terminal.
//
// What waits for its approvers and what the register holds with its
// approvals, one decision with the hash of exactly what it shows, the
// separation policy, and whether a decision's evidence still checks. An
// administrator at the store's console approves, rejects and reviews here
// by typing back the hash they were shown: no passkey can be asked from a
// terminal, so the console's approval is weaker than one made in the admin,
// and the record says which it was. Over the agent interface and the API
// the approvals are read and never given: an approval is a person's
// passkey over the hash of what they saw, and those surfaces show none.

func init() {
	registerCLI(cliModule{
		module:  "approval",
		command: "approval",
		heading: "approvals in the security record (who may approve what, each bound to the hash of what was shown)",
		help: "  quilzo approval list                     what waits for its approvers, and the decisions held with theirs\n" +
			"  quilzo approval show ID                  one decision: what it shows, the hash of it, and who may approve\n" +
			"  quilzo approval approve ID --surface HASH  approve at the console, typing back the hash show gave\n" +
			"  quilzo approval reject ID                take a waiting decision off the proposals, writing nothing\n" +
			"  quilzo approval review ID upheld|challenged --surface HASH  review a decision made alone\n" +
			"  quilzo approval check ID                 check a held decision's evidence again, offline\n" +
			"  quilzo approval policy [set FILE]        the separation policy, or declare it from a JSON file\n",
		run: cmdApproval,
		// The command asks an administrator of the register's area, and the
		// lines that only read narrow it to a view, so a subcommand added
		// later arrives guarded rather than open. Giving an approval at the
		// console is an administrator's, and the module asks the rule's own
		// atom besides; declaring who may approve is an administrator's too,
		// because whoever can rewrite the separation policy can make
		// themselves the only person it needs.
		needs: map[string]need{
			"approval": {action: auth.ActGrant, hint: "giving, rejecting or reviewing an approval at the console, and " +
				"declaring the separation policy, are for an administrator of the register; list, show, check and " +
				"policy only read"},
			"approval list":       {action: auth.ActView},
			"approval show":       {action: auth.ActView},
			"approval check":      {action: auth.ActView},
			"approval policy":     {action: auth.ActView},
			"approval policy set": {action: auth.ActGrant, hint: "the separation policy says who may approve what, and declaring it is for an administrator of the register"},
			"approval approve":    {action: auth.ActGrant, hint: "approving at the console is for an administrator of the register; anybody else approves in the admin with their passkey"},
			"approval reject":     {action: auth.ActGrant, hint: "rejecting at the console is for an administrator of the register; anybody else rejects in the admin"},
			"approval review":     {action: auth.ActGrant, hint: "reviewing at the console is for an administrator of the register; anybody else reviews in the admin with their passkey"},
		},
		area:   register.Area,
		reads:  [][]string{{"approval", "list"}, {"approval", "policy"}},
		absent: []string{"approval", "show", "00000000000000000000000000000000"},
		ops:    registerApprovalOps,
		notForRuns: "an approval is a person's passkey over what they were shown, and what waits for one is restricted; " +
			"an outside agent reads the approvals under its person's own grant and never gives one",
	})
	// `quilzo approval` alone lists, as a reader may, rather than asking
	// what the command as a whole asks.
	bareRuns["approval"] = "list"
}

func cmdApproval(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return approvalList(root)
	case "show", "check", "reject":
		pos, err := positionals(args[1:], 1)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errMisused{fmt.Errorf("usage: quilzo approval %s ID", args[0])}
		}
		switch args[0] {
		case "show":
			return approvalShow(root, pos[0])
		case "check":
			return approvalCheck(root, pos[0])
		}
		return approvalReject(root, pos[0])
	case "approve", "review":
		fs := flag.NewFlagSet("approval "+args[0], flag.ContinueOnError)
		surface := fs.String("surface", "", "the hash quilzo approval show gave, typed back")
		var pos []string
		want := 1
		if args[0] == "review" {
			want = 2
		}
		if err := parseFlags(fs, args[1:], &pos, want); err != nil {
			return err
		}
		if len(pos) != want || *surface == "" {
			if args[0] == "review" {
				return errMisused{fmt.Errorf("usage: quilzo approval review ID upheld|challenged --surface HASH")}
			}
			return errMisused{fmt.Errorf("usage: quilzo approval approve ID --surface HASH; quilzo approval show ID gives the hash")}
		}
		if args[0] == "review" {
			return approvalReview(root, pos[0], pos[1], *surface)
		}
		return approvalApprove(root, pos[0], *surface)
	case "policy":
		if len(args) > 1 && args[1] == "set" {
			pos, err := positionals(args[2:], 1)
			if err != nil {
				return err
			}
			if len(pos) != 1 {
				return errMisused{fmt.Errorf("usage: quilzo approval policy set FILE")}
			}
			return approvalPolicySet(root, pos[0])
		}
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return approvalPolicy(root)
	default:
		return errMisused{fmt.Errorf("unknown approval command %q; try list, show, approve, reject, review, check or policy", args[0])}
	}
}

// approvalsAt is the approvals of the store at root, writing as the caller
// through the register's one writer.
func approvalsAt(root string, c *Caller) (*approval.Approvals, error) {
	r, _, err := registerWriter(root, c)
	if err != nil {
		return nil, err
	}
	m := &approval.Approvals{Root: root, Register: r, Audit: func(rec audit.Record) error { return recordE(root, rec) },
		Settling: dualStore(root).Settling}
	if inUse, err := policyInUse(root); err != nil {
		return nil, err
	} else if inUse {
		if m.Access, err = loadPolicy(root); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// consolePerson is the caller as an administrator at the store's console:
// a person, at this machine, whose every check is asked as their own
// credential is.
func consolePerson(root string, c *Caller) (approval.Person, error) {
	if c.Kind != audit.KindHuman || c.Remote {
		return approval.Person{}, errBlocked{fmt.Errorf("an approval at the console is a person's, at this machine; " +
			"a program's credential, or one used over the agent interface, gives none")}
	}
	return approval.Person{Name: c.Name, Kind: c.Kind, Verified: c.Verified, Console: true,
		May: func(act auth.Action, resource string) error { return authorise(root, c, act, resource) }}, nil
}

// approvalErr is an error of the approvals as the command line answers it.
func approvalErr(err error) error {
	if errors.Is(err, approval.ErrRefused) {
		return errBlocked{err}
	}
	return registerError(err)
}

// waitingView is a waiting decision as the list and show give it.
type waitingView struct {
	ID       register.ID       `json:"id"`
	Kind     register.Kind     `json:"kind"`
	Label    string            `json:"label"`
	Rule     string            `json:"rule"`
	Atom     auth.Action       `json:"atom"`
	Who      string            `json:"who"`
	Needed   int               `json:"needed"`
	Of       int               `json:"of"`
	Over     []string          `json:"over,omitempty"`
	Signed   int               `json:"signed"`
	Surface  register.Digest   `json:"surface"`
	Shown    *approval.Surface `json:"shown,omitempty"`
	Expires  register.Time     `json:"expires,omitempty"`
	Approve  string            `json:"approve"`
	Proposed string            `json:"proposed_by"`
}

func viewOf(a *approval.Ask, whole bool) waitingView {
	v := waitingView{ID: a.Proposal.ID, Kind: a.Proposal.Kind, Label: register.Label(a.Proposal.Record), Rule: a.Rule.Name,
		Atom: a.Rule.Atom, Who: a.Rule.Describe(), Needed: a.Needed, Of: a.Of, Over: a.Over, Signed: len(a.Signed),
		Surface: a.Hash, Expires: a.Expires, Proposed: proposerOf(a.Proposal),
		Approve: "in the admin at /register/approvals/item/" + string(a.Proposal.ID) + " with a passkey, or at the console: " +
			"quilzo approval approve " + string(a.Proposal.ID) + " --surface " + string(a.Hash)}
	if whole {
		s := a.Surface
		v.Shown = &s
	}
	return v
}

// heldView is a decision held with its approval.
type heldView struct {
	approval.Held
	Status string `json:"status"`
	// InBatch says, for each signature given in a batch, what the decision
	// was in it: a spot-check opened, or approved beside them. Show gives
	// it; the list does not.
	InBatch []batchSaid `json:"in_batch,omitempty"`
}

// batchSaid is one signer's batch, as a decision it approved is shown.
type batchSaid struct {
	Subject register.ID     `json:"subject"`
	Root    register.Digest `json:"root"`
	Said    string          `json:"said"`
}

// inBatch is what a held decision was in each batch that approved it.
func inBatch(m *approval.Approvals, h approval.Held) []batchSaid {
	var out []batchSaid
	for _, sg := range h.Approval.Signers {
		if sg.Batch == "" {
			continue
		}
		said := ""
		switch b, it, err := m.InBatch(h.Record, sg); {
		case err != nil:
			said = "the batch's record could not be read: " + err.Error()
		case it != nil:
			said = fmt.Sprintf("one of %d, and %s", len(b.Items), approval.SpotCheck(*it))
		}
		out = append(out, batchSaid{Subject: sg.Subject, Root: sg.Batch, Said: said})
	}
	return out
}

func statusOf(h approval.Held) string {
	switch {
	case h.Lapsed:
		return "lapsed"
	case h.Overdue:
		return "review overdue"
	case h.Approval.Alone && h.Review == nil:
		return "approved alone, review owed"
	case h.Review != nil:
		return "reviewed: " + string(h.Review.Outcome)
	}
	return "approved"
}

func approvalList(root string) error {
	m, err := approvalsAt(root, resolveCaller(root, flagToken))
	if err != nil {
		return err
	}
	waiting, err := m.Waiting()
	if err != nil {
		return err
	}
	held, err := m.Held()
	if err != nil {
		return err
	}
	views := []waitingView{}
	for _, a := range waiting {
		views = append(views, viewOf(a, false))
	}
	helds := []heldView{}
	for _, h := range held {
		helds = append(helds, heldView{Held: h, Status: statusOf(h)})
	}
	if w.JSON(map[string]any{"waiting": views, "held": helds}) {
		return nil
	}
	if len(views) == 0 {
		fmt.Println("  nothing waits for an approval")
	}
	for _, v := range views {
		fmt.Printf("  %s%-12s%s %s  %s\n", bold, v.Kind, reset, v.ID, printable(truncate(v.Label, 50)))
		fmt.Printf("               %s%d of %d given, %d eligible, under %s; hash %s%s\n", dim, v.Signed, v.Needed, v.Of, v.Rule,
			v.Surface, reset)
	}
	if len(helds) > 0 {
		fmt.Printf("\n  %sheld with their approvals%s\n", bold, reset)
	}
	for _, h := range helds {
		fmt.Printf("  %-12s %s  %-40s %s\n", h.Kind, h.Record, printable(truncate(h.Label, 40)), h.Status)
	}
	return nil
}

func approvalShow(root, id string) error {
	m, err := approvalsAt(root, resolveCaller(root, flagToken))
	if err != nil {
		return err
	}
	a, err := m.Ask(register.ID(id))
	if errors.Is(err, register.ErrNotFound) {
		// Not waiting: perhaps held.
		held, herr := m.Held()
		if herr != nil {
			return herr
		}
		for _, h := range held {
			if string(h.Record) == id {
				batches := inBatch(m, h)
				if w.JSON(heldView{Held: h, Status: statusOf(h), InBatch: batches}) {
					return nil
				}
				fmt.Printf("  %s%s%s %s, %s\n", bold, h.Kind, reset, h.Record, statusOf(h))
				fmt.Printf("  approved under %s; the hash approved is %s\n", h.Approval.Rule, h.Approval.Surface)
				for _, s := range h.Approval.Signers {
					how := s.Method
					if how == "" {
						how = "passkey"
					}
					fmt.Printf("  %s by %s, %s; evidence %s\n", s.At.At().Format("2 Jan 2006 15:04 UTC"), s.Subject, how, s.Assertion)
				}
				for _, b := range batches {
					fmt.Printf("  %sin %s's batch whose root is %s: %s%s\n", dim, b.Subject, b.Root, b.Said, reset)
				}
				return nil
			}
		}
		return errNotFound{fmt.Errorf("no decision %s waits for an approval or is held with one", clip(id, 40))}
	}
	if err != nil {
		return approvalErr(err)
	}
	v := viewOf(a, true)
	if w.JSON(v) {
		return nil
	}
	fields, _ := json.MarshalIndent(json.RawMessage(a.Surface.Record), "  ", "  ")
	fmt.Printf("  %s%s%s %s  %s\n", bold, v.Kind, reset, v.ID, printable(v.Label))
	fmt.Printf("  %s\n", printable(string(fields)))
	for _, e := range a.Surface.Evidence {
		fmt.Printf("  cites %s\n", e)
	}
	for _, c := range a.Surface.Diff {
		fmt.Printf("  changes %s: %s → %s\n", c.Field, printable(truncate(string(c.Before), 60)), printable(truncate(string(c.After), 60)))
	}
	fmt.Printf("\n  %s\n  %d of %d approvals given, %d eligible\n", v.Who, v.Signed, v.Needed, v.Of)
	fmt.Printf("\n  the hash of what this shows: %s%s%s\n", bold, v.Surface, reset)
	fmt.Printf("  %sapprove %s%s\n", dim, v.Approve, reset)
	return nil
}

func approvalApprove(root, id, surface string) error {
	c := resolveCaller(root, flagToken)
	who, err := consolePerson(root, c)
	if err != nil {
		return err
	}
	m, err := approvalsAt(root, c)
	if err != nil {
		return err
	}
	out, err := m.Sign(who, register.ID(id), approval.Proof{Console: &approval.ConsoleProof{Typed: register.Digest(strings.TrimSpace(surface)),
		Credential: c.Credential}})
	if err != nil && (out == nil || !out.Done) {
		return approvalErr(err)
	}
	if w.JSON(out) {
		return err
	}
	if out.Done {
		fmt.Printf("  approved and written: %s, under the commit %s\n", id, out.Receipt.Commit)
		fmt.Printf("  %sthe receipt %s carries the hash %s%s\n", dim, out.Receipt.Digest, out.Surface, reset)
		if out.Alone {
			fmt.Printf("  %sapproved alone: a review by somebody else is owed%s\n", dim, reset)
		}
	} else {
		fmt.Printf("  approved: %d of %d approvals given; it waits for the rest\n", out.Signed, out.Needed)
	}
	return err
}

func approvalReject(root, id string) error {
	c := resolveCaller(root, flagToken)
	who, err := consolePerson(root, c)
	if err != nil {
		return err
	}
	m, err := approvalsAt(root, c)
	if err != nil {
		return err
	}
	if err := m.Reject(who, register.ID(id)); err != nil {
		return approvalErr(err)
	}
	if w.JSON(map[string]any{"rejected": id}) {
		return nil
	}
	fmt.Printf("  rejected %s: nothing was written to the register\n", id)
	return nil
}

func approvalReview(root, id, outcome, surface string) error {
	c := resolveCaller(root, flagToken)
	who, err := consolePerson(root, c)
	if err != nil {
		return err
	}
	if outcome != "upheld" && outcome != "challenged" {
		return errMisused{fmt.Errorf("a review upholds the decision or challenges it: upheld or challenged")}
	}
	m, err := approvalsAt(root, c)
	if err != nil {
		return err
	}
	rc, err := m.Review(who, register.ID(id), register.ReviewOutcome(outcome),
		approval.Proof{Console: &approval.ConsoleProof{Typed: register.Digest(strings.TrimSpace(surface)), Credential: c.Credential}})
	if err != nil && !errors.Is(err, register.ErrUnrecorded) {
		return approvalErr(err)
	}
	if w.JSON(rc) {
		return err
	}
	fmt.Printf("  reviewed %s: %s, under the commit %s\n", id, outcome, rc.Commit)
	return err
}

// checkView is one signer's evidence, checked again.
type checkView struct {
	Subject  register.ID     `json:"subject"`
	Evidence register.Digest `json:"evidence"`
	Method   string          `json:"method"`
	For      register.Digest `json:"for,omitempty"`
	Holds    bool            `json:"holds"`
	Why      string          `json:"why,omitempty"`
}

func approvalCheck(root, id string) error {
	m, err := approvalsAt(root, resolveCaller(root, flagToken))
	if err != nil {
		return err
	}
	held, err := m.Held()
	if err != nil {
		return err
	}
	for _, h := range held {
		if string(h.Record) != id {
			continue
		}
		var out []checkView
		all := true
		for _, s := range h.Approval.Signers {
			v := checkView{Subject: s.Subject, Evidence: s.Assertion, Method: string(s.Method)}
			ev, err := approval.LoadEvidence(root, s.Assertion)
			if err == nil {
				err = ev.Check()
				v.For = ev.For
			}
			if err == nil && ev.For != h.Approval.Surface && ev.For != s.Batch {
				err = fmt.Errorf("the evidence is over %s, and the approval is of %s", ev.For, h.Approval.Surface)
			}
			v.Holds = err == nil
			if err != nil {
				v.Why, all = err.Error(), false
			}
			out = append(out, v)
		}
		if w.JSON(map[string]any{"record": id, "surface": h.Approval.Surface, "signers": out, "holds": all}) {
			if !all {
				return errBlocked{fmt.Errorf("the evidence of %s does not hold", id)}
			}
			return nil
		}
		for _, v := range out {
			word := "holds"
			if !v.Holds {
				word = "does not hold: " + v.Why
			}
			fmt.Printf("  %s's evidence %s %s\n", v.Subject, v.Evidence, word)
		}
		if !all {
			return errBlocked{fmt.Errorf("the evidence of %s does not hold", id)}
		}
		return nil
	}
	return errNotFound{fmt.Errorf("the register holds no decision %s with an approval", clip(id, 40))}
}

func approvalPolicy(root string) error {
	pol, declared, err := approval.LoadPolicy(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"declared": declared, "policy": pol}) {
		return nil
	}
	if !declared {
		fmt.Printf("  %sthis store has declared no separation policy, so the default applies%s\n\n", dim, reset)
	}
	for _, r := range pol.Rules {
		when := ""
		if r.When != nil {
			when = " when " + r.When.Field + " is " + r.When.Equals
		}
		fmt.Printf("  %s%-18s%s %s%s, level %d\n", bold, r.Name, reset, r.Kind, when, r.Level)
		fmt.Printf("                     %s%s%s\n", dim, r.Describe(), reset)
	}
	for _, s := range pol.Seconds {
		fmt.Printf("  second approver: %s, as the organisation's %s\n", s.Principal, s.As)
	}
	fmt.Printf("\n  a decision made alone is reviewed by somebody else within %d days; a request waits %d days\n",
		pol.ReviewDays, pol.WaitDays)
	if pol.PhishingResistant {
		fmt.Println("  whoever decides signs in with a passkey, or single sign-on that used a method that cannot be phished")
	}
	return nil
}

func approvalPolicySet(root, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var p approval.Policy
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("%s is not a separation policy: %w", path, err)
	}
	if err := auditReady(root); err != nil {
		return fmt.Errorf("the policy was not declared, because the audit log cannot record it: %w", err)
	}
	if err := approval.SavePolicy(root, &p); err != nil {
		return errMisused{err}
	}
	c := resolveCaller(root, flagToken)
	if err := recordE(root, audit.Record{Action: "approval.policy", Resource: register.Area, Outcome: audit.Success,
		Principal: c.Name, Kind: c.Kind, Model: c.Model, Verified: c.Verified,
		Detail: map[string]string{"rules": fmt.Sprint(len(p.Rules)), "seconds": fmt.Sprint(len(p.Seconds))}}); err != nil {
		return err
	}
	if w.JSON(map[string]any{"declared": true, "policy": p}) {
		return nil
	}
	fmt.Printf("  declared a separation policy of %d rules\n", len(p.Rules))
	return nil
}

// observeApprovals is what the approvals owe, for the posture: overdue
// reviews and lapsed approvals.
func observeApprovals(root string) posture.ApprovalFacts {
	m, err := approvalsAt(root, &Caller{Name: "posture", Kind: audit.KindService})
	if err != nil {
		return posture.ApprovalFacts{}
	}
	return m.Posture()
}

// registerApprovalOps is the approvals on the agent interface: read, and
// never given. approval_approve is there to say why, and where.
func registerApprovalOps(srv *mcp.Server, root string, caller *Caller) {
	may := func() error {
		if err := authorise(root, caller, auth.ActView, register.Area); err != nil {
			return &mcp.Refusal{Reason: err.Error()}
		}
		return nil
	}
	srv.Register(mcp.Operation{
		Name: "approval_list", NeedsRole: "reader", Area: register.Area,
		Summary: "what in the security record waits for its approvers, and the decisions held with theirs",
		Detail: "Each waiting decision with the rule of the separation policy that decides it, how many approvals " +
			"it needs of how many people eligible, and the hash of what an approver is shown; each held decision " +
			"with whether it was approved alone, its review, and whether it has lapsed. Read-only.",
		Keywords: []string{"approvals", "approve", "decisions", "risk acceptance", "exceptions", "separation of duties"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		m, err := approvalsAt(root, caller)
		if err != nil {
			return nil, err
		}
		waiting, err := m.Waiting()
		if err != nil {
			return nil, err
		}
		held, err := m.Held()
		if err != nil {
			return nil, err
		}
		views := []waitingView{}
		for _, a := range waiting {
			views = append(views, viewOf(a, false))
		}
		helds := []heldView{}
		for _, h := range held {
			helds = append(helds, heldView{Held: h, Status: statusOf(h)})
		}
		return map[string]any{"waiting": views, "held": helds}, nil
	})
	srv.Register(mcp.Operation{
		Name: "approval_show", NeedsRole: "reader", Area: register.Area,
		Summary:  "one waiting decision as an approver is shown it, with the hash of what it shows",
		Args:     map[string]string{"id": "the decision's identifier: 32 hexadecimal characters"},
		Keywords: []string{"approval", "surface", "hash", "decision"},
	}, func(a map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		id, _ := a["id"].(string)
		if !register.ID(id).Valid() {
			return nil, &mcp.ArgumentError{Reason: "approval_show needs arguments.id, a decision's identifier of 32 hexadecimal characters"}
		}
		m, err := approvalsAt(root, caller)
		if err != nil {
			return nil, err
		}
		ask, err := m.Ask(register.ID(id))
		if errors.Is(err, register.ErrNotFound) || errors.Is(err, approval.ErrRefused) {
			return nil, &mcp.Refusal{Reason: "nothing with the identifier " + id + " waits for an approval"}
		}
		if err != nil {
			return nil, err
		}
		return viewOf(ask, true), nil
	})
	srv.Register(mcp.Operation{
		Name: "approval_policy", NeedsRole: "reader", Area: register.Area,
		Summary:  "the organisation's separation policy: who may approve each kind of decision, and how many of them",
		Keywords: []string{"separation policy", "four eyes", "approvers", "second approver"},
	}, func(map[string]any) (any, error) {
		if err := may(); err != nil {
			return nil, err
		}
		pol, declared, err := approval.LoadPolicy(root)
		if err != nil {
			return nil, err
		}
		return map[string]any{"declared": declared, "policy": pol}, nil
	})
	// It is asked as the console's approval is, of an administrator of the
	// register, although it never approves: an operation that would write
	// is gated as a write, so a reader is refused before it says why.
	srv.Register(mcp.Operation{
		Name: "approval_approve", NeedsRole: "admin", Area: register.Area, Writes: true,
		Summary: "refused: an approval is given in the admin with a passkey, never over the agent interface",
		Detail: "An approval in the security record is a person's fresh passkey assertion over the hash of exactly " +
			"what they were shown, and no agent approves anything. This operation answers with where the person " +
			"approves it instead.",
		Args:     map[string]string{"id": "the decision's identifier"},
		Keywords: []string{"approve", "approval", "passkey"},
	}, func(a map[string]any) (any, error) {
		id, _ := a["id"].(string)
		return nil, &mcp.Refusal{Reason: "approving needs the person's passkey over the hash of what they are shown, which " +
			"the agent interface cannot ask for; they approve it in the admin at /register/approvals/item/" +
			clip(id, 40) + ", or an administrator at the store's console with quilzo approval approve"}
	})
}
