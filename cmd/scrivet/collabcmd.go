package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/collab"
	"github.com/rsh1k/scrivet/internal/out"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
)

func locksPath(root string) string { return filepath.Join(root, "locks.json") }

func loadLocks(root string) (*collab.Locks, error) {
	l := &collab.Locks{}
	return l, loadJSON(locksPath(root), l)
}

func cmdLock(root string, args []string) error {
	if len(args) == 0 {
		return lockList(root)
	}
	switch args[0] {
	case "list":
		return lockList(root)
	case "release":
		return lockRelease(root, args[1:])
	default:
		return lockClaim(root, args)
	}
}

func lockClaim(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	note := fs.String("note", "", "what you are doing, so somebody can decide "+
		"whether to interrupt")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: scrivet lock <page> [--note \"...\"]")
	}

	locks, err := loadLocks(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	mine, existing := locks.Claim(pos[0], caller.Name, *note, time.Now())
	if err := saveJSON(locksPath(root), locks); err != nil {
		return err
	}

	if w.JSON(map[string]any{"claim": mine, "already_held_by": existing}) {
		return nil
	}
	record(root, resolveCaller(root, "").auditRecord("lock.claim", "/"+pos[0],
		audit.Success, nil))
	w.Human("%s is yours until %s\n", pos[0],
		time.Unix(mine.Until, 0).Format("15:04"))
	if existing != nil {
		w.Human("  %s%s had it", yellow, existing.Holder)
		if existing.Note != "" {
			w.Human(" — %s", existing.Note)
		}
		w.Human("%s\n", reset)
		w.Human("  %stalk to them. This is a courtesy, not a lock: if you both\n"+
			"  save, the second is refused rather than overwriting the first%s\n",
			dim, reset)
	}
	return nil
}

func lockRelease(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet lock release <page>")
	}
	locks, err := loadLocks(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	if !locks.Release(args[0], caller.Name, time.Now()) {
		return fmt.Errorf("%s does not hold %s", caller.Name, args[0])
	}
	if err := saveJSON(locksPath(root), locks); err != nil {
		return err
	}
	w.Human("released %s\n", args[0])
	return nil
}

func lockList(root string) error {
	locks, err := loadLocks(root)
	if err != nil {
		return err
	}
	active := locks.Active(time.Now())
	if w.JSON(map[string]any{"locks": active}) {
		return nil
	}
	if len(active) == 0 {
		w.Human("nobody has claimed anything\n")
		return nil
	}
	for _, l := range active {
		w.Human("  %-18s %s%s%s until %s", l.Page, bold, l.Holder, reset,
			time.Unix(l.Until, 0).Format("15:04"))
		if l.Note != "" {
			w.Human("  %s%s%s", dim, l.Note, reset)
		}
		w.Human("\n")
	}
	w.Human("\n  %sadvisory. They expire on their own, and the guarantee is\n"+
		"  compare-and-swap on save, not these%s\n", dim, reset)
	return nil
}

// -- review and approval -----------------------------------------------------

func proposalsPath(root string) string { return filepath.Join(root, "review.json") }
func approvalPolicyPath(root string) string {
	return filepath.Join(root, "approval.json")
}

type proposalFile struct {
	Proposals []collab.Proposal `json:"proposals"`
}

func loadApprovalPolicy(root string) (collab.Policy, error) {
	p := collab.Policy{}
	if err := loadJSON(approvalPolicyPath(root), &p); err != nil {
		return p, err
	}
	// An absent file means dual authorization is not configured. Defaulting to
	// NewPolicy would turn a single-person install into one that cannot publish
	// at all, which is how a security control gets deleted rather than adopted.
	return p, nil
}

// currentProposal returns the proposal for the draft as it stands, creating one
// if there is none.
//
// The proposal is keyed by the draft's commit id, so editing the draft produces
// a different proposal with no approvals rather than mutating the approved one.
func currentProposal(root string, s *store.Store) (*collab.Proposal, *proposalFile, error) {
	f := &proposalFile{}
	if err := loadJSON(proposalsPath(root), f); err != nil {
		return nil, nil, err
	}
	draft := s.GetRef(site.RefDraft)
	if draft == "" {
		return nil, nil, fmt.Errorf("there is no draft to review")
	}
	for i := range f.Proposals {
		if f.Proposals[i].Content == draft {
			return &f.Proposals[i], f, nil
		}
	}

	commit, err := s.GetCommit(draft)
	if err != nil {
		return nil, nil, err
	}
	kind := "human"
	if strings.HasPrefix(commit.Message, "assist:") ||
		strings.HasPrefix(commit.Message, "mcp:") {
		kind = "ai"
	}
	f.Proposals = append(f.Proposals, collab.Proposal{
		Content: draft, Author: commit.Author, AuthorKind: kind,
		CreatedAt: commit.At, Message: commit.Message,
	})
	return &f.Proposals[len(f.Proposals)-1], f, nil
}

func cmdReview(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return reviewStatus(root)
	case "approve":
		return reviewApprove(root, args[1:])
	case "require":
		return reviewRequire(root, args[1:])
	default:
		return fmt.Errorf("unknown review command %q; try status, approve "+
			"or require", args[0])
	}
}

func reviewStatus(root string) error {
	s, err := open(root)
	if err != nil {
		return err
	}
	pol, err := loadApprovalPolicy(root)
	if err != nil {
		return err
	}
	prop, _, err := currentProposal(root, s)
	if err != nil {
		return err
	}
	d := pol.Evaluate(*prop, kindOfPrincipal(root), time.Now())

	if w.JSON(map[string]any{
		"proposal": prop, "decision": d, "policy": pol,
	}) {
		return nil
	}

	w.Human("%sdraft %s%s by %s (%s)\n", bold, short(prop.Content), reset,
		prop.Author, prop.AuthorKind)
	if prop.Message != "" {
		w.Human("  %s%s%s\n", dim, prop.Message, reset)
	}
	w.Human("\n")
	if pol.Required == 0 && !pol.RequireHumanForAI {
		w.Human("  %sdual authorization is not configured%s\n", dim, reset)
		w.Human("  %sscrivet review require 2 — two people must agree before "+
			"publishing%s\n", dim, reset)
		return nil
	}

	for _, a := range prop.Approvals {
		if a.Content != prop.Content {
			continue
		}
		w.Human("  %sapproved%s by %s", green, reset, a.By)
		if a.Note != "" {
			w.Human(" — %s", a.Note)
		}
		w.Human("\n")
	}
	if stale := prop.Stale(); len(stale) > 0 {
		w.Human("\n  %s%d approval(s) of an earlier version, kept as history%s\n",
			dim, len(stale), reset)
	}

	w.Human("\n  %s%s%s\n", map[bool]string{true: green, false: yellow}[d.Allowed],
		d.Reason, reset)
	if !d.Allowed && len(d.Missing) > 0 {
		w.Human("  %swaiting on: %s%s\n", dim, strings.Join(d.Missing, ", "), reset)
	}
	return nil
}

func reviewApprove(root string, args []string) error {
	pos, flags := leadingArgs(args, 0)
	_ = pos
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	note := fs.String("note", "", "why you agree, which is what an auditor reads")
	if err := fs.Parse(flags); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	prop, file, err := currentProposal(root, s)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")

	if err := prop.Approve(caller.Name, *note, time.Now()); err != nil {
		return errBlocked{err}
	}
	if err := saveJSON(proposalsPath(root), file); err != nil {
		return err
	}

	// An approval is a privileged action: it is what lets content reach the
	// public, and under AC-3(2) the whole point of dual authorization is that
	// the record shows who agreed to what. The content hash is in the record,
	// so "approved" can never be separated from "approved *this*".
	record(root, audit.Record{
		Action: "review.approve", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			// "approved" rather than "content": the audit package refuses any
			// Detail key containing "content", "body", "key" or "secret",
			// because those are how page text and credentials leak into a log.
			// This holds a hash, but the check is a substring match and it is
			// right to be — a key that has to be argued about is a key that
			// eventually carries the thing it was named after.
			"approved": prop.Content, "author": prop.Author,
			"author_kind": prop.AuthorKind, "note": truncate(*note, 200),
		},
	})

	pol, _ := loadApprovalPolicy(root)
	d := pol.Evaluate(*prop, kindOfPrincipal(root), time.Now())

	if w.Mode == out.JSON {
		w.JSON(map[string]any{"approved": prop.Content, "decision": d})
		return nil
	}
	w.Human("%s approved %s\n", caller.Name, short(prop.Content))
	w.Human("  %s%s%s\n", map[bool]string{true: green, false: dim}[d.Allowed],
		d.Reason, reset)
	if d.Allowed {
		w.Human("  %sscrivet publish%s\n", dim, reset)
	}
	return nil
}

// kindOfPrincipal answers whether an approver is a person.
//
// A principal holding a policy binding is a person; one that exists only as a
// token is a service. That is a heuristic, and it is the honest one available:
// nothing here can prove a human pressed a key, so what it actually reports is
// "this identity is administered as a person".
func kindOfPrincipal(root string) collab.KindOf {
	pol, err := loadPolicy(root)
	if err != nil {
		return func(string) string { return "service" }
	}
	people := map[string]bool{}
	for _, b := range pol.Bindings {
		people[b.Principal] = true
	}
	return func(p string) string {
		if people[p] {
			return "human"
		}
		return "service"
	}
}

// reviewRequire configures dual authorization.
//
// A separate command rather than a JSON file people are expected to find,
// because a security control that requires reading the source to enable is a
// control most installations do not have.
func reviewRequire(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("require", flag.ContinueOnError)
	approvers := fs.String("approvers", "",
		"comma-separated principals whose approval counts; empty means anybody "+
			"who can publish")
	humanForAI := fs.Bool("human-for-ai", true,
		"an AI-authored change always needs a human approver")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: scrivet review require <n> [--approvers a,b]")
	}
	var n int
	if _, err := fmt.Sscanf(pos[0], "%d", &n); err != nil || n < 0 {
		return fmt.Errorf("the number of approvals must be zero or more")
	}

	pol := collab.Policy{Required: n, RequireHumanForAI: *humanForAI}
	for _, a := range strings.Split(*approvers, ",") {
		if a = strings.TrimSpace(a); a != "" {
			pol.Approvers = append(pol.Approvers, a)
		}
	}
	if err := saveJSON(approvalPolicyPath(root), pol); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "review.policy", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"required":     fmt.Sprintf("%d", n),
			"approvers":    strings.Join(pol.Approvers, ","),
			"human_for_ai": fmt.Sprintf("%t", *humanForAI),
		},
	})

	if w.JSON(pol) {
		return nil
	}
	if n == 0 && !*humanForAI {
		w.Human("%sdual authorization is off%s\n", yellow, reset)
		w.Human("  %sanybody who can publish, can publish anything%s\n", dim, reset)
		return nil
	}
	w.Human("publishing now needs %d approval(s)\n", n)
	if len(pol.Approvers) > 0 {
		w.Human("  %sfrom: %s%s\n", dim, strings.Join(pol.Approvers, ", "), reset)
	}
	if *humanForAI {
		w.Human("  %sand a human on anything a model wrote%s\n", dim, reset)
	}
	w.Human("  %san author can never approve their own change%s\n", dim, reset)
	return nil
}
