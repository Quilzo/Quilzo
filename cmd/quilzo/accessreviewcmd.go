// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/accessreview"
	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/scim"
)

// Reviewing the access this store grants (internal/accessreview).
//
// The command line and the People screen are two ways into the same four
// functions below, so a review started in one is decided in the other and
// both apply a revoke the same way: through the policy, the token store or
// provisioning's mapping as they are stored now, never a copy read earlier,
// and never leaving the store with nobody able to administer it.

func reviewStore(root string) *accessreview.Store {
	return &accessreview.Store{Dir: filepath.Join(root, "access", "reviews")}
}

// accessReviewEvery is how often a review is due: access.review.every, or the
// organisation's declared ac-02_odp.10 when that is stricter. The setting
// normally holds the declaration already (upkeep raises it to the floor),
// and asking both is what keeps the scan right in the hour after a setting
// was edited by hand below it.
func accessReviewEvery(root string) time.Duration {
	every := mustConfig(root).Dur("access.review.every")
	if pol, err := odp.Load(paramsPath(root)); err == nil {
		if d, ok := pol.Find("ac-02_odp.10"); ok {
			if declared, err := odp.ParsePeriod(d.Value); err == nil && declared > 0 && (every <= 0 || declared < every) {
				every = declared
			}
		}
	}
	if every <= 0 {
		every = accessreview.DefaultEvery
	}
	return every
}

// auditActivity reads, from the audit log, each person's latest record and
// when each identity provider group was mapped. The log is the one lasting
// record of somebody signing in: sessions are pruned a day after they end.
// events is the log already read, or nil to read it here.
func auditActivity(root string, events []audit.Event) (func(string) time.Time, map[string]time.Time) {
	if events == nil {
		events, _ = audit.Read(auditPath(root))
	}
	key, _ := os.ReadFile(auditKeyPath(root))
	latest := map[string]time.Time{}
	mapped := map[string]time.Time{}
	for _, e := range events {
		at, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil {
			continue
		}
		if at.After(latest[e.Principal]) {
			latest[e.Principal] = at
		}
		if e.Action == "scim.mapped" {
			if group, _, ok := strings.Cut(e.Detail["group"], " → "); ok && at.After(mapped[group]) {
				mapped[group] = at
			}
		}
	}
	seen := func(who string) time.Time {
		if len(key) > 0 {
			who = audit.Pseudonym(key, who)
		}
		return latest[who]
	}
	return seen, mapped
}

// reviewInputs is everything a snapshot is taken from, as stored now.
func reviewInputs(root string, events []audit.Event, now time.Time) (accessreview.Inputs, error) {
	pol, err := loadPolicy(root)
	if err != nil {
		return accessreview.Inputs{}, err
	}
	toks, err := loadTokens(root)
	if err != nil {
		return accessreview.Inputs{}, err
	}
	var st *scim.State
	if err := scimStore(root).Read(func(s *scim.State) { c := *s; st = &c }); err != nil {
		return accessreview.Inputs{}, err
	}
	seen, mapped := auditActivity(root, events)
	return accessreview.Inputs{Policy: pol, Tokens: toks, SCIM: st, MappedAt: mapped, Seen: seen, Now: now}, nil
}

func reviewer(c *Caller) accessreview.Decider {
	return accessreview.Decider{Name: c.Name, Kind: c.Kind, Verified: c.Verified, Model: c.Model}
}

// reviewStart takes the snapshot and opens a review over it.
func reviewStart(root string, c *Caller) (*accessreview.Review, error) {
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return nil, err
	}
	now := time.Now()
	in, err := reviewInputs(root, nil, now)
	if err != nil {
		return nil, err
	}
	r, err := accessreview.New(accessreview.NewID(now), accessreview.Snapshot(in), reviewer(c), now)
	if err != nil {
		return nil, err
	}
	if err := reviewStore(root).Start(r); err != nil {
		return nil, err
	}
	return r, recordE(root, c.auditRecord("review.started", r.Resource(), audit.Success, r.StartedDetail()))
}

// reviewDecide gives a verdict about one item, and applies a revoke at
// once: a revoke that is recorded and then carried out later by somebody
// else is how access reviews come to close with everything still in place.
func reviewDecide(root string, c *Caller, id string, v accessreview.Verdict, why string) (accessreview.Item,
	accessreview.Decision, error) {
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return accessreview.Item{}, accessreview.Decision{}, err
	}
	var it accessreview.Item
	var dec accessreview.Decision
	applied := false
	r, err := reviewStore(root).Update(func(r *accessreview.Review) error {
		var cerr error
		if it, cerr = r.Check(id, v, reviewer(c), why); cerr != nil {
			return cerr
		}
		if v == accessreview.Revoke {
			if err := applyRevoke(root, c, it); err != nil {
				return err
			}
			applied = true
		}
		dec = r.Record(it.ID, v, reviewer(c), why, time.Now())
		return nil
	})
	if err != nil && !applied {
		return it, dec, err
	}
	if r == nil {
		// Revoked, and the review file could not be written: the record
		// says what happened, and the error what is left to put right.
		r = &accessreview.Review{ID: "unsaved"}
	}
	rerr := recordE(root, c.auditRecord("review."+string(v), r.Resource(), audit.Success, r.DecisionDetail(it, dec)))
	if err != nil {
		return it, dec, fmt.Errorf("item %s was revoked and its review file could not be written: %w", it.ID, err)
	}
	return it, dec, rerr
}

// errLastAdministrator is a revoke that would leave nobody able to
// administer the store.
var errLastAdministrator = errors.New("that would leave nobody able to administer this store, so it is refused; " +
	"grant another administrator first")

// nobodyAdministers is lastAdminIn's question (internal/admin/people.go)
// asked of the policy as a revoke would leave it: is anybody at all still
// able to grant on the whole site? Asked after the change rather than of
// one principal before it, so a person who administers through a second
// binding keeps the store administered, and a group mapping that made
// three people administrators is judged by all three.
func nobodyAdministers(p *auth.Policy) bool {
	for _, who := range p.Principals() {
		if p.Evaluate(who, auth.ActGrant, "/").Allowed {
			return false
		}
	}
	return true
}

// applyRevoke takes an item's access away through the path that grants
// it, and records that path's own entry as well as the review's, so a
// search for auth.revoke or token.revoke finds a revocation however it was
// decided.
func applyRevoke(root string, c *Caller, it accessreview.Item) error {
	switch it.Kind {
	case accessreview.Credential:
		ts, err := loadTokens(root)
		if err != nil {
			return err
		}
		sessions, err := ts.Revoke(it.Credential)
		if err != nil {
			return err
		}
		if err := saveTokens(root, ts); err != nil {
			return err
		}
		record(root, c.auditRecord("token.revoke", "/", audit.Success, map[string]string{
			"revoked_id": it.Credential, "sessions_cascaded": fmt.Sprint(sessions)}))
		return nil
	case accessreview.Mapping:
		var current string
		var members []string
		if err := scimStore(root).Read(func(st *scim.State) {
			current = st.Mapping[it.Group]
			for _, g := range st.Groups {
				if g.DisplayName == it.Group {
					for _, id := range g.Members {
						if u, ok := st.User(id); ok {
							members = append(members, u.UserName)
						}
					}
				}
			}
		}); err != nil {
			return err
		}
		if current != it.Role {
			return fmt.Errorf("the group %q no longer means %s here, so this item is not what was reviewed; "+
				"start a new review to decide what it means now", it.Group, it.Role)
		}
		// Judged on everything provisioning gave the group's members, not
		// only what this one group gave: refusing a removal another group
		// would have covered is the safe way to be wrong.
		pol, err := loadPolicy(root)
		if err != nil {
			return err
		}
		after := &auth.Policy{}
		for _, b := range pol.Snapshot() {
			gone := false
			for _, m := range members {
				gone = gone || (b.GrantedBy == scimBy && strings.EqualFold(b.Principal, m))
			}
			if !gone {
				after.Bindings = append(after.Bindings, b)
			}
		}
		if nobodyAdministers(after) {
			return errLastAdministrator
		}
		if err := scimUnmap(root, it.Group); err != nil {
			return err
		}
		record(root, c.auditRecord("scim.unmapped", "/", audit.Success, map[string]string{"group": it.Group}))
		return nil
	}
	n := 0
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if it.AppRole {
			n = p.RevokeAppRole(it.Principal, it.Role)
		} else {
			n = p.RevokeNamed(it.Principal, it.Role, it.Resource)
		}
		if n == 0 {
			return fmt.Errorf("%s no longer holds this; nothing to revoke", it.Principal)
		}
		if nobodyAdministers(p) {
			return errLastAdministrator
		}
		return nil
	}); err != nil {
		return err
	}
	record(root, c.auditRecord("auth.revoke", "/", audit.Success, map[string]string{
		"subject": it.Principal, "bindings_removed": fmt.Sprint(n)}))
	return nil
}

// reviewClose ends the open review, and writes the evidence that the
// control operated.
func reviewClose(root string, c *Caller) (*accessreview.Review, accessreview.Summary, error) {
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return nil, accessreview.Summary{}, err
	}
	now := time.Now()
	in, err := reviewInputs(root, nil, now)
	if err != nil {
		return nil, accessreview.Summary{}, err
	}
	current := accessreview.Snapshot(in)
	alone := onlyAdministrator(root, c.Name)
	var sum accessreview.Summary
	r, err := reviewStore(root).Update(func(r *accessreview.Review) error {
		var cerr error
		sum, cerr = r.Close(reviewer(c), current, alone, now)
		return cerr
	})
	if err != nil {
		return nil, sum, err
	}
	if err := recordE(root, c.auditRecord("review.closed", r.Resource(), audit.Success, r.ClosedDetail(sum))); err != nil {
		return r, sum, err
	}
	return r, sum, recordReviewEvidence(root, r)
}

// recordReviewEvidence appends a closed review's evidence, beside the
// evidence of every other control, and puts it in the audit chain.
func recordReviewEvidence(root string, r *accessreview.Review) error {
	e := r.Evidence()
	if err := e.Validate(); err != nil {
		return err
	}
	if err := appendJSONL(evidencePath(root), e); err != nil {
		return err
	}
	return recordE(root, e.Record())
}

// observeReviews is the review facts the posture scan reasons about.
func observeReviews(root string, events []audit.Event, now time.Time) posture.ReviewFacts {
	st := reviewStore(root)
	last, closed, err := st.LastClosed()
	if err != nil {
		return posture.ReviewFacts{}
	}
	f := posture.ReviewFacts{Checked: true, Every: accessReviewEvery(root), LastClosed: last}
	if open, err := st.Current(); err == nil && open != nil {
		f.Open = open.Started
	}
	if closed {
		return f
	}
	in, err := reviewInputs(root, events, now)
	if err != nil {
		return posture.ReviewFacts{}
	}
	for _, it := range accessreview.Snapshot(in) {
		switch {
		case it.GrantedAt.IsZero():
			// Granted before grants were dated: as old as anything here,
			// and owed a review from the start.
			f.Undated = true
		case f.Owed.IsZero() || it.GrantedAt.Before(f.Owed):
			f.Owed = it.GrantedAt
		}
	}
	return f
}

func cmdAccess(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"review"}
	}
	switch args[0] {
	case "review":
		return cmdAccessReview(root, args[1:])
	}
	return fmt.Errorf("unknown access command %q; quilzo access review start | items | decide | close", args[0])
}

func cmdAccessReview(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"items"}
	}
	c := resolveCaller(root, flagToken)
	switch sub := args[0]; sub {
	case "start":
		r, err := reviewStart(root, c)
		if err != nil {
			return err
		}
		if w.JSON(r) {
			return nil
		}
		w.Human("review %s%s%s started: %d item(s) to decide\n", bold, r.ID, reset, len(r.Items))
		w.Human("  %squilzo access review items lists them, dormant and privileged first%s\n", dim, reset)
		return nil
	case "items":
		r, err := reviewStore(root).Current()
		if err != nil {
			return err
		}
		if r == nil {
			return errors.New("no review is open: quilzo access review start begins one")
		}
		if w.JSON(r) {
			return nil
		}
		w.Human("review %s%s%s, started %s by %s: %d of %d undecided\n", bold, r.ID, reset,
			r.Started.Format("2 Jan 2006"), onOneLine(r.StartedBy), r.Undecided(), len(r.Items))
		for _, it := range r.Items {
			state := yellow + "undecided" + reset
			if d, ok := r.Decided(it.ID); ok {
				state = green + string(d.Verdict) + reset + dim + " by " + onOneLine(d.By) + reset
			}
			marks := ""
			if it.Dormant {
				marks += "  " + red + "dormant: proposed revoke" + reset
			}
			if it.Privileged {
				marks += "  " + yellow + "privileged" + reset
			}
			w.Human("%s%3s%s  %s  %s%s\n", bold, it.ID, reset, onOneLine(it.Describe()), state, marks)
			w.Human("       %s%s%s\n", dim, itemFacts(it), reset)
		}
		return nil
	case "decide":
		pos, flags := leadingArgs(args[1:], 2)
		fs := flag.NewFlagSet("access review decide", flag.ContinueOnError)
		why := fs.String("why", "", "why; keeping privileged access needs one")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 2 {
			return errors.New("usage: quilzo access review decide ITEM keep|revoke [--why TEXT]")
		}
		it, dec, err := reviewDecide(root, c, pos[0], accessreview.Verdict(pos[1]), *why)
		if err != nil {
			return err
		}
		if w.JSON(dec) {
			return nil
		}
		w.Human("item %s: %s%s%s, %s\n", it.ID, bold, dec.Verdict, reset, onOneLine(it.Describe()))
		if dec.Verdict == accessreview.Revoke {
			w.Human("  %srevoked now; their next request is refused%s\n", dim, reset)
		}
		return nil
	case "close":
		r, sum, err := reviewClose(root, c)
		if err != nil {
			return err
		}
		if w.JSON(map[string]any{"review": r.ID, "summary": sum}) {
			return nil
		}
		w.Human("review %s%s%s closed: %d item(s), %d kept, %d revoked\n", bold, r.ID, reset, sum.Items,
			sum.Kept, sum.Revoked)
		if sum.Alone {
			w.Human("  %syou are the only administrator, so this was done alone, and %d of your own access "+
				"went unreviewed; the record says so%s\n", yellow, sum.Own, reset)
		}
		if len(sum.NotReviewed) > 0 {
			w.Human("  %s%d granted since it started, not reviewed by it:%s\n", yellow, len(sum.NotReviewed), reset)
			for _, it := range sum.NotReviewed {
				w.Human("    %s\n", onOneLine(it.Describe()))
			}
		}
		w.Human("  %sthe evidence is in quilzo assurance show %q%s\n", dim, accessreview.ControlID, reset)
		return nil
	}
	return fmt.Errorf("unknown access review command %q; start, items, decide or close", args[0])
}

// itemFacts is an item's second line: how and when it was granted, until
// when, and when it was last used.
func itemFacts(it accessreview.Item) string {
	var parts []string
	how := "granted " + it.Via
	if it.GrantedBy != "" {
		how += " by " + it.GrantedBy
	}
	if !it.GrantedAt.IsZero() {
		how += " on " + it.GrantedAt.Format("2 Jan 2006")
	}
	parts = append(parts, onOneLine(how))
	if !it.Expires.IsZero() {
		parts = append(parts, "until "+it.Expires.Format("2 Jan 2006"))
	}
	if it.LastActive.IsZero() {
		parts = append(parts, "no activity recorded")
	} else {
		parts = append(parts, "last active "+it.LastActive.Format("2 Jan 2006"))
	}
	if len(it.Members) > 0 {
		parts = append(parts, fmt.Sprintf("%d member(s)", len(it.Members)))
	}
	return strings.Join(parts, "; ")
}

// accessReviewHooks is the People screen's review, done by the same
// functions as the command line, as the person signed in.
func accessReviewHooks(root string) *admin.AccessReview {
	return &admin.AccessReview{
		Current: func() (*accessreview.Review, error) { return reviewStore(root).Current() },
		Last:    func() (time.Time, bool, error) { return reviewStore(root).LastClosed() },
		Every:   func() time.Duration { return accessReviewEvery(root) },
		Start: func(by admin.Actor) (*accessreview.Review, error) {
			return reviewStart(root, sessionCaller(by))
		},
		Decide: func(by admin.Actor, id string, v accessreview.Verdict, why string) (accessreview.Item, error) {
			it, _, err := reviewDecide(root, sessionCaller(by), id, v, why)
			return it, err
		},
		Close: func(by admin.Actor) (accessreview.Summary, error) {
			_, sum, err := reviewClose(root, sessionCaller(by))
			return sum, err
		},
	}
}
