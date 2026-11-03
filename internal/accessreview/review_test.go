// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package accessreview

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/scim"
)

var now = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

func person(name string) Decider { return Decider{Name: name, Kind: audit.KindHuman, Verified: true} }

// store is a policy, tokens and provisioning with one of everything a
// review must take in and one of everything it must leave out.
func store(t *testing.T) Inputs {
	t.Helper()
	pol := &auth.Policy{}
	for _, b := range []auth.Binding{
		{Principal: "dana", Role: auth.RoleAdmin, Resource: "/", GrantedBy: "cli", GrantedAt: now.Add(-400 * day).Unix()},
		{Principal: "sam", Role: auth.RoleAdmin, Resource: "/", GrantedBy: "dana", GrantedAt: now.Add(-200 * day).Unix()},
		{Principal: "kit", Role: auth.RoleAuthor, Resource: "/blog", GrantedBy: "dana", GrantedAt: now.Add(-200 * day).Unix()},
		{Principal: "kit", Role: auth.RolePublisher, Resource: "/legal", Deny: true, GrantedBy: "dana"},
		{Principal: "ada@example.com", Role: auth.RolePublisher, Resource: "/", GrantedBy: "scim"},
		{Principal: "agent:newsletter", Role: auth.RoleAuthor, Resource: "/news", GrantedBy: "dana"},
	} {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	ts := &auth.TokenStore{}
	if _, _, err := ts.Issue("deploy", "ci-bot", auth.RoleAuthor, "/", 30*day, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	ts.Tokens[0].CreatedAt, ts.Tokens[0].ExpiresAt = now.Add(-day).Unix(), now.Add(29*day).Unix()
	ts.Tokens[0].LastUsed = now.Add(-time.Hour).Unix()
	if _, _, err := ts.IssueSession("passkey:sam", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	ts.Tokens[1].CreatedAt, ts.Tokens[1].ExpiresAt = now.Add(-time.Hour).Unix(), now.Add(7*time.Hour).Unix()
	ts.Tokens = append(ts.Tokens, auth.Token{ID: "agenttok", Name: "agent", Principal: "agent:newsletter",
		Role: auth.RoleAuthor, Resource: "/news", CreatedAt: now.Add(-day).Unix(), ExpiresAt: now.Add(29 * day).Unix()})
	st := &scim.State{Mapping: map[string]string{"Editors": "publisher"},
		Users:  []scim.User{{ID: "u1", UserName: "ada@example.com", Active: true}},
		Groups: []scim.Group{{ID: "g1", DisplayName: "Editors", Members: []string{"u1"}}}}
	seen := map[string]time.Time{"dana": now.Add(-time.Hour), "sam": now.Add(-10 * day), "ada@example.com": now.Add(-2 * day)}
	return Inputs{Policy: pol, Tokens: ts, SCIM: st, MappedAt: map[string]time.Time{"Editors": now.Add(-30 * day)},
		Seen: func(who string) time.Time { return seen[who] }, Now: now}
}

func find(items []Item, match func(Item) bool) *Item {
	for i := range items {
		if match(items[i]) {
			return &items[i]
		}
	}
	return nil
}

// Regression 1. A binding made by hand is in, one provisioning made is
// out, a mapping is one item however many are in its group, and a
// long-lived token is in; sessions, agents and their tokens, and denies are
// out. Members of the public site are in another store altogether.
func TestThePopulationIsTheGrantsOnlyQuilzoHolds(t *testing.T) {
	items := Snapshot(store(t))
	if find(items, func(i Item) bool { return i.Kind == Binding && i.Principal == "kit" && i.Role == "author" }) == nil {
		t.Error("a binding made by hand is not reviewed")
	}
	if find(items, func(i Item) bool { return i.Principal == "ada@example.com" && i.Kind == Binding }) != nil {
		t.Error("a binding provisioning made is reviewed here, where its next sync would undo a revoke")
	}
	maps := 0
	for _, i := range items {
		if i.Kind == Mapping {
			maps++
			if i.Group != "Editors" || i.Role != "publisher" || len(i.Members) != 1 {
				t.Errorf("the mapping item is %+v", i)
			}
		}
	}
	if maps != 1 {
		t.Errorf("%d mapping items, want one", maps)
	}
	if find(items, func(i Item) bool { return i.Kind == Credential && i.Principal == "ci-bot" }) == nil {
		t.Error("a long-lived token is not reviewed")
	}
	for _, i := range items {
		if i.Principal == "agent:newsletter" || i.Credential == "agenttok" {
			t.Errorf("an agent's identity or token is reviewed here, where its renewal is its review: %+v", i)
		}
		if i.Kind == Credential && i.Principal == "sam" {
			t.Errorf("a session is reviewed: %+v", i)
		}
		if i.Principal == "kit" && i.Resource == "/legal" {
			t.Errorf("a deny is reviewed, and revoking it would widen access: %+v", i)
		}
	}
	if len(items) != 5 {
		t.Errorf("%d items, want dana, sam, kit, the mapping and the token, and no more: %+v", len(items), items)
	}
}

// Regression 2. Sessions are pruned a day after they end, so the audit
// log is what says somebody signed in: sam has no credential left and was
// active ten days ago, which is not dormant. Somebody with no activity for
// ninety-one days is, comes first, and is proposed for revoke.
func TestActivityComesFromTheAuditLogAndDormantComesFirst(t *testing.T) {
	in := store(t)
	in.Tokens.Tokens = in.Tokens.Tokens[:1]
	items := Snapshot(in)
	sam := find(items, func(i Item) bool { return i.Principal == "sam" })
	if sam == nil || sam.Dormant || !sam.LastActive.Equal(now.Add(-10*day)) {
		t.Fatalf("sam, seen in the log ten days ago: %+v", sam)
	}
	kit := find(items, func(i Item) bool { return i.Principal == "kit" })
	if kit == nil || !kit.Dormant || kit.Proposed != Revoke {
		t.Fatalf("kit, granted two hundred days ago and never seen: %+v", kit)
	}
	if items[0].Principal != "kit" || items[0].ID != "1" {
		t.Errorf("the dormant item is not first: %+v", items[0])
	}

	// Ninety-one days is dormant; eighty-nine is not.
	in.Seen = func(who string) time.Time {
		if who == "kit" {
			return now.Add(-91 * day)
		}
		return now
	}
	if kit := find(Snapshot(in), func(i Item) bool { return i.Principal == "kit" }); !kit.Dormant {
		t.Error("ninety-one days without activity is not dormant")
	}
	in.Seen = func(string) time.Time { return now.Add(-89 * day) }
	if kit := find(Snapshot(in), func(i Item) bool { return i.Principal == "kit" }); kit.Dormant {
		t.Error("eighty-nine days without activity is dormant")
	}
	// A grant made yesterday has not had ninety days to be unused in.
	if err := in.Policy.Grant(auth.Binding{Principal: "new", Role: auth.RoleReader, Resource: "/",
		GrantedAt: now.Add(-day).Unix()}); err != nil {
		t.Fatal(err)
	}
	in.Seen = func(string) time.Time { return time.Time{} }
	if fresh := find(Snapshot(in), func(i Item) bool { return i.Principal == "new" }); fresh.Dormant {
		t.Error("yesterday's grant is dormant")
	}
}

// Privileged comes after dormant and before the rest: the admin role, the
// guarded areas, and a permission only an administrator otherwise holds.
func TestPrivilegedIsAdministrationAndTheGuardedAreas(t *testing.T) {
	for _, c := range []struct {
		role, on string
		want     bool
	}{
		{"admin", "/", true}, {"admin", "/blog", true}, {"reader", "/@log", true},
		{"admin", "/@security", true}, {"reader", "/@compliance/x", true},
		{"approve", "/@agents/newsletter", true}, {"publisher", "/", false},
		{"author", "/@inbox", false}, {"run-agents", "/@agents", false},
	} {
		if got := Privileged(c.role, c.on); got != c.want {
			t.Errorf("%s on %s: privileged %v, want %v", c.role, c.on, got, c.want)
		}
	}
	if !mappingPrivileged("analyst") || mappingPrivileged("support") || !mappingPrivileged("admin") {
		t.Error("a mapping to a job is not judged by the job's grants")
	}
}

func open(t *testing.T) *Review {
	t.Helper()
	r, err := New("r1", Snapshot(store(t)), person("dana"), now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func itemOf(t *testing.T, r *Review, match func(Item) bool) Item {
	t.Helper()
	it := find(r.Items, match)
	if it == nil {
		t.Fatal("no such item")
	}
	return *it
}

// Regression 3. Reviewing yourself is refused under any spelling, as is a
// model and a service token, and so is keeping privileged access without a
// reason; keeping ordinary access without one is fine.
func TestTheRulesThatMakeAReviewOne(t *testing.T) {
	r := open(t)
	dana := itemOf(t, r, func(i Item) bool { return i.Principal == "dana" })
	sam := itemOf(t, r, func(i Item) bool { return i.Principal == "sam" })
	kit := itemOf(t, r, func(i Item) bool { return i.Principal == "kit" })
	mapping := itemOf(t, r, func(i Item) bool { return i.Kind == Mapping })

	for _, name := range []string{"dana", "Dana", " DANA ", "mailto:dana"} {
		if _, err := r.Check(dana.ID, Keep, person(name), "runs the site"); err == nil ||
			!strings.Contains(err.Error(), "own") {
			t.Errorf("%q reviewed dana's own access: %v", name, err)
		}
	}
	if _, err := r.Check(mapping.ID, Keep, person("ADA@example.com"), "edits"); err == nil {
		t.Error("a member of a group reviewed the group's mapping")
	}
	model := Decider{Name: "lee", Kind: audit.KindAI, Verified: true, Model: "a model"}
	if _, err := r.Check(kit.ID, Keep, model, ""); err == nil || !strings.Contains(err.Error(), "model") {
		t.Errorf("a model decided: %v", err)
	}
	service := Decider{Name: "ci-bot", Kind: audit.KindService, Verified: true}
	if _, err := r.Check(kit.ID, Keep, service, ""); err == nil {
		t.Error("a service token decided")
	}
	if _, err := r.Check(kit.ID, Keep, Decider{Name: "lee", Kind: audit.KindHuman}, ""); err == nil {
		t.Error("somebody nobody proved decided")
	}
	if _, err := r.Check(sam.ID, Keep, person("lee"), "  "); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("privileged access was kept with no reason: %v", err)
	}
	if _, err := r.Check(sam.ID, Keep, person("lee"), "the other administrator"); err != nil {
		t.Errorf("privileged access with a reason was refused: %v", err)
	}
	if _, err := r.Check(kit.ID, Keep, person("lee"), ""); err != nil {
		t.Errorf("ordinary access kept without a reason was refused: %v", err)
	}
	if _, err := r.Check(kit.ID, "reduce", person("lee"), ""); err == nil || !strings.Contains(err.Error(), "revoke it, then grant") {
		t.Errorf("reduce: %v", err)
	}
	if _, err := r.Check("99", Keep, person("lee"), ""); err == nil {
		t.Error("an item the review never showed anybody was decided")
	}
	r.Record(kit.ID, Revoke, person("lee"), "", now)
	if _, err := r.Check(kit.ID, Keep, person("lee"), ""); err == nil {
		t.Error("a revoked item was kept afterwards, which would not give it back")
	}
}

// Regression 6. Every review record is accepted by the log; no reason text
// reaches it; a token's id goes under "credential".
func TestEveryReviewRecordIsAcceptedAndCarriesNoReason(t *testing.T) {
	dir := t.TempDir()
	log, err := audit.New(audit.Options{Path: filepath.Join(dir, "audit.jsonl"), Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	r := open(t)
	write := func(action string, d map[string]string) map[string]string {
		t.Helper()
		e, err := log.Append(audit.Record{Action: action, Resource: r.Resource(), Outcome: audit.Success,
			Principal: "lee", Kind: audit.KindHuman, Verified: true, Detail: d})
		if err != nil {
			t.Fatalf("%s refused: %v", action, err)
		}
		return e.Detail
	}
	write("review.started", r.StartedDetail())
	const reason = "Priya in finance still needs it"
	for _, it := range r.Items {
		if it.Principal == "dana" {
			continue
		}
		v := Keep
		if it.Kind == Credential {
			v = Revoke
		}
		dec := r.Record(it.ID, v, person("lee"), reason, now)
		d := write("review."+string(v), r.DecisionDetail(it, dec))
		for k, val := range d {
			if strings.Contains(val, "Priya") || strings.Contains(val, reason) {
				t.Errorf("%s carries the reason under %q", it.ID, k)
			}
		}
		if d["reason"] != "given" || d["kind"] != string(it.Kind) || d["dormant"] == "" || d["privileged"] == "" {
			t.Errorf("item %s: %v", it.ID, d)
		}
		if it.Kind == Credential && (d["credential"] != it.Credential || d["principal"] != it.Principal) {
			t.Errorf("a token's revoke does not name the credential: %v", d)
		}
		for k := range d {
			if strings.Contains(k, "token") {
				t.Errorf("a detail key %q the log would refuse", k)
			}
		}
	}
	sum, err := r.Close(person("lee"), r.Items, false, now)
	if err == nil {
		t.Fatal("closed with dana's item undecided and a second administrator to decide it")
	}
	r.Record(itemOf(t, r, func(i Item) bool { return i.Principal == "dana" }).ID, Keep, person("sam"), "the owner", now)
	if sum, err = r.Close(person("lee"), r.Items, false, now); err != nil {
		t.Fatal(err)
	}
	if d := write("review.closed", r.ClosedDetail(sum)); d["kept"] == "" || d["revoked"] != "1" {
		t.Errorf("review.closed: %v", d)
	}
	if len(r.Decisions) == 0 || r.Decisions[0].Why != reason {
		t.Error("the reason is not kept in the review itself")
	}
}

// Regression 7, the half the package owns. Close is refused while
// anything is undecided, and a closed review evidences the quarter up to
// its close: one in six months is unproven, two are covered.
func TestCloseNeedsEveryDecisionAndTwoMakeTheControlProven(t *testing.T) {
	r := open(t)
	if _, err := r.Close(person("lee"), r.Items, false, now); err == nil || !strings.Contains(err.Error(), "undecided") {
		t.Fatalf("closed with nothing decided: %v", err)
	}
	for _, it := range r.Items {
		r.Record(it.ID, Keep, person("lee"), "still needed", now)
	}
	if _, err := r.Close(person("lee"), r.Items, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(person("lee"), r.Items, false, now); err == nil {
		t.Error("a closed review closed twice")
	}
	if _, err := r.Check("1", Keep, person("lee"), "x"); err == nil {
		t.Error("a closed review took a decision")
	}
	first := r.Evidence()
	if err := first.Validate(); err != nil {
		t.Fatal(err)
	}
	period := assurance.Period{From: now.Add(-182 * day), To: now}
	if cov := assurance.Measure(Control(), []assurance.Evidence{first}, period); cov.Proven() || cov.Complete() {
		t.Errorf("one review in six months: %s", cov.Why())
	}
	earlier := &Review{ID: "r0", Closed: now.Add(-91 * day), ClosedBy: "lee", Closer: audit.KindHuman, Summary: &Summary{}}
	cov := assurance.Measure(Control(), []assurance.Evidence{earlier.Evidence(), first}, period)
	if !cov.Proven() || !cov.Complete() {
		t.Errorf("two reviews a quarter apart: %s", cov.Why())
	}
}

// Regression 9, the half the package owns. With one administrator there
// is nobody else to decide their own access: the review closes alone,
// saying how much of theirs went unreviewed, and the record says alone.
func TestTheOnlyAdministratorClosesAlone(t *testing.T) {
	in := store(t)
	in.Policy.Revoke("sam", auth.RoleAdmin, "/")
	r, err := New("r1", Snapshot(in), person("dana"), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range r.Items {
		if !it.Holder("dana") {
			r.Record(it.ID, Keep, person("dana"), "needed", now)
		}
	}
	if _, err := r.Close(person("dana"), r.Items, false, now); err == nil {
		t.Fatal("dana's own item was left undecided with a second administrator to decide it")
	}
	sum, err := r.Close(person("dana"), r.Items, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Alone || sum.Own != 1 || r.ClosedDetail(sum)["alone"] != "true" {
		t.Errorf("closed alone: %+v %v", sum, r.ClosedDetail(sum))
	}
	if !strings.Contains(r.Evidence().What, "only administrator") {
		t.Errorf("the evidence does not say it was done alone: %s", r.Evidence().What)
	}
}

// Regression 10. A grant made after the snapshot is reported at the close
// as not reviewed; a grant taken away some other way before anybody
// decided it does not hold the review open.
func TestTheSnapshotIsWhatWasReviewed(t *testing.T) {
	in := store(t)
	r, err := New("r1", Snapshot(in), person("lee"), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Policy.Grant(auth.Binding{Principal: "late", Role: auth.RolePublisher, Resource: "/",
		GrantedAt: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	in.Policy.Revoke("kit", auth.RoleAuthor, "/blog")
	for _, it := range r.Items {
		if it.Principal != "kit" {
			r.Record(it.ID, Keep, person("lee"), "needed", now)
		}
	}
	sum, err := r.Close(person("lee"), Snapshot(in), false, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.NotReviewed) != 1 || sum.NotReviewed[0].Principal != "late" || sum.Gone != 1 {
		t.Errorf("closing after a grant and a removal: %+v", sum)
	}
	if r.ClosedDetail(sum)["not_reviewed"] != "1" {
		t.Error("review.closed does not count what went unreviewed")
	}
}

// One review is open at a time, and each is a file of its own.
func TestOneReviewAtATime(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "access", "reviews")}
	if r, err := s.Current(); err != nil || r != nil {
		t.Fatalf("an empty store has a review: %v %v", r, err)
	}
	first, _ := New(NewID(now), Snapshot(store(t)), person("lee"), now)
	if err := s.Start(first); err != nil {
		t.Fatal(err)
	}
	second, _ := New(NewID(now), nil, person("lee"), now)
	if err := s.Start(second); !errors.Is(err, ErrOpen) {
		t.Fatalf("a second review started while one was open: %v", err)
	}
	if _, err := s.Update(func(r *Review) error {
		for _, it := range r.Items {
			r.Record(it.ID, Keep, person("lee"), "needed", now)
		}
		_, err := r.Close(person("lee"), r.Items, false, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if at, ok, err := s.LastClosed(); err != nil || !ok || !at.Equal(now) {
		t.Fatalf("last closed: %v %v %v", at, ok, err)
	}
	if err := s.Start(second); err != nil {
		t.Fatalf("a review after the last one closed: %v", err)
	}
	if _, err := s.Update(func(r *Review) error { return errors.New("no") }); err == nil {
		t.Error("a failed change was reported as made")
	}
}
