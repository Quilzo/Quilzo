// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package accessreview

import (
	"errors"
	"fmt"
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
	sum, err := r.Close(person("lee"), r.Items, false, nil, now)
	if err == nil {
		t.Fatal("closed with dana's item undecided and a second administrator to decide it")
	}
	r.Record(itemOf(t, r, func(i Item) bool { return i.Principal == "dana" }).ID, Keep, person("sam"), "the owner", now)
	if sum, err = r.Close(person("lee"), r.Items, false, nil, now); err != nil {
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
	if _, err := r.Close(person("lee"), r.Items, false, nil, now); err == nil || !strings.Contains(err.Error(), "undecided") {
		t.Fatalf("closed with nothing decided: %v", err)
	}
	for _, it := range r.Items {
		r.Record(it.ID, Keep, person("lee"), "still needed", now)
	}
	if _, err := r.Close(person("lee"), r.Items, false, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(person("lee"), r.Items, false, nil, now); err == nil {
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
	if _, err := r.Close(person("dana"), r.Items, false, nil, now); err == nil {
		t.Fatal("dana's own item was left undecided with a second administrator to decide it")
	}
	sum, err := r.Close(person("dana"), r.Items, true, nil, now)
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
	sum, err := r.Close(person("lee"), Snapshot(in), false, nil, now)
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
		_, err := r.Close(person("lee"), r.Items, false, nil, now)
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

// A revoke may take what the reviewer was shown and nothing that only
// shares its principal, role and resource: not a deny (provisioning's
// suspension is a deny of reader on "/"), not what provisioning granted,
// and not another app role's bindings.
func TestAnItemCoversOnlyTheGrantItShowed(t *testing.T) {
	reader := Item{Kind: Binding, Principal: "lee", Role: "reader", Resource: "/"}
	app := Item{Kind: Binding, Principal: "lee", Role: "shop/clerk", AppRole: true}
	for _, c := range []struct {
		it   Item
		b    auth.Binding
		want bool
	}{
		{reader, auth.Binding{Principal: "lee", Role: auth.RoleReader, Resource: "/", GrantedBy: "dana"}, true},
		{reader, auth.Binding{Principal: "lee", Role: auth.RoleReader, Resource: "/", Deny: true, GrantedBy: provisioned}, false},
		{reader, auth.Binding{Principal: "lee", Role: auth.RoleReader, Resource: "/", Deny: true, GrantedBy: "dana"}, false},
		{reader, auth.Binding{Principal: "lee", Role: auth.RoleReader, Resource: "/", GrantedBy: provisioned}, false},
		{reader, auth.Binding{Principal: "Lee", Role: auth.RoleReader, Resource: "/"}, false},
		{reader, auth.Binding{Principal: "lee", Role: auth.RoleReader, Resource: "/blog"}, false},
		{reader, auth.Binding{Principal: "lee", Role: auth.RoleReader, Resource: "/", Via: auth.ViaApp("shop/clerk")}, false},
		{app, auth.Binding{Principal: "lee", Role: auth.RoleAuthor, Resource: "/shop", Via: auth.ViaApp("shop/clerk")}, true},
		{app, auth.Binding{Principal: "lee", Role: auth.RoleAuthor, Resource: "/shop", Via: auth.ViaApp("shop/owner")}, false},
		{app, auth.Binding{Principal: "lee", Role: auth.RoleAuthor, Resource: "/shop", Via: auth.ViaApp("shop/clerk"),
			GrantedBy: provisioned}, false},
		{Item{Kind: Credential, Principal: "lee", Role: "reader", Resource: "/"},
			auth.Binding{Principal: "lee", Role: auth.RoleReader, Resource: "/"}, false},
	} {
		if got := c.it.Covers(c.b); got != c.want {
			t.Errorf("%+v covers %+v: %v, want %v", c.it, c.b, got, c.want)
		}
	}
}

// NotHeldBy is the self-review rule on its own, so the host can ask it of
// a group's members as they are now.
func TestNotHeldByRefusesTheHolderUnderAnySpelling(t *testing.T) {
	group := Item{ID: "3", Kind: Mapping, Group: "Editors", Role: "publisher", Members: []string{"ada@example.com"}}
	if err := group.NotHeldBy("boss"); err != nil {
		t.Errorf("boss is not in the group: %v", err)
	}
	group.Members = append(group.Members, "Boss ")
	if err := group.NotHeldBy("boss"); err == nil || !strings.Contains(err.Error(), "own access") {
		t.Errorf("a member decided their group: %v", err)
	}
}

// A snapshot of a large provisioned store is taken in time to answer the
// request that asked for it, and the hourly posture scan, which takes one
// in a store that has never closed a review. It looked each item's holder
// up in every token and each member up in every user, and twenty thousand
// people in a group with ten thousand tokens took most of a minute.
func TestASnapshotOfALargeStoreIsQuick(t *testing.T) {
	pol := &auth.Policy{}
	for i := 0; i < 500; i++ {
		pol.Bindings = append(pol.Bindings, auth.Binding{Principal: fmt.Sprintf("p%d", i), Role: auth.RoleAuthor,
			Resource: "/", GrantedBy: "dana", GrantedAt: now.Add(-day).Unix()})
	}
	ts := &auth.TokenStore{}
	for i := 0; i < 10000; i++ {
		ts.Tokens = append(ts.Tokens, auth.Token{ID: fmt.Sprint("t", i), Principal: fmt.Sprintf("u%d@example.com", i),
			Session: true, CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), LastUsed: now.Unix()})
	}
	st := &scim.State{Mapping: map[string]string{"Everybody": "reader"}}
	everybody := scim.Group{ID: "g", DisplayName: "Everybody"}
	for i := 0; i < 20000; i++ {
		id := fmt.Sprint("u", i)
		st.Users = append(st.Users, scim.User{ID: id, UserName: fmt.Sprintf("u%d@example.com", i), Active: true})
		everybody.Members = append(everybody.Members, id)
	}
	st.Groups = []scim.Group{everybody}
	start := time.Now()
	items := Snapshot(Inputs{Policy: pol, Tokens: ts, SCIM: st, Now: now})
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("a snapshot of 500 grants, a group of 20000 and 10000 tokens took %v", took)
	}
	group := items[len(items)-1]
	if group.Kind != Mapping || len(group.Members) != 20000 || !group.LastActive.Equal(now) {
		t.Errorf("the group, its members and their last use: %d members, last active %v", len(group.Members),
			group.LastActive)
	}
}

// Closing alone, the closer's own items are theirs as the snapshot had
// them or as they are now: a group they joined after the start waits for
// nobody.
func TestClosingAloneCountsAGroupJoinedSinceAsOwn(t *testing.T) {
	group := Item{ID: "1", Kind: Mapping, Group: "Editors", Role: "publisher", Members: []string{"ada@example.com"}}
	r, err := New("r1", []Item{group}, person("boss"), now)
	if err != nil {
		t.Fatal(err)
	}
	joined := group
	joined.ID, joined.Members = "", []string{"ada@example.com", "boss"}
	if _, err := r.Close(person("boss"), []Item{joined}, false, nil, now); err == nil {
		t.Fatal("a review with two administrators closed with an item undecided")
	}
	sum, err := r.Close(person("boss"), []Item{joined}, true, nil, now)
	if err != nil {
		t.Fatalf("the only administrator could not close: %v", err)
	}
	if sum.Own != 1 || !sum.Alone {
		t.Errorf("the group boss joined since: %+v", sum)
	}
}

// An item every administrator holds, a group they are all in, is decided
// by nobody, and closes undecided and counted; one an administrator does
// not hold still waits for them.
func TestAnItemEveryAdministratorHoldsClosesUndecided(t *testing.T) {
	staff := Item{ID: "1", Kind: Mapping, Group: "Staff", Role: "reader", Members: []string{"dana", "sam", "kit"}}
	editors := Item{ID: "2", Kind: Mapping, Group: "Editors", Role: "publisher", Members: []string{"dana", "kit"}}
	r, err := New("r1", []Item{staff, editors}, person("dana"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Close(person("dana"), r.Items, false, []string{"dana", "sam"}, now); err == nil ||
		!strings.Contains(err.Error(), "(2)") {
		t.Fatalf("Editors, which sam may decide, did not wait for sam: %v", err)
	}
	if _, err := r.Check("2", Keep, person("sam"), ""); err != nil {
		t.Fatal(err)
	}
	r.Record("2", Keep, person("sam"), "", now)
	sum, err := r.Close(person("dana"), r.Items, false, []string{"dana", "sam"}, now)
	if err != nil {
		t.Fatalf("Staff, which every administrator is in, held the review open: %v", err)
	}
	if sum.Unreviewable != 1 || sum.Kept != 1 || r.ClosedDetail(sum)["unreviewable"] != "1" ||
		!strings.Contains(r.Evidence().What, "held by every administrator") {
		t.Errorf("what was left unreviewed is not said: %+v %v", sum, r.ClosedDetail(sum))
	}
	if heldByAll(nil, staff, staff) {
		t.Error("with nobody named, an item was held by everybody")
	}
}

// A close that waits names which of the waiting items are the closer's
// own. The list was the numbers alone, so an administrator who had decided
// everything they could was told items were undecided and nothing about
// why they could not decide them.
func TestACloseThatWaitsSaysWhichItemsAreYourOwn(t *testing.T) {
	r := open(t)
	for _, it := range r.Items {
		if !it.Holder("dana") {
			r.Record(it.ID, Keep, person("dana"), "still needed", now)
		}
	}
	own := itemOf(t, r, func(i Item) bool { return i.Kind == Binding && i.Principal == "dana" })
	_, err := r.Close(person("dana"), r.Items, false, []string{"dana", "sam"}, now)
	if err == nil {
		t.Fatal("closed with dana's own item undecided and sam to decide it")
	}
	if want := own.ID + " is your own, for another administrator to decide"; !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal does not say whose the item is: %v", err)
	}
	if _, err := r.Close(person("sam"), r.Items, false, []string{"dana", "sam"}, now); err == nil ||
		strings.Contains(err.Error(), "your own") {
		t.Errorf("sam was told dana's item is theirs: %v", err)
	}
	if got := listed([]string{"1", "3", "5"}, "is", "are"); got != "1, 3 and 5 are" {
		t.Errorf("listed: %q", got)
	}
}

// What a decision did is said the same way on both surfaces, in the past
// tense, and a revoked grant is not described as refusing the person: a
// grant revoked from somebody who holds another leaves them that one.
func TestADecisionIsSaidAsDoneAndARevokeAsWhatItTook(t *testing.T) {
	if Keep.Past() != "kept" || Revoke.Past() != "revoked" {
		t.Errorf("past: %q %q", Keep.Past(), Revoke.Past())
	}
	grant := Item{Kind: Binding, Principal: "kit", Role: "author", Resource: "/blog"}
	if got := grant.Revoked(); !strings.Contains(got, "kit's next request, it gives them nothing") ||
		strings.Contains(got, "is refused") {
		t.Errorf("a revoked grant: %q", got)
	}
	if got := (Item{Kind: Credential}).Revoked(); !strings.Contains(got, "every session made from it") {
		t.Errorf("a revoked token: %q", got)
	}
	if got := (Item{Kind: Mapping}).Revoked(); !strings.Contains(got, "its members lose what it gave") {
		t.Errorf("a revoked mapping: %q", got)
	}
	r := open(t)
	sam := itemOf(t, r, func(i Item) bool { return i.Kind == Binding && i.Principal == "sam" })
	if _, err := r.Check(sam.ID, Keep, person("dana"), ""); err == nil ||
		!strings.Contains(err.Error(), "Why on People") || !strings.Contains(err.Error(), "--why") {
		t.Errorf("a privileged keep with no reason says how to give one on only one surface: %v", err)
	}
}
