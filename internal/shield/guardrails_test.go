// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

func TestAnAutomaticProtectionNeverRunsPastADayFromItsStart(t *testing.T) {
	root := t.TempDir()
	p := ok(Block, "source:"+handle)
	p.Auto, p.Until = true, t0.Add(20*time.Hour)
	first, fresh, err := Apply(root, p, t0)
	if err != nil || !fresh {
		t.Fatal(err)
	}
	// Within its own day: lengthened in place.
	p.Until = t0.Add(24 * time.Hour)
	if got, fresh, _ := Apply(root, p, t0.Add(time.Hour)); fresh || got.ID != first.ID || !got.Until.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("not lengthened in place: %+v", got)
	}
	// Past it: a new protection with its own start, and the old one says
	// so; the automatic one never stretches past its day.
	later := t0.Add(23 * time.Hour)
	p.Until = later.Add(24 * time.Hour)
	second, fresh, err := Apply(root, p, later)
	if err != nil || !fresh || second.ID == first.ID || !second.At.Equal(later) {
		t.Fatalf("renewed past its limit: %+v %v", second, err)
	}
	st, _ := Load(root)
	var old Protection
	for _, q := range append(st.Protections, st.Ended...) {
		if q.ID == first.ID {
			old = q
		}
	}
	if old.ReplacedBy != second.ID || old.ActiveAt(later) {
		t.Fatalf("the first one did not end: %+v", old)
	}
	for _, q := range st.Protections {
		if q.Auto && q.Until.Sub(q.At) > MaxAuto {
			t.Fatalf("an automatic protection lasts %s", q.Until.Sub(q.At))
		}
	}
}

func TestAPersonsProtectionIsAPersonsNotAPlaybooks(t *testing.T) {
	root := t.TempDir()
	auto := ok(Block, "source:"+handle)
	auto.Auto, auto.By, auto.Playbook = true, "playbook:x", "x"
	a, _, _ := Apply(root, auto, t0)
	manual := ok(Block, "source:"+handle)
	manual.By, manual.Until = "dana", t0.Add(6*24*time.Hour)
	m, fresh, err := Apply(root, manual, t0.Add(time.Minute))
	if err != nil || !fresh || m.ID == a.ID || m.Auto || m.By != "dana" || m.Playbook != "" {
		t.Fatalf("a person's week was folded into the playbook's record: %+v %v", m, err)
	}
}

func TestARecordWrittenToLastForeverEnds(t *testing.T) {
	p := Protection{Auto: true, At: t0, Until: t0.Add(1000 * time.Hour)}
	if !p.ActiveAt(t0.Add(23 * time.Hour)) {
		t.Fatal("ended early")
	}
	if p.ActiveAt(t0.Add(25 * time.Hour)) {
		t.Fatal("an automatic protection outlived its day")
	}
	p.Auto = false
	if p.ActiveAt(t0.Add(8 * 24 * time.Hour)) {
		t.Fatal("a manual protection outlived its week")
	}
}

func TestNothingOnTheInsideIsBlocked(t *testing.T) {
	for _, n := range []string{"10.0.0.0/16", "172.16.0.0/16", "192.168.1.0/24", "100.64.0.0/16", "127.0.0.0/16", "fd00::/48", "fe80::/48"} {
		if err := ok(Block, "net:"+n).Validate(t0); err == nil || !strings.Contains(err.Error(), "on the inside") {
			t.Errorf("%s: %v", n, err)
		}
	}
	g := guard(t)
	for _, a := range []string{"10.1.2.3", "100.64.1.1", "fd00::5"} {
		put(t, g, ok(Block, "source:"+audit.Pseudonym(testKey, a)))
		g.Refresh()
		if _, blocked := g.Blocked(a, Site, t0); blocked {
			t.Errorf("%s was blocked", a)
		}
	}
}

func TestAnIPv6SourceIsItsSlash64(t *testing.T) {
	r := newRig(t, injection())
	for _, a := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::3"} {
		r.see("chatbot-injection", a, "help")
	}
	if _, blocked := r.Guard.Blocked("2001:db8:1:2:abcd::9", Site, r.clock); !blocked {
		t.Fatal("rotating inside one /64 escaped counting or blocking")
	}
	if _, blocked := r.Guard.Blocked("2001:db8:1:3::1", Site, r.clock); blocked {
		t.Fatal("the next /64 was blocked")
	}
}

func TestAStrongSignInKeepsItsSourceOnTheAdmin(t *testing.T) {
	var signin Playbook
	for _, pb := range Builtins() {
		if pb.Name == "signin-attack" {
			signin = pb
		}
	}
	signin.On.Count = 1 // one signal per stage, to keep the test short
	signin.Stages = []Stage{
		{Do: []Step{{Action: "block-source", Where: Admin, For: Duration(time.Hour)}}},
		{Do: []Step{{Action: "block-source", Where: All, For: Duration(time.Hour)}}},
	}
	r := newRig(t, signin)
	if err := Vouch(r.Root, r.Guard.Handles(mustAddr("203.0.113.9")), r.clock); err != nil {
		t.Fatal(err)
	}
	r.Guard.Refresh()
	got := r.see("signin-failures", "203.0.113.9", "")
	if len(got) != 1 || !strings.Contains(got[0].Did[0], "did not block the admin") || !got[0].Tell {
		t.Fatalf("%+v", got)
	}
	if len(r.notified) != 1 {
		t.Fatal("nobody was told the block was held back")
	}
	if _, blocked := r.Guard.Blocked("203.0.113.9", Admin, r.clock); blocked {
		t.Fatal("an administrator's own address was blocked from the admin")
	}
	// The second stage blocks the site only.
	r.clock = r.clock.Add(time.Hour + time.Minute) // past the rest after a stage
	got = r.see("signin-failures", "203.0.113.9", "")
	if !strings.Contains(got[0].Did[0], "on the site") || !strings.Contains(got[0].Did[0], "not the admin") {
		t.Fatalf("%+v", got)
	}
	if _, blocked := r.Guard.Blocked("203.0.113.9", Admin, r.clock); blocked {
		t.Fatal("blocked from the admin")
	}
	if _, blocked := r.Guard.Blocked("203.0.113.9", Site, r.clock); !blocked {
		t.Fatal("not blocked from the site")
	}
	// A month later, the vouching has lapsed.
	r.clock = r.clock.Add(VouchFor + time.Hour)
	r.Guard.Refresh()
	got = r.see("signin-failures", "203.0.113.9", "")
	if !strings.HasPrefix(got[0].Did[0], "blocked the source on the admin") {
		t.Fatalf("%+v", got)
	}
}

func TestALockdownNobodyCanGetPastIsNotApplied(t *testing.T) {
	h := Duration(time.Hour)
	pb := Playbook{Name: "x", Title: "x", Mode: "act",
		On:     Trigger{Signal: "decoy", Per: "any", Count: 1, Within: h},
		Stages: []Stage{{Do: []Step{{Action: "lockdown", For: h}}}}}
	r := newRig(t, pb)
	r.CanLockdown = func() bool { return false }
	got := r.see("decoy", "", "")
	if !strings.HasPrefix(got[0].Did[0], "did not lock the admin down") || !got[0].Tell {
		t.Fatalf("%+v", got)
	}
	if _, on := r.Guard.Lockdown(r.clock); on {
		t.Fatal("locked down with nobody able to get past it")
	}
	if len(r.notified) != 1 {
		t.Fatal("nobody was told")
	}
}

func TestHoldingEveryPlaybookTakesOnePersonAndLettingThemActTakesTwo(t *testing.T) {
	r := newRig(t, injection())
	if err := HoldAll(r.Root, "dana", "", r.clock); err == nil {
		t.Fatal("held without a reason")
	}
	if err := HoldAll(r.Root, "dana", "checking a mistaken block", r.clock); err != nil {
		t.Fatal(err)
	}
	r.Guard.Refresh()
	var got []Response
	for i := 0; i < 3; i++ {
		got = r.see("chatbot-injection", "203.0.113.9", "help")
	}
	if got[0].Mode != "held" || !strings.Contains(got[0].Did[0], "held to watching") {
		t.Fatalf("%+v", got)
	}
	if _, blocked := r.Guard.Blocked("203.0.113.9", Site, r.clock); blocked {
		t.Fatal("acted while held")
	}
	p, err := ProposeRelease(r.Root, "the mistake is fixed", "dana", r.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decide(r.Root, p.ID, "dana", true, false, r.clock); err == nil {
		t.Fatal("the person who held them let them act again alone")
	}
	if _, err := Decide(r.Root, p.ID, "lee", true, false, r.clock); err != nil {
		t.Fatal(err)
	}
	if st, _ := Load(r.Root); st.Watching != nil {
		t.Fatal("still held after approval")
	}
	if _, err := ReleaseOnMachine(r.Root, "x", "root", r.clock); err == nil {
		t.Fatal("released what was not held")
	}
}

func TestAPersonLiftingABlockTakesItsStageBack(t *testing.T) {
	r := newRig(t, injection())
	var got []Response
	for i := 0; i < 3; i++ {
		got = r.see("chatbot-injection", "203.0.113.9", "help")
	}
	if got[0].Stage != 1 || len(got[0].Applied) != 1 {
		t.Fatalf("%+v", got)
	}
	if _, err := Lift(r.Root, got[0].Applied[0], "dana", r.clock); err != nil {
		t.Fatal(err)
	}
	r.Guard.Refresh()
	r.clock = r.clock.Add(time.Hour + time.Minute) // past the rest after a stage
	for i := 0; i < 3; i++ {
		got = r.see("chatbot-injection", "203.0.113.9", "help")
	}
	if got[0].Stage != 1 {
		t.Fatalf("escalated past a block a person lifted: stage %d", got[0].Stage)
	}
}

func TestAfterAStageTheSourceIsNotCountedForAWhile(t *testing.T) {
	pb := injection()
	r := newRig(t, pb)
	for i := 0; i < 3; i++ {
		r.see("chatbot-injection", "203.0.113.9", "help")
	}
	// A burst straight after, as another process might see before the
	// block reaches it: no second stage at once.
	for i := 0; i < 9; i++ {
		if got := r.see("chatbot-injection", "203.0.113.9", "help"); len(got) != 0 {
			t.Fatalf("a second stage within the cooldown: %+v", got)
		}
	}
	r.clock = r.clock.Add(time.Hour + time.Minute) // past the rest after a stage
	var got []Response
	for i := 0; i < 3; i++ {
		got = r.see("chatbot-injection", "203.0.113.9", "help")
	}
	if len(got) != 1 || got[0].Stage != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestAdminHuntingCountsDistinctAddresses(t *testing.T) {
	var hunt Playbook
	for _, pb := range Builtins() {
		if pb.Name == "admin-hunting" {
			hunt = pb
		}
	}
	r := newRig(t, hunt)
	// Somebody on the wrong host, trying to sign in again and again.
	for i := 0; i < 20; i++ {
		if got := r.see("admin-hunt", "203.0.113.9", "/signin"); len(got) != 0 {
			t.Fatalf("one address asked for again was taken as hunting: %+v", got)
		}
	}
	r.see("admin-hunt", "203.0.113.9", "/security")
	got := r.see("admin-hunt", "203.0.113.9", "/tokens")
	if len(got) != 1 || !strings.Contains(got[0].Did[0], "on the site") {
		t.Fatalf("%+v", got)
	}
	if _, blocked := r.Guard.Blocked("203.0.113.9", Admin, r.clock); blocked {
		t.Fatal("hunting on the site closed the admin")
	}
}

func TestBlocksNeedSignalsNobodyCanRaiseForSomebodyElse(t *testing.T) {
	pb := injection()
	pb.On.Count = 1
	if err := pb.Validate(); err == nil || !strings.Contains(err.Error(), "innocent") {
		t.Fatalf("a block on one phrase match: %v", err)
	}
	Signals["test-spoofable"] = "a signal anybody can send"
	Traits["test-spoofable"] = Trait{Confidence: 3, Spoofable: 3}
	defer delete(Signals, "test-spoofable")
	defer delete(Traits, "test-spoofable")
	pb = injection()
	pb.On.Signal = "test-spoofable"
	if err := pb.Validate(); err == nil || !strings.Contains(err.Error(), "somebody else's name") {
		t.Fatalf("a block on a spoofable signal: %v", err)
	}
	pb.Stages = []Stage{{Do: []Step{{Action: "notify"}}}}
	if err := pb.Validate(); err != nil {
		t.Fatalf("notifying on it: %v", err)
	}
	for _, pb := range Builtins() {
		if err := pb.Validate(); err != nil {
			t.Errorf("%s: %v", pb.Name, err)
		}
		if _, ok := Traits[pb.On.Signal]; !ok {
			t.Errorf("%s has no traits", pb.On.Signal)
		}
	}
	for name := range Signals {
		if _, ok := Traits[name]; !ok {
			t.Errorf("signal %s has no traits", name)
		}
	}
}

func TestPrecisionIsCountedFromVerdicts(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 12; i++ {
		p := ok(Block, "source:"+audit.Pseudonym(testKey, "203.0.113."+string(rune('a'+i))))
		p.Auto, p.Playbook, p.By = true, "x", "playbook:x"
		applied, _, err := Apply(root, p, t0)
		if err != nil {
			t.Fatal(err)
		}
		verdict := Right
		if i < 2 {
			verdict = Mistake
		}
		if _, err := Judge(root, applied.ID, verdict, "dana", t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Judge(root, "sh-none", Right, "dana", t0); err == nil {
		t.Fatal("judged nothing")
	}
	st, _ := Load(root)
	recs := Records(st)
	if len(recs) != 1 || recs[0].Right != 10 || recs[0].Mistakes != 2 || recs[0].Applied != 12 {
		t.Fatalf("%+v", recs)
	}
	rate, low, high, enough := recs[0].Precision()
	if !enough || rate < 0.83 || rate > 0.84 || low > rate || high < rate || low < 0.5 {
		t.Fatalf("%v %v %v %v", rate, low, high, enough)
	}
	if _, _, _, enough := (Record{Right: 3}).Precision(); enough {
		t.Fatal("quoted from three verdicts")
	}
}

func TestAnUnreadableRecordIsSetAsideByRepair(t *testing.T) {
	root := t.TempDir()
	if _, err := Repair(root, t0); err == nil {
		t.Fatal("repaired nothing")
	}
	os.WriteFile(Path(root), []byte("{"), 0o600)
	rep, err := Repair(root, t0)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(rep.Aside); string(b) != "{" {
		t.Fatal("what it held was not kept")
	}
	if _, err := Load(root); err != nil {
		t.Fatal(err)
	}
	if _, frozen := Frozen(root, t0); frozen {
		t.Fatal("still frozen after repair")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestOneMistypedTokenBlocksNobody(t *testing.T) {
	var signin Playbook
	for _, pb := range Builtins() {
		if pb.Name == "signin-attack" {
			signin = pb
		}
	}
	r := newRig(t, signin)
	for i := 0; i < 4; i++ {
		if got := r.see("signin-failures", "203.0.113.9", ""); len(got) != 0 {
			t.Fatalf("blocked after %d wrong tokens: %+v", i+1, got)
		}
	}
	if got := r.see("signin-failures", "203.0.113.9", ""); len(got) != 1 || !strings.HasPrefix(got[0].Did[0], "blocked the source on the admin") {
		t.Fatalf("the fifth: %+v", got)
	}
}

func TestEverySignalSaysWhatItCounts(t *testing.T) {
	for name := range Signals {
		if c, ok := Counted[name]; !ok || c[0] == "" || c[1] == "" {
			t.Errorf("%s says nothing about what it counts", name)
		}
	}
}

func TestAnAdministratorsAddressKeepsTheAdminWhateverAPlaybookBlocked(t *testing.T) {
	g := guard(t)
	if err := Vouch(g.Root, g.Handles(mustAddr("203.0.113.9")), t0); err != nil {
		t.Fatal(err)
	}
	auto := ok(Block, "net:203.0.113.0/24")
	auto.Auto, auto.Playbook = true, "x"
	put(t, g, auto)
	g.Refresh()
	if _, blocked := g.Blocked("203.0.113.9", Admin, t0); blocked {
		t.Fatal("a playbook's network block shut an administrator out of the admin")
	}
	if _, blocked := g.Blocked("203.0.113.9", Site, t0); !blocked {
		t.Fatal("the site is not covered by the exemption")
	}
	if _, blocked := g.Blocked("203.0.113.10", Admin, t0); !blocked {
		t.Fatal("the rest of the network got the administrator's exemption")
	}
	// A person's block is a person's decision.
	g2 := guard(t)
	Vouch(g2.Root, g2.Handles(mustAddr("203.0.113.9")), t0)
	put(t, g2, ok(Block, "net:203.0.113.0/24"))
	g2.Refresh()
	if _, blocked := g2.Blocked("203.0.113.9", Admin, t0); !blocked {
		t.Fatal("a person's block did not hold")
	}
}

func TestAHoldDoesNotSkipStagesWhenItIsReleased(t *testing.T) {
	r := newRig(t, injection())
	HoldAll(r.Root, "dana", "looking at a mistake", r.clock)
	r.Guard.Refresh()
	cross := func() Response {
		var got []Response
		for i := 0; i < 3; i++ {
			got = r.see("chatbot-injection", "203.0.113.9", "help")
		}
		r.clock = r.clock.Add(time.Hour + time.Minute)
		return got[0]
	}
	// Held, it says what it would have done, escalating as it would have.
	if a, b := cross(), cross(); a.Mode != "held" || b.Stage != 2 {
		t.Fatalf("held: %+v %+v", a, b)
	}
	if _, err := ReleaseOnMachine(r.Root, "fixed", "dana", r.clock); err != nil {
		t.Fatal(err)
	}
	r.Guard.Refresh()
	if got := cross(); got.Mode != "act" || got.Stage != 1 {
		t.Fatalf("the first action after the hold was stage %d", got.Stage)
	}
}

func TestAnUnverifiedSourceIsCountedAndNotBlocked(t *testing.T) {
	r := newRig(t, injection())
	var got []Response
	for i := 0; i < 3; i++ {
		got = r.Observe(Signal{Name: "chatbot-injection", Source: "104.16.1.1", Unverified: true, At: r.clock})
	}
	if len(got) != 1 || !strings.Contains(got[0].Did[0], "not named in network.trusted_proxies") || !got[0].Tell {
		t.Fatalf("%+v", got)
	}
	if _, blocked := r.Guard.Blocked("104.16.1.1", Site, r.clock); blocked {
		t.Fatal("an unnamed proxy was blocked as one visitor")
	}
	if len(r.notified) != 1 {
		t.Fatal("nobody was told")
	}
}

func TestWatchingSaysWhatItWouldHaveDoneAndDidNot(t *testing.T) {
	pb := injection()
	pb.Mode = "watch"
	pb.Stages[0].Do = append(pb.Stages[0].Do, Step{Action: "notify"}, Step{Action: "open-case"})
	r := newRig(t, pb)
	var got []Response
	for i := 0; i < 3; i++ {
		got = r.see("chatbot-injection", "203.0.113.9", "help")
	}
	if got[0].Did[1] != "would have told the security contact" || got[0].Did[2] != "would have opened a case" {
		t.Fatalf("%q", got[0].Did)
	}
	if len(r.notified) != 0 || len(r.cases) != 0 {
		t.Fatal("watching told somebody")
	}
}

func TestRepairKeepsWhatStillReadsWhole(t *testing.T) {
	root := t.TempDir()
	// The protections are damaged; the rest reads.
	os.WriteFile(Path(root), []byte(`{"protections": [{"id": 5}], "trusted": ["198.51.100.0/24"],
		"vouched": [{"handle": "`+handle+`", "at": "2026-10-04T12:00:00Z"}], "decoys": [{"id": "sh-1", "hash": "x", "note": "CI"}]}`), 0o600)
	rep, err := Repair(root, t0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Load(root)
	if err != nil || len(st.Trusted) != 1 || len(st.Vouched) != 1 || len(st.Decoys) != 1 || len(st.Protections) != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	if len(rep.Kept) != 3 || !strings.Contains(strings.Join(rep.Lost, ","), "protections") {
		t.Fatalf("%+v", rep)
	}
	// A playbook file nobody can read is set aside too.
	os.WriteFile(BookPath(root), []byte("{"), 0o600)
	if _, err := RepairBook(root, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBook(root); err != nil {
		t.Fatal(err)
	}
}

func TestASpentBudgetTellsSomebodyThenPausesTheAgent(t *testing.T) {
	var pb Playbook
	for _, x := range Builtins() {
		if x.Name == "model-budget-spent" {
			pb = x
		}
	}
	r := newRig(t, pb)
	if got := r.Observe(Signal{Name: "model-spend", Subject: "agent:triage", At: r.clock}); len(got) != 1 || len(r.notified) != 1 {
		t.Fatalf("%+v", got)
	}
	// It keeps being refused: one stage an hour, not one a call.
	if got := r.Observe(Signal{Name: "model-spend", Subject: "agent:triage", At: r.clock.Add(time.Minute)}); len(got) != 0 {
		t.Fatalf("again at once: %+v", got)
	}
	r.clock = r.clock.Add(2 * time.Hour)
	got := r.Observe(Signal{Name: "model-spend", Subject: "agent:triage", At: r.clock})
	if len(got) != 1 || got[0].Stage != 2 || !strings.HasPrefix(got[0].Did[0], "paused the agent triage") {
		t.Fatalf("%+v", got)
	}
	// A chatbot has nothing to pause; the gateway already quotes pages.
	r.clock = r.clock.Add(2 * time.Hour)
	r.Observe(Signal{Name: "model-spend", Subject: "chatbot:help", At: r.clock})
	r.clock = r.clock.Add(2 * time.Hour)
	if got := r.Observe(Signal{Name: "model-spend", Subject: "chatbot:help", At: r.clock}); !strings.HasPrefix(got[0].Did[0], "nothing to pause") {
		t.Fatalf("%+v", got)
	}
	// A refused route is cut.
	var route Playbook
	for _, x := range Builtins() {
		if x.Name == "model-route-refused" {
			route = x
		}
	}
	r2 := newRig(t, route)
	if got := r2.Observe(Signal{Name: "route-trouble", Subject: "hosted", At: r2.clock}); !strings.HasPrefix(got[0].Did[0], "cut the model route hosted for 6 hours") {
		t.Fatalf("%+v", got)
	}
	if _, on := Find(r2.Root, Route, "hosted", r2.clock); !on {
		t.Fatal("not cut")
	}
}

func TestRoutesTokensAndUploadsAreNamedExactly(t *testing.T) {
	good := []Protection{ok(Route, "hosted"), ok(Token, "0a1b2c3d4e5f"), ok(Feature, "upload:"+strings.Repeat("a", 64))}
	for _, p := range good {
		if err := p.Validate(t0); err != nil {
			t.Errorf("%s %s: %v", p.Kind, p.Target, err)
		}
	}
	bad := []Protection{ok(Route, "Hosted Route"), ok(Token, "../x"), ok(Feature, "upload:../../etc"), ok(Feature, "upload")}
	for _, p := range bad {
		if err := p.Validate(t0); err == nil {
			t.Errorf("%s %q was accepted", p.Kind, p.Target)
		}
	}
	g := guard(t)
	put(t, g, ok(Token, "0a1b2c3d4e5f"))
	if _, on := g.Suspended("0a1b2c3d4e5f", t0); !on {
		t.Fatal("not suspended")
	}
	if _, on := g.Suspended("ffffffffffff", t0); on {
		t.Fatal("another token was suspended")
	}
}

func TestAViolationIsToldWhenManyNetworksReportItAndNeverBlocks(t *testing.T) {
	var pb Playbook
	for _, x := range Builtins() {
		if x.Name == "page-tampering" {
			pb = x
		}
	}
	if err := pb.Validate(); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, pb)
	group := "script-src-elem https://evil.example /checkout"
	// One network reporting it ten times is one network.
	for i := 0; i < 10; i++ {
		if got := r.Observe(Signal{Name: "page-violation", Subject: group, By: "net-1", Source: "203.0.113.9", At: r.clock}); len(got) != 0 {
			t.Fatalf("one network: %+v", got)
		}
	}
	var got []Response
	for i := 2; i <= 5; i++ {
		got = r.Observe(Signal{Name: "page-violation", Subject: group, By: fmt.Sprint("net-", i), Source: "203.0.113.9", At: r.clock})
	}
	if len(got) != 1 || len(r.notified) != 1 {
		t.Fatalf("%+v", got)
	}
	if st := r.state(t); len(st.Protections) != 0 {
		t.Fatal("a report blocked somebody")
	}
	// And no playbook may make a report block, slow, lock down or freeze.
	for _, step := range []Step{{Action: "block-source", Where: Site, For: Duration(time.Hour)}, {Action: "lockdown", For: Duration(time.Hour)}} {
		x := pb
		x.On.Per = "source"
		x.Stages = []Stage{{Do: []Step{step}}}
		if err := x.Validate(); err == nil {
			t.Fatalf("a report may %s", step.Action)
		}
	}
}
