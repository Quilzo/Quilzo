// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

type rig struct {
	*Engine
	clock    time.Time
	notified []Response
	cases    []Response
	records  []string
}

func newRig(t *testing.T, pbs ...Playbook) *rig {
	t.Helper()
	r := &rig{clock: t0}
	g := &Guard{Root: t.TempDir(), Key: testKey, ASN: func(a netip.Addr) (uint32, bool) {
		if strings.HasPrefix(a.String(), "192.0.2.") {
			return 64500, true
		}
		return 0, false
	}}
	r.Engine = &Engine{Root: g.Root, Guard: g,
		Playbooks: func() []Playbook { return pbs },
		Notify:    func(x Response, _ Signal) { r.notified = append(r.notified, x) },
		OpenCase:  func(x Response, _ Signal) { r.cases = append(r.cases, x) },
		Record: func(action string, d map[string]string) {
			r.records = append(r.records, action+" "+d["playbook"]+" "+d["mode"])
		},
		Now:         func() time.Time { return r.clock },
		CanLockdown: func() bool { return true },
	}
	return r
}

func (r *rig) see(name, source, subject string) []Response {
	return r.Observe(Signal{Name: name, Source: source, Subject: subject, At: r.clock})
}

func (r *rig) state(t *testing.T) *State {
	t.Helper()
	st, err := Load(r.Root)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func injection() Playbook {
	for _, pb := range Builtins() {
		if pb.Name == "chatbot-injection" {
			return pb
		}
	}
	panic("no chatbot-injection")
}

func TestAPlaybookActsWhenItsTriggerIsMet(t *testing.T) {
	r := newRig(t, injection())
	for i := 0; i < 2; i++ {
		if got := r.see("chatbot-injection", "203.0.113.9", "help"); len(got) != 0 {
			t.Fatalf("acted on signal %d of 3", i+1)
		}
		r.clock = r.clock.Add(time.Minute)
	}
	// A different source's signals are counted apart.
	if got := r.see("chatbot-injection", "203.0.113.10", "help"); len(got) != 0 {
		t.Fatal("counted two sources together")
	}
	got := r.see("chatbot-injection", "203.0.113.9", "help")
	if len(got) != 1 || got[0].Stage != 1 || got[0].Mode != "act" {
		t.Fatalf("third signal: %+v", got)
	}
	if !strings.HasPrefix(got[0].Did[0], "blocked the source on the site for an hour") {
		t.Fatalf("did %q", got[0].Did)
	}
	if _, blocked := r.Guard.Blocked("203.0.113.9", Site, r.clock); !blocked {
		t.Fatal("not blocked on the site")
	}
	if _, blocked := r.Guard.Blocked("203.0.113.9", Admin, r.clock); blocked {
		t.Fatal("blocked on the admin too")
	}
	if _, blocked := r.Guard.Blocked("203.0.113.10", Site, r.clock); blocked {
		t.Fatal("the other source was blocked")
	}
	st := r.state(t)
	p := st.Protections[0]
	if !p.Auto || p.By != "playbook:chatbot-injection" || p.Playbook != "chatbot-injection" || p.Stage != 1 ||
		!p.Until.Equal(r.clock.Add(time.Hour)) || p.Target != "source:"+audit.Pseudonym(testKey, "203.0.113.9") {
		t.Fatalf("protection %+v", p)
	}
	if strings.Contains(fmt.Sprint(st), "203.0.113") {
		t.Fatal("an address was stored")
	}
	if len(st.Responses) != 1 || len(r.records) != 1 || r.records[0] != "shield.responded chatbot-injection act" {
		t.Fatalf("responses %d records %v", len(st.Responses), r.records)
	}
}

func TestSignalsOutsideTheWindowDoNotAddUp(t *testing.T) {
	r := newRig(t, injection())
	for i := 0; i < 6; i++ {
		if got := r.see("chatbot-injection", "203.0.113.9", "help"); len(got) != 0 {
			t.Fatalf("acted on signals %d minutes apart", 6)
		}
		r.clock = r.clock.Add(6 * time.Minute)
	}
}

func TestStagesEscalateWithinADayAndThenStartAgain(t *testing.T) {
	r := newRig(t, injection())
	cross := func() Response {
		t.Helper()
		var got []Response
		for i := 0; i < 3; i++ {
			got = r.see("chatbot-injection", "203.0.113.9", "help")
		}
		if len(got) != 1 {
			t.Fatalf("no crossing: %+v", got)
		}
		r.clock = r.clock.Add(2 * time.Hour)
		return got[0]
	}
	if s := cross(); s.Stage != 1 {
		t.Fatalf("first: stage %d", s.Stage)
	}
	if s := cross(); s.Stage != 2 || !strings.Contains(s.Did[0], "for 4 hours") {
		t.Fatalf("second: stage %d %q", s.Stage, s.Did)
	}
	if s := cross(); s.Stage != 3 || !strings.Contains(s.Did[0], "for 24 hours") {
		t.Fatalf("third: stage %d %q", s.Stage, s.Did)
	}
	if s := cross(); s.Stage != 3 {
		t.Fatalf("fourth stays at the last: stage %d", s.Stage)
	}
	r.clock = r.clock.Add(25 * time.Hour)
	if s := cross(); s.Stage != 1 {
		t.Fatalf("a day later: stage %d", s.Stage)
	}
}

func TestWatchingAndOffDoNothing(t *testing.T) {
	watch := injection()
	watch.Mode = "watch"
	off := injection()
	off.Name, off.Mode = "off-one", "off"
	r := newRig(t, watch, off)
	var got []Response
	for i := 0; i < 3; i++ {
		got = r.see("chatbot-injection", "203.0.113.9", "help")
	}
	if len(got) != 1 || got[0].Mode != "watch" || !strings.HasPrefix(got[0].Did[0], "would have blocked") {
		t.Fatalf("%+v", got)
	}
	st := r.state(t)
	if len(st.Protections) != 0 || len(st.Responses) != 1 {
		t.Fatalf("watching applied %d", len(st.Protections))
	}
	if r.records[0] != "shield.would-respond chatbot-injection watch" {
		t.Fatalf("%v", r.records)
	}
}

func TestTheHourlyLimitStopsAFloodOfSpoofedSignals(t *testing.T) {
	pb := injection()
	pb.On.Count, pb.PerHour = 1, 2
	pb.Stages = []Stage{{Do: []Step{{Action: "block-source", Where: Site, For: Duration(time.Hour)}, {Action: "notify"}}}}
	r := newRig(t, pb)
	for i := 0; i < 2; i++ {
		if got := r.see("chatbot-injection", fmt.Sprintf("203.0.113.%d", i+1), ""); got[0].Mode != "act" {
			t.Fatalf("%d: %+v", i, got)
		}
	}
	got := r.see("chatbot-injection", "203.0.113.3", "")
	if got[0].Mode != "limited" || !strings.Contains(got[0].Did[0], "hourly limit") {
		t.Fatalf("past the limit: %+v", got)
	}
	if _, blocked := r.Guard.Blocked("203.0.113.3", Site, r.clock); blocked {
		t.Fatal("blocked past the limit")
	}
	// Said once; then quiet, and nothing more is written.
	before := len(r.state(t).Responses)
	for i := 0; i < 5; i++ {
		if got := r.see("chatbot-injection", fmt.Sprintf("203.0.113.%d", 10+i), ""); len(got) != 0 {
			t.Fatalf("still responding past the limit: %+v", got)
		}
	}
	if after := len(r.state(t).Responses); after != before || len(r.records) != 3 {
		t.Fatalf("wrote %d more responses, %d records", after-before, len(r.records))
	}
	// The two the playbook asked for, and the limit itself: a playbook
	// that has gone quiet is something a person must know.
	if len(r.notified) != 3 || r.notified[2].Mode != "limited" {
		t.Fatalf("notified %d times: %+v", len(r.notified), r.notified)
	}
	r.clock = r.clock.Add(61 * time.Minute)
	if got := r.see("chatbot-injection", "203.0.113.4", ""); got[0].Mode != "act" {
		t.Fatal("the limit did not reset after an hour")
	}
}

func TestTheDefaultHourlyLimit(t *testing.T) {
	pb := injection()
	pb.On.Count = 1
	r := newRig(t, pb)
	for i := 0; i < DefaultPerHour; i++ {
		r.see("chatbot-injection", fmt.Sprintf("203.0.%d.%d", i/200, i%200+1), "")
	}
	if got := r.see("chatbot-injection", "198.51.100.1", ""); got[0].Mode != "limited" {
		t.Fatalf("%+v", got)
	}
}

func TestProviderNetworkAndFeatureSteps(t *testing.T) {
	h := Duration(time.Hour)
	spread := Playbook{Name: "spread", Title: "Spread", Mode: "act",
		On: Trigger{Signal: "signin-failures", Per: "provider", Count: 2, Within: h},
		Stages: []Stage{{Do: []Step{{Action: "block-provider", Where: Admin, For: h},
			{Action: "block-network", Where: Admin, For: h}, {Action: "block-source", Where: Admin, For: h}}}}}
	flood := Playbook{Name: "flood", Title: "Flood", Mode: "act",
		On:     Trigger{Signal: "chatbot-injection", Per: "subject", Count: 2, Within: h},
		Stages: []Stage{{Do: []Step{{Action: "shield-feature", Feature: "subject", Level: Limited, For: h}}}}}
	forms := Playbook{Name: "forms", Title: "Forms", Mode: "act",
		On:     Trigger{Signal: "form-spam", Per: "subject", Count: 1, Within: h},
		Stages: []Stage{{Do: []Step{{Action: "shield-feature", Feature: "subject", Level: Off, For: h}}}}}
	steered := Playbook{Name: "steered", Title: "Steered", Mode: "act",
		On:     Trigger{Signal: "agent-hijacked", Per: "subject", Count: 1, Within: h},
		Stages: []Stage{{Do: []Step{{Action: "pause-agent", For: h}, {Action: "notify"}, {Action: "open-case"}}}}}
	r := newRig(t, spread, flood, forms, steered)

	r.see("signin-failures", "192.0.2.10", "")
	got := r.see("signin-failures", "192.0.2.77", "")
	if len(got) != 1 {
		t.Fatalf("two sources at one provider did not add up: %+v", got)
	}
	for _, a := range []string{"192.0.2.200", "192.0.2.77"} {
		if _, blocked := r.Guard.Blocked(a, Admin, r.clock); !blocked {
			t.Errorf("%s not blocked", a)
		}
	}
	st := r.state(t)
	targets := map[string]bool{}
	for _, p := range st.Protections {
		targets[p.Target] = true
	}
	if !targets["asn:64500"] || !targets["net:192.0.2.0/24"] || !targets["source:"+audit.Pseudonym(testKey, "192.0.2.77")] {
		t.Fatalf("targets %v", targets)
	}
	// Sources at an unknown provider are not counted together.
	r.see("signin-failures", "203.0.113.1", "")
	if got := r.see("signin-failures", "203.0.113.2", ""); len(got) != 0 {
		t.Fatal("an unknown provider was counted")
	}

	r.see("chatbot-injection", "198.51.100.1", "help")
	r.see("chatbot-injection", "198.51.100.2", "help")
	if p, on := r.Guard.Feature("chatbot:help", r.clock); !on || p.Level != Limited {
		t.Fatal("the chatbot was not limited")
	}
	if _, on := r.Guard.Feature("chatbot:sales", r.clock); on {
		t.Fatal("another chatbot was limited")
	}
	r.see("form-spam", "198.51.100.1", "contact")
	if _, on := r.Guard.Feature("form:contact", r.clock); !on {
		t.Fatal("the form was not turned off")
	}
	r.see("agent-hijacked", "", "triage")
	if _, on := r.Guard.AgentPaused("triage", r.clock); !on {
		t.Fatal("the agent was not paused")
	}
	if len(r.notified) != 1 || len(r.cases) != 1 || r.cases[0].Playbook != "steered" {
		t.Fatalf("notified %d cases %d", len(r.notified), len(r.cases))
	}
}

func TestIPv6NetworksAreTheirSlash48(t *testing.T) {
	h := Duration(time.Hour)
	pb := Playbook{Name: "v6", Title: "v6", Mode: "act",
		On:     Trigger{Signal: "admin-hunt", Per: "source", Count: 1, Within: h},
		Stages: []Stage{{Do: []Step{{Action: "block-network", Where: Site, For: h}}}}}
	r := newRig(t, pb)
	r.see("admin-hunt", "2001:db8:1:2::9", "")
	if _, blocked := r.Guard.Blocked("2001:db8:1:ffff::1", Site, r.clock); !blocked {
		t.Fatal("the /48 was not blocked")
	}
	if _, blocked := r.Guard.Blocked("2001:db8:2::1", Site, r.clock); blocked {
		t.Fatal("beyond the /48 was blocked")
	}
}

func TestStepsThatCannotBeDoneSaySo(t *testing.T) {
	h := Duration(time.Hour)
	pb := Playbook{Name: "x", Title: "x", Mode: "act",
		On: Trigger{Signal: "decoy", Per: "any", Count: 1, Within: h},
		Stages: []Stage{{Do: []Step{{Action: "block-source", Where: All, For: h},
			{Action: "block-network", Where: All, For: h}, {Action: "block-provider", Where: All, For: h},
			{Action: "lockdown", For: h}}}}}
	r := newRig(t, pb)
	got := r.see("decoy", "", "")
	if len(got) != 1 {
		t.Fatal("no response")
	}
	for i, want := range []string{"could not block the source", "could not block the network", "could not block the provider", "locked the admin"} {
		if !strings.HasPrefix(got[0].Did[i], want) {
			t.Errorf("step %d: %q", i, got[0].Did[i])
		}
	}
}

func TestThisMachineAndTrustedNetworksAreNotBlockedByPlaybooks(t *testing.T) {
	var decoy, lock Playbook
	for _, pb := range Builtins() {
		switch pb.Name {
		case "decoy-touched":
			decoy = pb
		case "decoy-lockdown":
			lock = pb
		}
	}
	lock.Mode = "act"
	r := newRig(t, decoy, lock)
	Trust(r.Root, "198.51.100.0/24", true, t0)
	r.Guard.Refresh()
	for _, a := range []string{"127.0.0.1", "10.1.2.3", "100.64.0.9", "fd00::1", "198.51.100.7"} {
		got := r.see("decoy", a, "")
		if len(got) != 2 || !strings.HasPrefix(got[0].Did[0], "did not block") {
			t.Fatalf("%s: %+v", a, got)
		}
		// Somebody inside with a stolen token still locks the admin.
		if !strings.HasPrefix(got[1].Did[0], "locked the admin") {
			t.Fatalf("%s: %q", a, got[1].Did)
		}
		r.clock = r.clock.Add(Cooldown)
	}
	for _, p := range r.state(t).Protections {
		if p.Kind == Block {
			t.Fatalf("blocked %s", p.Target)
		}
	}
}

func TestEngineMemoryIsBoundedAndForgetsTheOldestFirst(t *testing.T) {
	pb := injection()
	r := newRig(t, pb)
	r.see("chatbot-injection", "203.0.113.9", "help") // one real key, touched now
	r.Engine.mu.Lock()
	for i := 0; i <= maxKeys; i++ {
		k := fmt.Sprint("old|", i)
		r.Engine.counts[k] = []hit{{at: t0.Add(-48 * time.Hour)}}
		r.Engine.touch[k] = t0.Add(-48*time.Hour + time.Duration(i))
	}
	r.Engine.mu.Unlock()
	r.see("chatbot-injection", "203.0.113.10", "help")
	r.Engine.mu.Lock()
	defer r.Engine.mu.Unlock()
	if n := len(r.Engine.touch); n > maxKeys*9/10+2 {
		t.Fatalf("not swept: %d", n)
	}
	// What was touched lately survives; a flood of other keys does not
	// wipe it.
	if _, ok := r.Engine.counts["chatbot-injection|"+audit.Pseudonym(testKey, "203.0.113.9")]; !ok {
		t.Fatal("a live key was forgotten for the flood")
	}
	if _, ok := r.Engine.touch["old|0"]; ok {
		t.Fatal("the oldest key was kept")
	}
}

func TestWatchingIsLimitedToo(t *testing.T) {
	pb := injection()
	pb.On.Count, pb.Mode, pb.PerHour = 1, "watch", 3
	r := newRig(t, pb)
	for i := 0; i < 10; i++ {
		r.see("chatbot-injection", fmt.Sprintf("10.0.%d.1", i), "")
	}
	st := r.state(t)
	if len(st.Responses) != 4 || st.Responses[3].Mode != "limited" {
		t.Fatalf("kept %d: %+v", len(st.Responses), st.Responses)
	}
}

func TestResponsesAreBounded(t *testing.T) {
	pb := injection()
	pb.On.Count = 1
	r := newRig(t, pb)
	Change(r.Root, t0, func(st *State) error {
		st.Responses = make([]Response, maxKept)
		return nil
	})
	r.see("chatbot-injection", "203.0.113.9", "")
	st := r.state(t)
	if len(st.Responses) != maxKept || st.Responses[maxKept-1].Playbook != "chatbot-injection" {
		t.Fatalf("kept %d", len(st.Responses))
	}
}

func TestDryRunAppliesAndWritesNothing(t *testing.T) {
	pb := injection()
	var signals []Signal
	for i := 0; i < 7; i++ {
		// Out of order, as two logs merged might be.
		signals = append(signals, Signal{Name: "chatbot-injection", Handle: handle, At: t0.Add(time.Duration(6-i) * time.Minute)})
	}
	signals = append(signals, Signal{Name: "admin-hunt", Handle: handle, At: t0})
	// After 2h, when the block it would have made has ended, the source
	// comes back.
	for i := 0; i < 3; i++ {
		signals = append(signals, Signal{Name: "chatbot-injection", Handle: handle, At: t0.Add(2*time.Hour + time.Duration(i)*time.Minute)})
	}
	got := DryRun(pb, signals)
	// The four after the first crossing came while the source would have
	// been blocked, so could not have arrived.
	if len(got) != 2 || got[0].Stage != 1 || got[1].Stage != 2 || got[0].Key != handle {
		t.Fatalf("%+v", got)
	}
	if !got[0].At.Equal(t0.Add(2*time.Minute)) || !strings.HasPrefix(got[0].Did[0], "would have blocked") {
		t.Fatalf("%+v", got[0])
	}
	if !signals[0].At.Equal(t0.Add(6 * time.Minute)) {
		t.Fatal("the caller's signals were reordered")
	}
}

func TestObserveWithoutPlaybooks(t *testing.T) {
	var e *Engine
	if e.Observe(Signal{Name: "decoy"}) != nil {
		t.Fatal("a nil engine responded")
	}
	if (&Engine{}).Observe(Signal{Name: "decoy"}) != nil {
		t.Fatal("an engine with no playbooks responded")
	}
}
