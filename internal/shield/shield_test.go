// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

const handle = "p_0123456789abcdef0123456789abcdef"

func ok(kind, target string) Protection {
	p := Protection{Kind: kind, Target: target, Reason: "testing", By: "dana", Until: t0.Add(time.Hour)}
	switch kind {
	case Block:
		p.Where = All
	case Feature:
		p.Level = Off
	}
	return p
}

func TestValidateRefusesWhatTheShieldMustNotDo(t *testing.T) {
	with := func(p Protection, f func(*Protection)) Protection { f(&p); return p }
	good := []Protection{
		ok(Block, "source:"+handle),
		ok(Block, "net:203.0.113.0/24"),
		ok(Block, "net:198.51.0.0/16"),
		ok(Block, "net:2001:db8::/48"),
		ok(Block, "asn:13335"),
		ok(Feature, "chatbots"),
		ok(Feature, "chatbot:help"),
		with(ok(Feature, "chatbot:help"), func(p *Protection) { p.Level = Limited }),
		with(ok(Feature, "chatbots"), func(p *Protection) { p.Level = Limited }),
		ok(Feature, "forms"),
		ok(Feature, "form:contact"),
		ok(Feature, "signup"),
		ok(Lockdown, ""),
		ok(Freeze, ""),
		ok(Agent, "triage"),
		with(ok(Freeze, ""), func(p *Protection) { p.Until = t0.Add(MaxManual) }),
		with(ok(Freeze, ""), func(p *Protection) { p.Auto, p.Until = true, t0.Add(MaxAuto) }),
	}
	for _, p := range good {
		if err := p.Validate(t0); err != nil {
			t.Errorf("%s %s refused: %v", p.Kind, p.Target, err)
		}
	}
	bad := map[string]Protection{
		"ended already":            with(ok(Freeze, ""), func(p *Protection) { p.Until = t0 }),
		"automatic beyond a day":   with(ok(Freeze, ""), func(p *Protection) { p.Auto, p.Until = true, t0.Add(MaxAuto+2*time.Minute) }),
		"by a person beyond seven": with(ok(Freeze, ""), func(p *Protection) { p.Until = t0.Add(MaxManual + 2*time.Minute) }),
		"no reason":                with(ok(Freeze, ""), func(p *Protection) { p.Reason = "  " }),
		"long reason":              with(ok(Freeze, ""), func(p *Protection) { p.Reason = strings.Repeat("x", 301) }),
		"nobody applied it":        with(ok(Freeze, ""), func(p *Protection) { p.By = "" }),
		"block nowhere":            with(ok(Block, "asn:1"), func(p *Protection) { p.Where = "" }),
		"block somewhere else":     with(ok(Block, "asn:1"), func(p *Protection) { p.Where = "studio" }),
		"raw address as source":    ok(Block, "source:203.0.113.9"),
		"short handle":             ok(Block, "source:p_0123"),
		"upper-case handle":        ok(Block, "source:p_0123456789ABCDEF0123456789ABCDEF"),
		"not a network":            ok(Block, "net:example.com"),
		"bare address":             ok(Block, "net:203.0.113.9"),
		"wider than /16":           ok(Block, "net:10.0.0.0/15"),
		"wider than /48":           ok(Block, "net:2001:db8::/47"),
		"everything":               ok(Block, "net:0.0.0.0/0"),
		"this machine":             ok(Block, "net:127.0.0.0/16"),
		"this machine v6":          ok(Block, "net:::1/128"),
		"provider zero":            ok(Block, "asn:0"),
		"provider word":            ok(Block, "asn:cloud"),
		"provider too big":         ok(Block, "asn:4294967296"),
		"block a person":           ok(Block, "user:dana"),
		"unknown feature":          ok(Feature, "signin"),
		"admin screens":            ok(Feature, "security"),
		"chatbot unnamed":          ok(Feature, "chatbot"),
		"chatbots named":           ok(Feature, "chatbots:help"),
		"chatbot bad name":         ok(Feature, "chatbot:../x"),
		"forms limited":            with(ok(Feature, "forms"), func(p *Protection) { p.Level = Limited }),
		"feature no level":         with(ok(Feature, "forms"), func(p *Protection) { p.Level = "" }),
		"lockdown of something":    ok(Lockdown, "admin"),
		"freeze of something":      ok(Freeze, "home"),
		"agent unnamed":            ok(Agent, ""),
		"agent path":               ok(Agent, "../x"),
		"unknown kind":             ok("delete", ""),
	}
	for name, p := range bad {
		if err := p.Validate(t0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestApplyLengthensRatherThanDoubles(t *testing.T) {
	root := t.TempDir()
	p := ok(Block, "source:"+handle)
	first, fresh, err := Apply(root, p, t0)
	if err != nil || !fresh || !strings.HasPrefix(first.ID, "sh-") || !first.At.Equal(t0) {
		t.Fatalf("first apply: %+v %v %v", first, fresh, err)
	}
	p.Until = t0.Add(3 * time.Hour)
	again, fresh, err := Apply(root, p, t0.Add(time.Minute))
	if err != nil || fresh || again.ID != first.ID || !again.Until.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("second apply should lengthen the first: %+v %v %v", again, fresh, err)
	}
	// Shorter does not shorten.
	p.Until = t0.Add(2 * time.Hour)
	again, _, _ = Apply(root, p, t0.Add(2*time.Minute))
	if !again.Until.Equal(t0.Add(3 * time.Hour)) {
		t.Fatalf("a shorter apply shortened it: %v", again.Until)
	}
	// The same target on a different surface is a different protection.
	p.Where = Site
	if _, fresh, _ := Apply(root, p, t0); !fresh {
		t.Fatal("a site block was merged into an all block")
	}
	st, _ := Load(root)
	if len(st.Protections) != 2 {
		t.Fatalf("want 2 protections, have %d", len(st.Protections))
	}
	if _, _, err := Apply(root, ok(Block, "net:10.0.0.0/8"), t0); err == nil {
		t.Fatal("an invalid protection was applied")
	}
}

func TestTrustedNetworksAreNeverBlocked(t *testing.T) {
	root := t.TempDir()
	if err := Trust(root, "198.51.100.0/24", true, t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Apply(root, ok(Block, "net:198.51.0.0/16"), t0); err == nil {
		t.Fatal("a network overlapping a trusted one was blocked")
	}
	if _, _, err := Apply(root, ok(Block, "net:198.51.101.0/24"), t0); err != nil {
		t.Fatalf("a neighbouring network was refused: %v", err)
	}
	if err := Trust(root, "198.51.100.0/24", false, t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Apply(root, ok(Block, "net:198.51.0.0/16"), t0); err != nil {
		t.Fatalf("once untrusted, it can be blocked: %v", err)
	}
	if err := Trust(root, "nonsense", true, t0); err == nil {
		t.Fatal("a non-network was trusted")
	}
}

func TestEndedProtectionsMoveToTheHistory(t *testing.T) {
	root := t.TempDir()
	a, _, _ := Apply(root, ok(Freeze, ""), t0)
	b, _, _ := Apply(root, ok(Lockdown, ""), t0)
	lifted, err := Lift(root, b.ID, "sam", t0.Add(time.Minute))
	if err != nil || len(lifted) != 1 || lifted[0].LiftedBy != "sam" {
		t.Fatalf("lift: %+v %v", lifted, err)
	}
	g := &Guard{Root: root}
	if _, on := g.Lockdown(t0.Add(time.Minute)); on {
		t.Fatal("a lifted lockdown is in force")
	}
	if _, on := g.Frozen(t0.Add(time.Minute)); !on {
		t.Fatal("lifting one lifted another")
	}
	if _, err := Lift(root, "sh-nothing", "sam", t0); err == nil {
		t.Fatal("lifting nothing succeeded")
	}
	if p, frozen := Frozen(root, t0.Add(time.Minute)); !frozen || p.ID != a.ID {
		t.Fatal("the freeze is not in force")
	}
	if _, frozen := Frozen(root, t0.Add(time.Hour)); frozen {
		t.Fatal("the freeze outlived its end")
	}
	// The next change moves both out.
	if err := Change(root, t0.Add(2*time.Hour), func(*State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	st, _ := Load(root)
	if len(st.Protections) != 0 || len(st.Ended) != 2 {
		t.Fatalf("in force %d, ended %d", len(st.Protections), len(st.Ended))
	}
	// Lift all, with nothing in force, is not an error.
	if _, err := Lift(root, "all", "sam", t0); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryAndActiveAreBounded(t *testing.T) {
	root := t.TempDir()
	st := &State{}
	for i := 0; i < MaxActive; i++ {
		p := ok(Agent, "a"+strings.Repeat("x", i%50))
		p.ID, p.At = newID(), t0
		st.Protections = append(st.Protections, p)
	}
	for i := 0; i < maxKept+20; i++ {
		st.Ended = append(st.Ended, ok(Freeze, ""))
	}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(Path(root), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Apply(root, ok(Freeze, ""), t0); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("applied past the limit: %v", err)
	}
	// Lengthening one already in force is not adding one.
	if _, _, err := Apply(root, ok(Agent, "a"), t0); err != nil {
		t.Fatalf("lengthening at the limit: %v", err)
	}
	got, _ := Load(root)
	if len(got.Ended) != maxKept {
		t.Fatalf("history kept %d", len(got.Ended))
	}
}

func TestAnUnreadableShieldIsAnError(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(Path(root), []byte("{"), 0o600)
	if _, err := Load(root); err == nil {
		t.Fatal("a broken file loaded")
	}
	if _, _, err := Apply(root, ok(Freeze, ""), t0); err == nil {
		t.Fatal("a broken file was overwritten")
	}
	// What is contained stays contained: an unreadable record may be
	// holding a freeze or a paused agent.
	if p, frozen := Frozen(root, t0); !frozen || p.Reason != Unreadable {
		t.Fatalf("a broken file let publishing through: %+v", p)
	}
	if p, paused := Find(root, Agent, "triage", t0); !paused || p.Reason != Unreadable {
		t.Fatalf("a broken file let a paused agent run: %+v", p)
	}
}

func TestTheFileIsPrivate(t *testing.T) {
	root := t.TempDir()
	Apply(root, ok(Freeze, ""), t0)
	fi, err := os.Stat(Path(root))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi.Mode(), err)
	}
	// The lock is held by a descriptor, not by the file existing: what is
	// left is empty and private.
	if fi, err := os.Stat(Path(root) + ".lock"); err != nil || fi.Size() != 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the lock file: %v %v", fi, err)
	}
}
