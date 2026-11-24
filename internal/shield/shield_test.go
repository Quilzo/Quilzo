// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
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
	if _, err := Lift(root, "sh-nothing", "sam", t0); !errors.Is(err, ErrNoProtection) {
		t.Fatalf("lifting nothing was not refused as nothing there: %v", err)
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
	if err := writeShield(root, b, 0o600); err != nil {
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
	writeShield(root, []byte("{"), 0o600)
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

// writeShield writes the shield's file as it lies, for a test of what is
// read back: in its directory, which Change makes and a test must too.
func writeShield(root string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(Path(root)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(Path(root), b, mode)
}

// A network is the network it names, however it was written.
//
// A request's address is compared as IPv4 whichever way it arrived, and a
// range is compared only within its own family. So a block or a slowing of
// ::ffff:203.0.113.0/120, which is 203.0.113.0/24 as a dual-stack listener
// and a copied log line write it, was taken, listed as in force and
// refused nobody; ::ffff:127.0.0.1/128 passed the rule that this machine is
// never blocked; and a network trusted in that spelling spared nobody.
func TestANetworkWrittenAsIPv4InsideIPv6IsTheIPv4Network(t *testing.T) {
	g := guard(t)
	block := ok(Block, "net:::ffff:203.0.113.0/120")
	block.Where = Site
	if got := put(t, g, block); got.Target != "net:203.0.113.0/24" {
		t.Fatalf("kept as %q, which no request's address is compared with", got.Target)
	}
	for _, a := range []string{"203.0.113.9", "::ffff:203.0.113.9", "[::ffff:203.0.113.200]"} {
		if _, blocked := g.Blocked(a, Site, t0); !blocked {
			t.Errorf("%s is in the blocked network and was let through", a)
		}
	}
	if _, blocked := g.Blocked("203.0.114.9", Site, t0); blocked {
		t.Error("the next network was blocked too")
	}
	slow := ok(Slow, "net:::ffff:198.51.100.64/122")
	slow.Where = Site
	if got := put(t, g, slow); got.Target != "net:198.51.100.64/26" {
		t.Fatalf("a slowing was kept as %q", got.Target)
	}
	if _, slowed := g.Slowed("198.51.100.70", Site, t0); !slowed {
		t.Error("an address in the slowed network was not slowed")
	}
	// One an older version kept as it was typed is in force now as well:
	// it was listed as in force all along.
	if err := Change(g.Root, t0, func(st *State) error {
		st.Protections = append(st.Protections, Protection{ID: "sh-kept", Kind: Block, Where: All,
			Target: "net:::ffff:192.0.2.0/120", Reason: "kept by an older version", By: "dana", At: t0, Until: t0.Add(time.Hour)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	if _, blocked := g.Blocked("192.0.2.7", Admin, t0); !blocked {
		t.Error("a block kept in the old spelling still refuses nobody")
	}
	// The rules about what may be blocked read the network it names.
	for n, want := range map[string]string{
		"::ffff:127.0.0.1/128":  "this machine",
		"::ffff:127.0.0.0/112":  "this machine",
		"::ffff:10.0.0.0/104":   "wider than /16",
		"::ffff:0.0.0.0/96":     "wider than /16",
		"::ffff:0.0.0.0/90":     "every IPv4 address",
		"::ffff:203.0.113.0/64": "this machine",
	} {
		if err := ok(Block, "net:"+n).Validate(t0); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want it refused as %s", n, err, want)
		}
	}
	// And so does the list of networks never blocked.
	if err := Trust(g.Root, "::ffff:192.0.2.0/120", true, t0); err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	if st, _ := Load(g.Root); len(st.Trusted) != 1 || st.Trusted[0] != "192.0.2.0/24" {
		t.Fatalf("trusted %v, want 192.0.2.0/24", st.Trusted)
	}
	if _, blocked := g.Blocked("192.0.2.7", Admin, t0); blocked {
		t.Error("an address in a trusted network was blocked")
	}
	if _, _, err := Apply(g.Root, ok(Block, "net:::ffff:192.0.2.128/121"), t0); err == nil || !strings.Contains(err.Error(), "trusted") {
		t.Errorf("a block inside a trusted network was taken: %v", err)
	}
}

// Removing a trusted network removes that network, and says so when there
// was none to remove.
//
// The list was compared as text. A network added from an address inside
// it, 198.51.100.7/24, was kept in that spelling, so removing
// 198.51.100.0/24 left it trusted; and removing one that was never there
// said the same as removing one that was. Either way the answer was "no
// longer trusted", for a network the shield went on never blocking.
func TestRemovingATrustedNetworkRemovesItOrSaysThereWasNone(t *testing.T) {
	root := t.TempDir()
	trusted := func() []string {
		t.Helper()
		st, err := Load(root)
		if err != nil {
			t.Fatal(err)
		}
		return st.Trusted
	}
	if err := Trust(root, "198.51.100.7/24", true, t0); err != nil {
		t.Fatal(err)
	}
	if got := trusted(); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("kept as %v, want the network by its first address", got)
	}
	// Twice is once.
	if err := Trust(root, "198.51.100.0/24", true, t0); err != nil || len(trusted()) != 1 {
		t.Fatalf("added twice: %v %v", err, trusted())
	}
	if err := Trust(root, "203.0.113.0/24", false, t0); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("removing a network that was never trusted: %v", err)
	}
	if err := Trust(root, "198.51.100.0/25", false, t0); !errors.Is(err, ErrNotTrusted) || len(trusted()) != 1 {
		t.Fatalf("removing half of a trusted network: %v, left %v", err, trusted())
	}
	if err := Trust(root, "198.51.100.200/24", false, t0); err != nil || len(trusted()) != 0 {
		t.Fatalf("the same network in another spelling was not removed: %v, left %v", err, trusted())
	}
	if err := Trust(root, "198.51.100.0/24", false, t0); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("removed twice: %v", err)
	}
	// One an older version kept as it was typed is removed by its network.
	if err := Change(root, t0, func(st *State) error {
		st.Trusted = []string{"2001:db8:1::9/48", "198.51.100.7/24"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Trust(root, "198.51.100.0/24", false, t0); err != nil {
		t.Fatal(err)
	}
	if err := Trust(root, "2001:db8:1::/48", false, t0); err != nil || len(trusted()) != 0 {
		t.Fatalf("an older spelling was not removed: %v, left %v", err, trusted())
	}
}

// Nobody declares most of the internet trusted.
//
// A trusted network is never blocked or slowed, by a playbook or a person.
// `shield trust add 0.0.0.0/0` was taken like an office's /24, from one
// administrator and at once, and from then on the shield blocked nobody:
// every playbook answered "did not block or slow: the source is this
// machine or on a trusted network". Stopping the shield acting is a hold,
// which says why, is told to the security contact and takes a second
// administrator to undo.
func TestMostOfTheInternetIsNotATrustedNetwork(t *testing.T) {
	g := guard(t)
	put(t, g, ok(Block, "source:"+audit.Pseudonym(testKey, "203.0.113.9")))
	for _, n := range []string{"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "192.0.0.0/7", "2000::/3", "2000::/7",
		"::ffff:0.0.0.0/96", "::ffff:128.0.0.0/97", "::/8", "::ffff:0.0.0.0/90"} {
		if err := Trust(g.Root, n, true, t0); err == nil {
			t.Errorf("%s was declared trusted", n)
		}
	}
	g.Refresh()
	if st, _ := Load(g.Root); len(st.Trusted) != 0 {
		t.Fatalf("trusted %v", st.Trusted)
	}
	if _, blocked := g.Blocked("203.0.113.9", Site, t0); !blocked {
		t.Fatal("a blocked source was let through")
	}
	// What an organisation does hold is still declared: the private ranges
	// whole, and a provider's allocation.
	for _, n := range []string{"10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10", "fd00::/8", "2001:db8::/32", "198.51.100.9/32"} {
		if err := Trust(g.Root, n, true, t0); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	// One an older version took can still be taken off the list.
	if err := Change(g.Root, t0, func(st *State) error {
		st.Trusted = []string{"0.0.0.0/0", "::/0"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"0.0.0.0/0", "::/0"} {
		if err := Trust(g.Root, n, false, t0); err != nil {
			t.Errorf("removing %s: %v", n, err)
		}
	}
}

// The posture check is told which trusted networks are wide ones: wider
// than the shield blocks as one network, or, in a record from before the
// limit, most of the internet. An office is neither.
func TestTheWideTrustedNetworksAreNamed(t *testing.T) {
	st := &State{Trusted: []string{"198.51.100.0/24", "10.0.0.0/8", "2001:db8::/32", "fd00:1:2::/48",
		"::ffff:10.0.0.0/104", "0.0.0.0/0", "::/0", "not a network"}}
	broad, most := st.TrustedWidely()
	if got := strings.Join(broad, " "); got != "10.0.0.0/8 2001:db8::/32 ::ffff:10.0.0.0/104" {
		t.Errorf("wide: %s", got)
	}
	if got := strings.Join(most, " "); got != "0.0.0.0/0 ::/0" {
		t.Errorf("most of the internet: %s", got)
	}
}
