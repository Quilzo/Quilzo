// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func guard(t *testing.T) *Guard {
	t.Helper()
	return &Guard{Root: t.TempDir(), Key: testKey}
}

func put(t *testing.T, g *Guard, p Protection) Protection {
	t.Helper()
	out, _, err := Apply(g.Root, p, t0)
	if err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	return out
}

func TestABlockedSourceIsKnownByItsHandle(t *testing.T) {
	g := guard(t)
	h := audit.Pseudonym(testKey, "203.0.113.9")
	p := ok(Block, "source:"+h)
	p.Where = Admin
	put(t, g, p)
	if _, blocked := g.Blocked("203.0.113.9", Admin, t0); !blocked {
		t.Fatal("the source was not blocked")
	}
	if _, blocked := g.Blocked("203.0.113.10", Admin, t0); blocked {
		t.Fatal("its neighbour was blocked")
	}
	if _, blocked := g.Blocked("203.0.113.9", Site, t0); blocked {
		t.Fatal("an admin block reached the site")
	}
	if _, blocked := g.Blocked("203.0.113.9", Admin, t0.Add(time.Hour)); blocked {
		t.Fatal("the block outlived its end")
	}
	// The same address written as IPv4 in IPv6 is the same source.
	if _, blocked := g.Blocked("[::ffff:203.0.113.9]", Admin, t0); !blocked {
		t.Fatal("a mapped address escaped")
	}
	// A guard without the key cannot know handles and blocks none by them.
	if _, blocked := (&Guard{Root: g.Root}).Blocked("203.0.113.9", Admin, t0); blocked {
		t.Fatal("blocked without a key")
	}
}

func TestBlocksByNetworkAndProvider(t *testing.T) {
	g := guard(t)
	g.ASN = func(a netip.Addr) (uint32, bool) {
		if strings.HasPrefix(a.String(), "192.0.2.") {
			return 64500, true
		}
		return 0, false
	}
	n := ok(Block, "net:198.51.100.0/24")
	n.Where = Site
	put(t, g, n)
	put(t, g, ok(Block, "asn:64500"))
	put(t, g, ok(Block, "net:2001:db8:1::/48"))
	cases := map[string]bool{
		"198.51.100.200|site":   true,
		"198.51.100.200|admin":  false,
		"198.51.101.1|site":     false,
		"192.0.2.7|admin":       true,
		"192.0.2.7|site":        true,
		"203.0.113.1|site":      false,
		"2001:db8:1:ff::1|site": true,
		"2001:db8:2::1|site":    false,
		"not-an-address|site":   false,
	}
	for c, want := range cases {
		addr, where, _ := strings.Cut(c, "|")
		if _, got := g.Blocked(addr, where, t0); got != want {
			t.Errorf("%s: blocked %v, want %v", c, got, want)
		}
	}
	// Without the provider database a provider block blocks nobody.
	g.ASN = nil
	g.Refresh()
	if _, got := g.Blocked("192.0.2.7", Admin, t0); got {
		t.Fatal("provider block without a database")
	}
}

func TestThisMachineAndTrustedNetworksAreNeverBlocked(t *testing.T) {
	g := guard(t)
	put(t, g, ok(Block, "source:"+audit.Pseudonym(testKey, "127.0.0.1")))
	put(t, g, ok(Block, "source:"+audit.Pseudonym(testKey, "::1")))
	put(t, g, ok(Block, "source:"+audit.Pseudonym(testKey, "198.51.100.4")))
	for _, a := range []string{"127.0.0.1", "::1", "[::1]"} {
		if _, blocked := g.Blocked(a, Admin, t0); blocked {
			t.Fatalf("%s was blocked", a)
		}
	}
	if _, blocked := g.Blocked("198.51.100.4", Admin, t0); !blocked {
		t.Fatal("not blocked before it was trusted")
	}
	Trust(g.Root, "198.51.100.0/24", true, t0)
	g.Refresh()
	if _, blocked := g.Blocked("198.51.100.4", Admin, t0); blocked {
		t.Fatal("a trusted address was blocked")
	}
}

func TestFeatureShieldsByNameAndForEveryOne(t *testing.T) {
	g := guard(t)
	lim := ok(Feature, "chatbots")
	lim.Level = Limited
	put(t, g, lim)
	if p, on := g.Feature("chatbot:help", t0); !on || p.Level != Limited {
		t.Fatalf("every chatbot did not cover one: %+v %v", p, on)
	}
	if _, on := g.Feature("form:contact", t0); on {
		t.Fatal("a chatbot shield reached a form")
	}
	// Off outranks limited, whichever came first.
	put(t, g, ok(Feature, "chatbot:help"))
	if p, _ := g.Feature("chatbot:help", t0); p.Level != Off {
		t.Fatalf("level %q", p.Level)
	}
	if p, _ := g.Feature("chatbot:other", t0); p.Level != Limited {
		t.Fatalf("another chatbot: level %q", p.Level)
	}
	put(t, g, ok(Feature, "forms"))
	if _, on := g.Feature("form:contact", t0); !on {
		t.Fatal("every form did not cover one")
	}
	if _, on := g.Feature("signup", t0); on {
		t.Fatal("signup is shielded")
	}
	put(t, g, ok(Feature, "signup"))
	if _, on := g.Feature("signup", t0); !on {
		t.Fatal("signup is not shielded")
	}
}

func TestLockdownFreezeAndPause(t *testing.T) {
	g := guard(t)
	for _, f := range []func(time.Time) (Protection, bool){g.Lockdown, g.Frozen} {
		if _, on := f(t0); on {
			t.Fatal("on before anything was applied")
		}
	}
	put(t, g, ok(Lockdown, ""))
	put(t, g, ok(Freeze, ""))
	put(t, g, ok(Agent, "triage"))
	if _, on := g.Lockdown(t0); !on {
		t.Fatal("no lockdown")
	}
	if _, on := g.Frozen(t0); !on {
		t.Fatal("no freeze")
	}
	if _, on := g.AgentPaused("triage", t0); !on {
		t.Fatal("not paused")
	}
	if _, on := g.AgentPaused("writer", t0); on {
		t.Fatal("another agent paused")
	}
	if n := len(g.Active(t0)); n != 3 {
		t.Fatalf("%d active", n)
	}
}

func TestTheGuardSeesChangesFromOtherProcesses(t *testing.T) {
	g := guard(t)
	if _, on := g.Frozen(t0); on {
		t.Fatal("frozen")
	}
	// Another process applies a freeze; this one has read the file within
	// the second, so it does not see it until the second has passed.
	Apply(g.Root, ok(Freeze, ""), t0)
	g.mu.Lock()
	g.checked = time.Now()
	g.mu.Unlock()
	if _, on := g.Frozen(time.Now()); on {
		t.Fatal("read the file again within the second")
	}
	g.Refresh()
	if _, on := g.Frozen(t0); !on {
		t.Fatal("did not see the freeze after a refresh")
	}
}

func TestTwoChangesWithinOneClockTickAreBothSeen(t *testing.T) {
	g := guard(t)
	Apply(g.Root, ok(Freeze, ""), t0)
	if _, on := g.Frozen(t0); !on {
		t.Fatal("not frozen")
	}
	before, _ := os.Stat(Path(g.Root))
	// Another process changes it within the same tick of the clock, so the
	// file's time is unchanged; a second later this one looks again.
	Apply(g.Root, ok(Lockdown, ""), t0)
	os.Chtimes(Path(g.Root), before.ModTime(), before.ModTime())
	g.mu.Lock()
	g.checked = time.Time{}
	g.mu.Unlock()
	if _, on := g.Lockdown(t0); !on {
		t.Fatal("the second change was missed")
	}
}

func TestAnUnreadableFileKeepsWhatWasLastRead(t *testing.T) {
	g := guard(t)
	put(t, g, ok(Freeze, ""))
	if _, on := g.Frozen(t0); !on {
		t.Fatal("not frozen")
	}
	os.WriteFile(Path(g.Root), []byte("{broken"), 0o600)
	g.Refresh()
	if _, on := g.Frozen(t0); !on {
		t.Fatal("a broken file lifted the freeze")
	}
	// And a guard that has never read it protects nothing rather than
	// refusing everything.
	fresh := &Guard{Root: g.Root, Key: testKey}
	if _, blocked := fresh.Blocked("203.0.113.9", Admin, t0); blocked {
		t.Fatal("blocked on a broken file")
	}
}

func TestDecoysAreKnownAndOpenNothing(t *testing.T) {
	g := guard(t)
	secret, d, err := AddDecoy(g.Root, "CI variable in the old pipeline", "dana", t0)
	if err != nil {
		t.Fatal(err)
	}
	// The shape of an access token: prefix and 52 base32 characters.
	if !strings.HasPrefix(secret, "qz_") || len(secret) != 55 || strings.ToLower(secret) != secret {
		t.Fatalf("decoy %q does not look like a token", secret)
	}
	g.Refresh()
	if got, hit := g.Decoy(secret, t0); !hit || got.ID != d.ID {
		t.Fatal("the decoy was not recognised")
	}
	if _, hit := g.Decoy(" "+secret+"\n", t0); !hit {
		t.Fatal("surrounding space hid the decoy")
	}
	other := secret[:len(secret)-1] + "a"
	if strings.HasSuffix(secret, "a") {
		other = secret[:len(secret)-1] + "b"
	}
	if _, hit := g.Decoy(other, t0); hit {
		t.Fatal("a different token matched")
	}
	if _, hit := g.Decoy("qz_"+strings.Repeat("a", 52), t0); hit {
		t.Fatal("an arbitrary token matched")
	}
	st, _ := Load(g.Root)
	raw, _ := os.ReadFile(Path(g.Root))
	if strings.Contains(string(raw), secret) || st.Decoys[0].Hash == "" {
		t.Fatal("the decoy itself was kept")
	}
	for _, note := range []string{"", "two\nlines", strings.Repeat("x", 201)} {
		if _, _, err := AddDecoy(g.Root, note, "dana", t0); err == nil {
			t.Errorf("note %q accepted", note)
		}
	}
	if err := RemoveDecoy(g.Root, d.ID, t0); err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	if _, hit := g.Decoy(secret, t0); hit {
		t.Fatal("a removed decoy still matched")
	}
	if err := RemoveDecoy(g.Root, d.ID, t0); err == nil {
		t.Fatal("removed twice")
	}
}
