// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/clientip"
)

func TestTheSlowBudgetIsTwentyAtOnceThenOneASecond(t *testing.T) {
	var l limiter
	now := t0
	for i := 0; i < slowBurst; i++ {
		if ok, _ := l.allow("k", 1, now); !ok {
			t.Fatalf("refused the %dth of the burst", i+1)
		}
	}
	ok, wait := l.allow("k", 1, now)
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("past the burst: %v %v", ok, wait)
	}
	if ok, _ := l.allow("k", 1, now.Add(time.Second)); !ok {
		t.Fatal("a second later, one more was refused")
	}
	// A write costs ten.
	var w limiter
	w.allow("k", slowWrite, now)
	w.allow("k", slowWrite, now)
	if ok, wait := w.allow("k", slowWrite, now); ok || wait < 9*time.Second {
		t.Fatalf("a third write at once: %v %v", ok, wait)
	}
	// Another key has its own budget.
	if ok, _ := l.allow("other", 1, now); !ok {
		t.Fatal("one key's budget was another's")
	}
}

func TestTheSlowLimiterForgetsWhatItCanWithoutGrowing(t *testing.T) {
	var l limiter
	for i := 0; i < maxSlowKeys+500; i++ {
		l.allow(fmt.Sprint(i), 1, t0)
	}
	if len(l.tat) > maxSlowKeys {
		t.Fatalf("%d keys", len(l.tat))
	}
	// Later, everything is whole again and is forgotten first.
	l.allow("new", 1, t0.Add(time.Hour))
	if len(l.tat) > maxSlowKeys {
		t.Fatalf("%d keys", len(l.tat))
	}
}

func TestASlowedSourceGetsABudgetAndEverybodyElseNothing(t *testing.T) {
	g := guard(t)
	p := ok(Slow, "source:"+audit.Pseudonym(testKey, "203.0.113.9"))
	p.Until, p.Where = time.Now().Add(time.Hour), Site
	if _, _, err := Apply(g.Root, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	h := g.Wrap(Site, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	do := func(remote, method string, prefetch bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/", nil)
		r.RemoteAddr = remote
		if prefetch {
			r.Header.Set("Sec-Purpose", "prefetch")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < slowBurst; i++ {
		if w := do("203.0.113.9:1", "GET", false); w.Code != 200 {
			t.Fatalf("the %dth request within the budget: %d", i+1, w.Code)
		}
	}
	w := do("203.0.113.9:1", "GET", false)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Connection") != "close" {
		t.Fatalf("past the budget: %d %v", w.Code, w.Header())
	}
	if secs, _ := strconv.Atoi(w.Header().Get("Retry-After")); secs < 1 || secs > 2 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	// A prefetch is refused and not charged; anybody else is untouched.
	if w := do("203.0.113.9:1", "GET", true); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a slowed source's prefetch: %d", w.Code)
	}
	for i := 0; i < 50; i++ {
		if w := do("203.0.113.10:1", "POST", false); w.Code != 200 {
			t.Fatalf("another source was slowed: %d", w.Code)
		}
	}
	if !strings.Contains(Describe(p), "slowed the source on the site") {
		t.Fatal(Describe(p))
	}
}

func TestTheIndexFindsWhatAPassOverEveryProtectionWould(t *testing.T) {
	g := guard(t)
	g.ASN = func(a netip.Addr) (uint32, bool) {
		if !a.Is4() {
			return 0, false
		}
		return 64500 + uint32(a.As4()[1]%4), true
	}
	rng := rand.New(rand.NewPCG(1, 2))
	addr := func() netip.Addr {
		if rng.IntN(4) == 0 {
			return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(rng.IntN(4)), 0, byte(rng.IntN(4)), 15: byte(rng.IntN(250) + 1)})
		}
		return netip.AddrFrom4([4]byte{203, byte(rng.IntN(4)), byte(rng.IntN(4)), byte(rng.IntN(250) + 1)})
	}
	wheres := []string{Admin, Site, All}
	err := Change(g.Root, t0, func(st *State) error {
		for i := 0; i < 400; i++ {
			a := addr()
			p := Protection{ID: fmt.Sprint("sh-", i), Kind: []string{Block, Slow}[rng.IntN(2)], Where: wheres[rng.IntN(3)],
				Reason: "x", By: "x", At: t0, Until: t0.Add(time.Duration(rng.IntN(3)) * time.Hour), Auto: rng.IntN(2) == 0}
			switch rng.IntN(3) {
			case 0:
				p.Target = "source:" + g.Handle(clientipSource(a))
			case 1:
				bits := 24
				if a.Is6() {
					bits = 48
				}
				pfx, _ := a.Prefix(bits)
				p.Target = "net:" + pfx.String()
			default:
				n, _ := g.ASN(a)
				p.Target = "asn:" + strconv.Itoa(int(n))
			}
			st.Protections = append(st.Protections, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	st := g.state(t0)
	naive := func(kind, where string, a netip.Addr) bool {
		hs := g.Handles(a)
		for _, p := range st.Protections {
			if p.Kind != kind || !p.ActiveAt(t0) || (p.Where != All && p.Where != where) {
				continue
			}
			k, v, _ := strings.Cut(p.Target, ":")
			switch k {
			case "source":
				for _, h := range hs {
					if h == v {
						return true
					}
				}
			case "net":
				if pfx, err := netip.ParsePrefix(v); err == nil && pfx.Contains(a) {
					return true
				}
			case "asn":
				if n, ok := g.ASN(a); ok && strconv.Itoa(int(n)) == v {
					return true
				}
			}
		}
		return false
	}
	for i := 0; i < 3000; i++ {
		a := addr()
		where := []string{Admin, Site}[rng.IntN(2)]
		for _, kind := range []string{Block, Slow} {
			_, got := g.match(kind, a.String(), where, t0)
			if want := naive(kind, where, a); got != want {
				t.Fatalf("%s %s %s: index %v, every protection %v", kind, where, a, got, want)
			}
		}
	}
}

func TestLowConfidencePublicSignalsSlowBeforeTheyBlock(t *testing.T) {
	for _, name := range []string{"admin-hunting", "conversation-guessing", "chatbot-injection"} {
		for _, pb := range Builtins() {
			if pb.Name == name && pb.Stages[0].Do[0].Action != "slow-source" {
				t.Errorf("%s starts with %s", name, pb.Stages[0].Do[0].Action)
			}
		}
	}
	// Signals anybody can raise do nothing wide either.
	Signals["test-forged"] = "x"
	Traits["test-forged"] = Trait{Confidence: 1, Spoofable: 2}
	defer delete(Signals, "test-forged")
	defer delete(Traits, "test-forged")
	for _, step := range []Step{{Action: "lockdown", For: Duration(time.Hour)}, {Action: "freeze", For: Duration(time.Hour)},
		{Action: "shield-feature", Feature: "forms", Level: Off, For: Duration(time.Hour)},
		{Action: "slow-source", Where: Site, For: Duration(time.Hour)}} {
		pb := Playbook{Name: "x", Title: "x", Mode: "act", On: Trigger{Signal: "test-forged", Per: "source", Count: 5, Within: Duration(time.Hour)},
			Stages: []Stage{{Do: []Step{step}}}}
		if err := pb.Validate(); err == nil {
			t.Errorf("a forgeable signal may %s", step.Action)
		}
	}
}

func clientipSource(a netip.Addr) string { return clientip.Source(a) }
