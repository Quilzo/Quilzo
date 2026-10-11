// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func browsing(caps []string, b *Browser) Manifest {
	return Manifest{Name: "buyer", Kind: KindTask, Purpose: "order supplies",
		Capabilities: caps, Autonomy: AutonomyDraft, Browser: b,
		Budget: Budget{Steps: 20, Tools: 1, Duration: Duration(time.Minute)}}
}

// A browser declaration says exactly which hosts, and nothing that cannot
// mean what it appears to is accepted.
func TestABrowserDeclarationMeansWhatItSays(t *testing.T) {
	open := []string{"browser_open", "browser_read"}
	sign := []string{"browser_open", "browser_read", "browser_click", "browser_sign_in"}
	shop := &Browser{Read: []string{"docs.example.com"}, Write: []string{"shop.example.com"},
		Credentials: []BrowserCredential{{Secret: "shop", Host: "shop.example.com"}}}
	ok := []Manifest{
		browsing(open, &Browser{Read: []string{"docs.example.com"}}),
		browsing(sign, shop),
		browsing(append(open, "browser_look"), &Browser{Read: []string{"docs.example.com"}, Pictures: true}),
	}
	for _, m := range ok {
		if err := m.Validate(nil); err != nil {
			t.Errorf("%v / %+v: %v", m.Capabilities, m.Browser, err)
		}
	}
	for _, c := range []struct {
		m    Manifest
		want string
	}{
		{browsing(open, nil), "names no host"},
		{browsing(open, &Browser{}), "names no host"},
		{browsing(nil, &Browser{Read: []string{"docs.example.com"}}), "holds none of its capabilities"},
		{browsing(open, &Browser{Read: []string{"*.example.com"}}), "not one host name"},
		{browsing(open, &Browser{Read: []string{"https://docs.example.com"}}), "not one host name"},
		{browsing(open, &Browser{Read: []string{"Docs.example.com"}}), "not one host name"},
		{browsing(open, &Browser{Read: []string{"localhost"}}), "not one host name"},
		{browsing(open, &Browser{Read: []string{"10.0.0.8"}}), "is an address"},
		{browsing(open, &Browser{Read: []string{"a.example.com", "a.example.com"}}), "twice"},
		{browsing(open, &Browser{Read: make([]string, MaxBrowserHosts+1)}), "at most"},
		{browsing(sign, &Browser{Read: []string{"shop.example.com"},
			Credentials: []BrowserCredential{{Secret: "shop", Host: "shop.example.com"}}}), "not a host it may write to"},
		{browsing(sign, &Browser{Write: []string{"shop.example.com"},
			Credentials: []BrowserCredential{{Secret: "Shop Login", Host: "shop.example.com"}}}), "not a credential's name"},
		{browsing(sign, &Browser{Write: []string{"shop.example.com"}}), "no credential to sign in with"},
		{browsing(append(open, "browser_look"), &Browser{Read: []string{"docs.example.com"}}), "does not allow pictures"},
	} {
		err := c.m.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.m.Browser, err, c.want)
		}
	}
	m := browsing(open, &Browser{Read: []string{"docs.example.com"}})
	m.Program = &Program{Command: []string{"/usr/bin/true"}}
	if err := m.Validate(nil); err == nil || !strings.Contains(err.Error(), "has a program") {
		t.Errorf("a program with a browser: %v", err)
	}
}

// Handing work on narrows the browser too: the hosts both may reach,
// written to only where both may write, the credentials both hold.
func TestABrowserIsNarrowedLikeEverythingElse(t *testing.T) {
	parent := &Browser{Read: []string{"docs.example.com"}, Write: []string{"crm.example.com", "shop.example.com"},
		Credentials: []BrowserCredential{{Secret: "crm", Host: "crm.example.com"}}, Pictures: true}
	child := &Browser{Read: []string{"crm.example.com", "evil.example.net"}, Write: []string{"docs.example.com", "shop.example.com"},
		Credentials: []BrowserCredential{{Secret: "crm", Host: "crm.example.com"}, {Secret: "shop", Host: "shop.example.com"}}}
	got := narrowBrowser(parent, child)
	want := &Browser{Read: []string{"crm.example.com", "docs.example.com"}, Write: []string{"shop.example.com"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("narrowed to %+v, want %+v", got, want)
	}
	if narrowBrowser(parent, nil) != nil || narrowBrowser(nil, child) != nil {
		t.Error("a side with no browser left a browser")
	}
}

// What the model chose leaves through an address it opens or words it
// types; once the run holds something private after reading somebody
// else's words, those wait for a person. Reading and pressing do not.
func TestTheBreakerWatchesWhatABrowserSends(t *testing.T) {
	s := NewSession(browsing(BrowserCapabilities, &Browser{Read: []string{"docs.example.com"}}), nil)
	open := Action{Op: "browser_open", Input: map[string]any{"url": "https://docs.example.com/?q=x"}}
	if _, breaks := s.Breaks(open); breaks {
		t.Fatal("a clean run was held")
	}
	s.ReadWeb("docs.example.com", "https://docs.example.com/")
	s.HoldsPrivate("what crm.example.com shows once signed in")
	for _, a := range []Action{open, {Op: "browser_type", Input: map[string]any{"ref": "e1", "text": "x"}}} {
		why, breaks := s.Breaks(a)
		if !breaks || !strings.Contains(why, "crm.example.com shows once signed in") {
			t.Errorf("%s was not held: %q", a.Op, why)
		}
	}
	if why, _ := s.Breaks(open); !strings.Contains(why, "send to docs.example.com") {
		t.Errorf("the host is not named: %q", why)
	}
	for _, op := range []string{"browser_read", "browser_click", "browser_choose", "browser_look"} {
		if _, breaks := s.Breaks(Action{Op: op}); breaks {
			t.Errorf("%s was held", op)
		}
	}
}

// Weighed and breaking at once is asked about once, with both reasons.
func TestOneQuestionCarriesEveryReason(t *testing.T) {
	m := browsing(BrowserCapabilities, &Browser{Read: []string{"docs.example.com"}})
	s := NewSession(m, nil)
	s.ReadWeb("docs.example.com", "https://docs.example.com/")
	s.HoldsPrivate("a customer's address")
	open := Action{Op: "browser_open", Input: map[string]any{"url": "https://docs.example.com/"}}
	p := &scripted{plan: []Action{open}}
	var asked []Pending
	r := Runner{Decide: p.decide, Perform: (&doer{}).perform,
		Weighs: func(Action) string { return "it is called Send" },
		Hold: func(_ context.Context, w Pending, _ func()) (Verdict, error) {
			asked = append(asked, w)
			return Verdict{N: w.N, Approve: true, By: "dana"}, nil
		}}
	if _, err := r.Run(context.Background(), s, "look it up"); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || !strings.Contains(asked[0].Why, "called Send") || !strings.Contains(asked[0].Why, "a customer's address") {
		t.Errorf("asked %+v", asked)
	}
}

// A browser action the declaration asks first about is asked about with
// what it commits to and what the breaker says, once; and the run's record
// stops offering the question as soon as it is answered.
func TestAnAskFirstQuestionSaysWhatThePressDoes(t *testing.T) {
	m := browsing(BrowserCapabilities, &Browser{Read: []string{"docs.example.com"}})
	m.AskFirst = []string{"browser_type"}
	s := NewSession(m, nil)
	s.ReadWeb("docs.example.com", "https://docs.example.com/")
	s.HoldsPrivate("a customer's address")
	p := &scripted{plan: []Action{{Op: "browser_type", Input: map[string]any{"ref": "e5", "text": "x"}}}}
	var asked []Pending
	var kept []Trace
	r := Runner{Decide: p.decide, Perform: (&doer{}).perform,
		Weighs:     func(Action) string { return `it types into "Pay now"` },
		Checkpoint: func(t Trace) { kept = append(kept, t) },
		Hold: func(_ context.Context, w Pending, _ func()) (Verdict, error) {
			asked = append(asked, w)
			return Verdict{N: w.N, Approve: true, By: "dana"}, nil
		}}
	if _, err := r.Run(context.Background(), s, "pay"); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || !strings.Contains(asked[0].Why, "Pay now") || !strings.Contains(asked[0].Why, "a customer's address") {
		t.Fatalf("asked %+v", asked)
	}
	for i, k := range kept {
		if k.Waiting == nil && i > 0 && kept[i-1].Waiting != nil && len(k.Steps) == 0 {
			return // cleared before the step was taken
		}
	}
	t.Errorf("the question was still on the record when the action ran: %d checkpoints", len(kept))
}
