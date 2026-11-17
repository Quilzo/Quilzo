// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
	"time"
)

func webbed(caps []string, w *Web) Manifest {
	return Manifest{Name: "reader", Kind: KindTask, Purpose: "read the web", Capabilities: caps,
		Autonomy: AutonomyDraft, Web: w, Budget: Budget{Steps: 10, Tools: 1, Duration: Duration(time.Minute)}}
}

// A web declaration means what it says: hosts named one by one, or any
// public host said in as many words, and never both or neither.
func TestAWebDeclarationMeansWhatItSays(t *testing.T) {
	for _, m := range []Manifest{
		webbed([]string{"web_fetch"}, &Web{Fetch: []string{"docs.example.com"}}),
		webbed([]string{"web_fetch", "web_search"}, &Web{Any: true}),
		webbed([]string{"web_search"}, nil),
	} {
		if err := m.Validate(nil); err != nil {
			t.Errorf("%+v: %v", m.Web, err)
		}
	}
	for _, c := range []struct {
		m    Manifest
		want string
	}{
		{webbed([]string{"web_fetch"}, nil), "names nothing it may read"},
		{webbed([]string{"web_fetch"}, &Web{}), "names nothing it may read"},
		{webbed([]string{"web_fetch"}, &Web{Any: true, Fetch: []string{"a.example"}}), "say one"},
		{webbed([]string{"web_fetch"}, &Web{Fetch: []string{"*.example.com"}}), "not one host name"},
		{webbed([]string{"web_fetch"}, &Web{Fetch: []string{"10.0.0.1"}}), "an address"},
		{webbed([]string{"web_fetch"}, &Web{Fetch: []string{"a.example", "a.example"}}), "twice"},
		{webbed([]string{"web_search"}, &Web{Any: true}), "does not hold web_fetch"},
		{webbed([]string{"read_page"}, &Web{Any: true}), "holds none of its capabilities"},
	} {
		if err := c.m.Validate(nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v %v: %v, want %q", c.m.Web, c.m.Capabilities, err, c.want)
		}
	}
}

// Handing work on narrows the web: hosts both may read, any host only
// when both say so, nothing when either says nothing.
func TestTheWebIsNarrowedLikeEverythingElse(t *testing.T) {
	for _, c := range []struct {
		m, by *Web
		want  string
	}{
		{&Web{Any: true}, &Web{Any: true}, "any"},
		{&Web{Any: true}, &Web{Fetch: []string{"a.example"}}, "a.example"},
		{&Web{Fetch: []string{"a.example", "b.example"}}, &Web{Any: true}, "a.example,b.example"},
		{&Web{Fetch: []string{"a.example", "b.example"}}, &Web{Fetch: []string{"b.example", "c.example"}}, "b.example"},
		{&Web{Any: true}, nil, "nil"},
	} {
		got := narrowWeb(c.m, c.by)
		s := "nil"
		if got != nil {
			s = strings.Join(got.Fetch, ",")
			if got.Any {
				s = "any"
			}
		}
		if s != c.want {
			t.Errorf("%+v by %+v: %s, want %s", c.m, c.by, s, c.want)
		}
	}
}

// Once a run holds something private and has read somebody else's words,
// an address it reads and a query it searches wait for a person: both are
// the model's words carried to a host.
func TestTheBreakerWatchesWhatTheWebIsSent(t *testing.T) {
	s := NewSession(webbed([]string{"web_fetch", "web_search"}, &Web{Any: true}), nil)
	fetch := Action{Op: "web_fetch", Input: map[string]any{"url": "https://collector.example/?d=balance"}}
	search := Action{Op: "web_search", Input: map[string]any{"query": "balance 4210"}}
	if _, breaks := s.Breaks(fetch); breaks {
		t.Fatal("a run holding nothing private was held")
	}
	s.ReadWeb("hartsbakery.co.uk", "https://hartsbakery.co.uk/")
	s.HoldsPrivate("the draft of the price list")
	why, breaks := s.Breaks(fetch)
	if !breaks || !strings.Contains(why, "collector.example") {
		t.Fatalf("reading an address after holding something private: %q %v", why, breaks)
	}
	if c := CommitOf(fetch, why, WaitAsk, false); c != "sends" {
		t.Errorf("a held read commits to %q", c)
	}
	if _, breaks := s.Breaks(search); !breaks {
		t.Error("a search after holding something private was not held")
	}
}

// A search of the research indexes, and the identifier a citation is
// looked up by, are the model's words carried to a host, as a web search
// is: once a run holds something private and has read somebody else's
// words, both wait for a person.
//
// Found by an audit: the breaker's list had the web's hands and the
// browser's, and not the research operations a run performs through the
// agent interface, so a tainted run's research_search with a private
// balance in its query went to the index while its web_search was held.
func TestTheBreakerWatchesWhatTheResearchIndexesAreSent(t *testing.T) {
	s := NewSession(webbed([]string{"web_search"}, nil), nil)
	search := Action{Op: "research_search", Input: map[string]any{"query": "balance 4210"}}
	cite := Action{Op: "research_cite", Input: map[string]any{"id": "10.1000/balance-4210"}}
	if _, breaks := s.Breaks(search); breaks {
		t.Fatal("a run holding nothing private was held")
	}
	s.ReadWeb("hartsbakery.co.uk", "https://hartsbakery.co.uk/")
	s.HoldsPrivate("the draft of the price list")
	for _, a := range []Action{search, cite} {
		why, breaks := s.Breaks(a)
		if !breaks || !strings.Contains(why, "research") {
			t.Errorf("%s after holding something private: %q %v", a.Op, why, breaks)
		}
	}
	// A tool that happens to share the name is the tool's, and its host is
	// read as a tool's is.
	if to, sends := HandSends(Action{Op: "research_search", Tool: "lookup"}); sends {
		t.Errorf("a tool's call was read as the research hand's, to %q", to)
	}
}

// A search of the research indexes that waits for a person is shown to
// them as what it is, a send, whatever the run read and whatever it is
// asked about.
//
// What an action commits to is read from the action first and from the
// reason it waits only when the action does not say. A search of the web
// was named there and a search of the research indexes was not, so once
// the breaker held one its class was read from the breaker's words, which
// name what the run holds and what it read: a run holding the draft of the
// order form had its search shown to the person deciding it as a payment,
// and one that had read the page on how to cancel, as a deletion.
func TestAHeldResearchSearchIsShownAsASend(t *testing.T) {
	s := NewSession(webbed([]string{"web_search"}, nil), nil)
	s.ReadWeb("hartsbakery.co.uk", "https://hartsbakery.co.uk/cancel")
	s.HoldsPrivate("the draft of the order form")
	for _, a := range []Action{
		{Op: "research_search", Input: map[string]any{"query": "balance 4210"}},
		{Op: "research_cite", Input: map[string]any{"id": "10.1000/balance-4210"}},
	} {
		why, breaks := s.Breaks(a)
		if !breaks {
			t.Fatalf("%s after holding something private was not held", a.Op)
		}
		if c := CommitOf(a, why, WaitAsk, false); c != "sends" {
			t.Errorf("a held %s commits to %q: %q", a.Op, c, why)
		}
		if Earnable(a, why, WaitAsk, false) {
			t.Errorf("a held %s may be earned away", a.Op)
		}
		// And asked about for any other reason, it is still what it is.
		if c := CommitOf(a, "", WaitAsk, false); c != "sends" {
			t.Errorf("%s asked about first commits to %q", a.Op, c)
		}
	}
}
