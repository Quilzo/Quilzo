// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
	publishgate "github.com/quilzo/quilzo/internal/gate"
)

// fakeModel answers with one canned proposal and remembers what it was asked.
type fakeModel struct {
	mu    sync.Mutex
	asked []string
	reply string
}

func (f *fakeModel) Name() string { return "fake" }

func (f *fakeModel) Complete(_ context.Context, _, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, user)
	return f.reply, nil
}

func (f *fakeModel) lastAsk(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.asked) == 0 {
		t.Fatal("the model was never asked anything")
	}
	return f.asked[len(f.asked)-1]
}

// refusingGate is a content check that always refuses, with one finding.
func refusingGate(seen *map[string]any) func(map[string]any) (*publishgate.Report, []publishgate.Finding, error) {
	return func(pages map[string]any) (*publishgate.Report, []publishgate.Finding, error) {
		*seen = pages
		return &publishgate.Report{
			Check: publishgate.Check{
				Name: "claims",
				Refusal: func(n int) string {
					return "one claim has nothing behind it"
				},
			},
			Findings: []publishgate.Finding{
				{Page: "prices", Detail: "says \"the fastest CMS\" and cites nothing"},
			},
		}, []publishgate.Finding{{Detail: "a licence expires in six weeks"}}, nil
	}
}

func assistServer(t *testing.T, m *fakeModel,
	gates func(map[string]any) (*publishgate.Report, []publishgate.Finding, error)) (*Server, string) {

	t.Helper()
	srv, token := setup(t)
	srv.Assist = &Assist{
		Model: func() (assist.Model, error) { return m, nil },
		Pages: func() (map[string]any, error) {
			return map[string]any{"index": map[string]any{"title": "Home"}}, nil
		},
		Gates: gates,
	}
	return srv, token
}

const oneProposal = `{"pages":{"prices":{"title":"Prices","body":"The fastest CMS."}}}`

// A proposal is put through the publish gates before anybody accepts it.
//
// The checks were only ever asked at publication, which for a proposal is the
// last possible moment: a model writes a claim with nothing behind it, the
// person accepts it because it reads well, and the refusal arrives days later
// against a draft nobody remembers proposing.
func TestAProposalIsGatedBeforeItIsAccepted(t *testing.T) {
	m := &fakeModel{reply: oneProposal}
	var seen map[string]any
	srv, token := assistServer(t, m, refusingGate(&seen))

	html := postForm(t, srv, "/assist", token,
		"instruction=write a prices page").Body.String()

	for _, want := range []string{
		"This would not publish yet",
		"one claim has nothing behind it",
		"says &#34;the fastest CMS&#34; and cites nothing",
		"Ask fake to fix this",
		"a licence expires in six weeks",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the proposal screen does not say %q", want)
		}
	}
	// Accepting is still offered. The draft is where unfinished work belongs,
	// and a screen that refused to let anybody accept a proposal until it was
	// publishable would be a worse tool than one that said nothing.
	if !strings.Contains(html, "Accept into the draft") {
		t.Error("the gate findings took away the accept button")
	}

	// The gates were asked about the draft this would make, not about the
	// proposal alone: every finding that is about how a page sits beside what
	// is already there needs both.
	if _, ok := seen["index"]; !ok {
		t.Error("the gates were not shown the pages that already exist")
	}
	if _, ok := seen["prices"]; !ok {
		t.Error("the gates were not shown the proposed page")
	}
}

// The findings go back to the model, in the words the refusal uses.
func TestTheFindingsCanBeSentBackToTheModel(t *testing.T) {
	m := &fakeModel{reply: oneProposal}
	var seen map[string]any
	srv, token := assistServer(t, m, refusingGate(&seen))

	first := postForm(t, srv, "/assist", token,
		"instruction=write a prices page").Body.String()
	fix := hiddenValue(t, first, "fix")
	if !strings.Contains(fix, "the fastest CMS") {
		t.Fatalf("the fix note does not carry the finding: %q", fix)
	}

	again := postForm(t, srv, "/assist", token,
		"instruction=write a prices page&fix="+queryEscape(fix))
	if again.Code >= 400 {
		t.Fatalf("asking again answered %d", again.Code)
	}
	asked := m.lastAsk(t)
	if !strings.Contains(asked, "write a prices page") {
		t.Error("the second ask lost the original instruction")
	}
	if !strings.Contains(asked, "one claim has nothing behind it") {
		t.Error("the second ask did not carry the refusal")
	}
	if !strings.Contains(asked, "cites nothing") {
		t.Error("the second ask did not carry the finding")
	}
	if !strings.Contains(again.Body.String(), "Asked again") {
		t.Error("the screen does not say this was a second attempt")
	}
}

// A check that cannot run is said, not swallowed.
//
// "The claim check could not run" reaching somebody as silence would read as
// "there is nothing wrong with this", which is the failure mode internal/gate
// names and refuses to have.
func TestAGateThatCannotRunIsNotSilence(t *testing.T) {
	m := &fakeModel{reply: oneProposal}
	srv, token := assistServer(t, m,
		func(map[string]any) (*publishgate.Report, []publishgate.Finding, error) {
			return nil, nil, errNoCheck
		})

	html := postForm(t, srv, "/assist", token, "instruction=anything").Body.String()
	if !strings.Contains(html, "A check could not run") {
		t.Error("a gate that errored was not mentioned at all")
	}
	if strings.Contains(html, "passes on") {
		t.Error("a gate that errored was reported as a pass")
	}
}

// With no gates wired, the screen says nothing about them rather than claiming
// a proposal is clean.
func TestNoGatesMeansNoClaim(t *testing.T) {
	m := &fakeModel{reply: oneProposal}
	srv, token := assistServer(t, m, nil)

	html := postForm(t, srv, "/assist", token, "instruction=anything").Body.String()
	if strings.Contains(html, "passes on") || strings.Contains(html, "would not publish") {
		t.Error("an unwired gate produced a verdict")
	}
	if !strings.Contains(html, "Accept into the draft") {
		t.Error("the proposal is not acceptable without gates")
	}
}

// A proposal that passes says so, because "nothing shown" and "nothing wrong"
// have to be distinguishable.
func TestACleanProposalSaysSo(t *testing.T) {
	m := &fakeModel{reply: oneProposal}
	srv, token := assistServer(t, m,
		func(map[string]any) (*publishgate.Report, []publishgate.Finding, error) {
			return nil, nil, nil
		})

	html := postForm(t, srv, "/assist", token, "instruction=anything").Body.String()
	if !strings.Contains(html, "passes on the draft this would make") {
		t.Error("a clean proposal says nothing")
	}
}

// errNoCheck stands in for a gate that could not answer.
var errNoCheck = errors.New("the claim rules could not be read")

// hiddenValue pulls one hidden field's value out of rendered markup.
func hiddenValue(t *testing.T, html, name string) string {
	t.Helper()
	marker := `name="` + name + `" value="`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("there is no hidden %q field on the screen", name)
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("the %q field is not closed", name)
	}
	// Rendered through html/template, so it comes back escaped.
	return htmlUnescape(rest[:j])
}

// htmlUnescape reverses the escaping html/template applies to an attribute.
func htmlUnescape(s string) string {
	for _, pair := range [][2]string{
		{"&#34;", `"`}, {"&#39;", "'"}, {"&lt;", "<"}, {"&gt;", ">"},
		{"&#43;", "+"}, {"&amp;", "&"},
	} {
		s = strings.ReplaceAll(s, pair[0], pair[1])
	}
	return s
}

func queryEscape(s string) string { return url.QueryEscape(s) }
