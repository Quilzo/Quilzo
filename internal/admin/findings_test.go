// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// fakeRegister is a finding register in memory with a decision log.
type fakeRegister struct {
	reg       *finding.Register
	decisions []finding.Decision
	produced  bool
}

func newFakeRegister(fs ...finding.Finding) *fakeRegister {
	fr := &fakeRegister{reg: finding.NewRegister(), produced: len(fs) > 0}
	for _, f := range fs {
		fr.reg.Record(f, f.First)
	}
	return fr
}

func (fr *fakeRegister) wire() *Findings {
	return &Findings{
		Queue: func(now time.Time) ([]finding.Finding, bool, error) {
			return finding.View(fr.reg, fr.decisions, now), fr.produced, nil
		},
		History: func(id string) ([]finding.Decision, error) {
			return finding.History(id, fr.decisions), nil
		},
		Decide: func(d finding.Decision) error {
			fr.decisions = append(fr.decisions, d)
			return nil
		},
	}
}

func detectionFinding(who, msg string, sev telemetry.Severity) finding.Finding {
	return finding.Finding{
		Kind: finding.FromDetection, Title: "Failed sign-in to a privileged account",
		Source: "auth.privileged-failed",
		Entity: telemetry.ID{Issuer: "okta", Value: who}, Severity: sev,
		State: finding.Open, First: time.Now().UTC().Add(-3 * time.Hour),
		Technique: []string{"T1110"},
		Evidence: []finding.Evidence{{At: time.Now().UTC().Add(-3 * time.Hour),
			What: msg, Source: "okta/system", Tainted: true}},
	}
}

func decideForm(t *testing.T, srv *Server, path, token string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestTheQueueSaysWhenNothingHasLooked.
//
// An empty register and one nothing has ever written are opposite facts
// that render the same. Only the first means nothing is wrong.
func TestTheQueueSaysWhenNothingHasLooked(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/findings", token).Body.String()
	if !strings.Contains(body, "without a finding register") {
		t.Errorf("an unwired build did not say so")
	}
	srv.Findings = newFakeRegister().wire()
	body = get(t, srv, "/findings", token).Body.String()
	if !strings.Contains(body, "Nothing has looked yet") {
		t.Errorf("a never-written register read as a quiet one")
	}
	if strings.Contains(body, "Nothing needs attention") {
		t.Errorf("a never-written register said nothing needs attention")
	}
}

// TestTheQueueShowsWhatNeedsAttentionFirst.
func TestTheQueueShowsWhatNeedsAttentionFirst(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(
		detectionFinding("admin-low", "a", telemetry.SeverityLow),
		detectionFinding("admin-crit", "b", telemetry.SeverityCritical),
	)
	srv.Findings = fr.wire()
	body := get(t, srv, "/findings", token).Body.String()
	crit, low := strings.Index(body, "okta:admin-crit"), strings.Index(body, "okta:admin-low")
	if crit < 0 || low < 0 || crit > low {
		t.Fatalf("the critical finding is not first (%d, %d)", crit, low)
	}
	if !strings.Contains(body, "a person decides") {
		t.Error("a finding resting on log text does not say a person decides")
	}
	// Filtering by severity.
	body = get(t, srv, "/findings?severity=critical", token).Body.String()
	if strings.Contains(body, "okta:admin-low") || !strings.Contains(body, "okta:admin-crit") {
		t.Error("the severity filter did not filter")
	}
}

// TestNothingAnAttackerWroteRunsOnTheScreen.
//
// Every field here came from outside: the message is log text from the
// source being attacked, and the entity is whatever name the attacker tried.
func TestNothingAnAttackerWroteRunsOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	evil := `<script>alert(1)</script><img src=x onerror=alert(2)>`
	f := detectionFinding(`admin-"><svg onload=alert(3)>`, evil, telemetry.SeverityHigh)
	f.Title = "<b>title</b>"
	fr := newFakeRegister(f)
	srv.Findings = fr.wire()
	id := finding.View(fr.reg, nil, time.Now())[0].ID
	for _, path := range []string{"/findings", "/findings/" + id} {
		body := get(t, srv, path, token).Body.String()
		for _, raw := range []string{"<script>alert(1)", "<img src=x", "<svg onload", "<b>title</b>"} {
			if strings.Contains(body, raw) {
				t.Errorf("%s: %q reached the page unescaped", path, raw)
			}
		}
	}
}

// TestAVerdictIsRecordedAndApplied.
func TestAVerdictIsRecordedAndApplied(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(detectionFinding("admin-dana", "failed", telemetry.SeverityHigh))
	srv.Findings = fr.wire()
	id := finding.View(fr.reg, nil, time.Now())[0].ID

	// No reason: refused, and nothing recorded.
	w := decideForm(t, srv, "/findings/decide", token, url.Values{
		"id": {id}, "to": {"false-positive"}})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatalf("a verdict with no reason: %d %q", w.Code, w.Header().Get("Location"))
	}
	if len(fr.decisions) != 0 {
		t.Fatal("a refused verdict was recorded")
	}

	w = decideForm(t, srv, "/findings/decide", token, url.Values{
		"id": {id}, "to": {"false-positive"}, "because": {"a load test"}})
	if w.Code != http.StatusSeeOther || len(fr.decisions) != 1 {
		t.Fatalf("a valid verdict: %d, %d recorded", w.Code, len(fr.decisions))
	}
	d := fr.decisions[0]
	if d.By != "editor" || d.To != finding.FalsePositive || d.Because != "a load test" {
		t.Fatalf("recorded %+v", d)
	}
	// Off the queue, and the reason is on the finding's page.
	if body := get(t, srv, "/findings", token).Body.String(); strings.Contains(body, "okta:admin-dana") {
		t.Error("a false positive is still in the queue")
	}
	if body := get(t, srv, "/findings/"+id, token).Body.String(); !strings.Contains(body, "a load test") {
		t.Error("the reason is not shown with the decision")
	}
}

// TestADecisionNeedsARealFindingAndTheRight.
func TestADecisionNeedsARealFindingAndTheRight(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(detectionFinding("admin-dana", "failed", telemetry.SeverityHigh))
	srv.Findings = fr.wire()
	if w := decideForm(t, srv, "/findings/decide", token, url.Values{
		"id": {"not-a-finding"}, "to": {"fixed"}}); w.Code != http.StatusNotFound {
		t.Errorf("a decision about nothing answered %d", w.Code)
	}
	// Accepted must expire, in the future.
	id := finding.View(fr.reg, nil, time.Now())[0].ID
	for _, until := range []string{"", "2001-01-01", "tomorrow"} {
		decideForm(t, srv, "/findings/decide", token, url.Values{
			"id": {id}, "to": {"accepted"}, "because": {"x"}, "until": {until}})
	}
	if len(fr.decisions) != 0 {
		t.Fatalf("an acceptance with no future expiry was recorded: %+v", fr.decisions)
	}
	// A reader sees nothing and decides nothing.
	reader, rtoken := asRole(t, auth.RoleReader)
	reader.Findings = fr.wire()
	if w := get(t, reader, "/findings", rtoken); w.Code == http.StatusOK {
		t.Error("a reader opened the queue")
	}
	if w := decideForm(t, reader, "/findings/decide", rtoken, url.Values{
		"id": {id}, "to": {"fixed"}}); w.Code == http.StatusSeeOther || len(fr.decisions) != 0 {
		t.Errorf("a reader recorded a decision: %d", w.Code)
	}
}

// TestAnAgentsSuggestionIsShownAsOne.
func TestAnAgentsSuggestionIsShownAsOne(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(detectionFinding("admin-dana", "x", telemetry.SeverityHigh))
	caps := fr.wire()
	id := finding.View(fr.reg, nil, time.Now())[0].ID
	caps.Proposals = func(string) ([]finding.Proposal, error) {
		return []finding.Proposal{{Finding: id, At: time.Now(), By: "p_agent",
			For: "dana", To: finding.FalsePositive,
			Because: "<script>alert(1)</script> the VPN egresses in NZ"}}, nil
	}
	srv.Findings = caps
	body := get(t, srv, "/findings/"+id, token).Body.String()
	if !strings.Contains(body, "Suggested by an agent") ||
		!strings.Contains(body, "Nothing here has changed") {
		t.Fatal("a proposal is not shown as a suggestion")
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("a model's reasoning reached the page unescaped")
	}
	// And it did not change anything.
	if got := finding.View(fr.reg, fr.decisions, time.Now())[0].State; got != finding.Open {
		t.Fatalf("state %s", got)
	}
}
