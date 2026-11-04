// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/accessreview"
	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/scim"
	"github.com/quilzo/quilzo/internal/site"
)

const reviewDay = 24 * time.Hour

// reviewed is a store with two administrators (dana and sam) and an
// author on /blog (kit), each holding a token of their own.
func reviewed(t *testing.T) (root string, tokens map[string]string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root = connectStore(t)
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	tokens = map[string]string{"dana": personToken(t, root, "dana", auth.RoleAdmin)}
	flagToken = tokens["dana"]
	for _, g := range [][]string{{"grant", "sam", "admin"}, {"grant", "kit", "author", "--on", "/blog"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	tokens["sam"] = personToken(t, root, "sam", auth.RoleAdmin)
	tokens["kit"] = personToken(t, root, "kit", auth.RoleAuthor)
	return root, tokens
}

// personToken is somebody's own long-lived token, named the way a person's
// is ("cli"), so the caller it makes is the person rather than a service.
func personToken(t *testing.T, root, who string, role auth.Role) string {
	t.Helper()
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.Issue("cli", who, role, "/", 30*reviewDay, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	return secret
}

func review(t *testing.T, root, as string, args ...string) error {
	t.Helper()
	flagToken = as
	return cmdAccess(root, append([]string{"review"}, args...))
}

func openReview(t *testing.T, root string) *accessreview.Review {
	t.Helper()
	r, err := reviewStore(root).Current()
	if err != nil || r == nil {
		t.Fatalf("no open review: %v", err)
	}
	return r
}

func itemFor(t *testing.T, r *accessreview.Review, match func(accessreview.Item) bool) accessreview.Item {
	t.Helper()
	for _, it := range r.Items {
		if match(it) {
			return it
		}
	}
	t.Fatalf("no such item in %+v", r.Items)
	return accessreview.Item{}
}

func bindingOf(who string) func(accessreview.Item) bool {
	return func(it accessreview.Item) bool { return it.Kind == accessreview.Binding && it.Principal == who }
}

func credentialOf(who string) func(accessreview.Item) bool {
	return func(it accessreview.Item) bool { return it.Kind == accessreview.Credential && it.Principal == who }
}

// decideAll decides everything as whoever may: each administrator keeps
// the other's, with a reason.
func decideAll(t *testing.T, root string, tokens map[string]string) {
	t.Helper()
	r := openReview(t, root)
	for _, it := range r.Items {
		if _, done := r.Decided(it.ID); done {
			continue
		}
		as := tokens["dana"]
		if it.Holder("dana") {
			as = tokens["sam"]
		}
		if err := review(t, root, as, "decide", it.ID, "keep", "--why", "still needed"); err != nil {
			t.Fatal(err)
		}
	}
}

func events(t *testing.T, root string) []audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func lastEvent(t *testing.T, root, action string) *audit.Event {
	t.Helper()
	evs := events(t, root)
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Action == action {
			return &evs[i]
		}
	}
	return nil
}

// Regression 1, through the command: what start puts in front of the
// reviewer.
func TestStartingAReviewTakesInWhatOnlyQuilzoGrants(t *testing.T) {
	root, tokens := reviewed(t)
	if err := cmdSCIM(root, []string{"map", "Editors", "publisher"}); err != nil {
		t.Fatal(err)
	}
	if err := scimStore(root).Update(func(st *scim.State) error {
		st.Users = append(st.Users, scim.User{ID: "u1", UserName: "ada@example.com", Active: true})
		st.Groups = append(st.Groups, scim.Group{ID: "g1", DisplayName: "Editors", Members: []string{"u1"}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := scimSync(root, "ada@example.com", []string{"publisher"}, false); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	if _, _, err := ts.IssueSession("passkey:sam", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}

	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	r := openReview(t, root)
	kinds := map[accessreview.Kind]int{}
	for _, it := range r.Items {
		kinds[it.Kind]++
		if it.Principal == "ada@example.com" {
			t.Errorf("a grant provisioning made is reviewed here: %+v", it)
		}
	}
	// dana, sam and kit by hand; the one mapping; the three long-lived
	// tokens, and not sam's session.
	if kinds[accessreview.Binding] != 3 || kinds[accessreview.Mapping] != 1 || kinds[accessreview.Credential] != 3 {
		t.Errorf("the population: %v %+v", kinds, r.Items)
	}
	started := lastEvent(t, root, "review.started")
	if started == nil || started.Detail["items"] != "7" {
		t.Fatalf("review.started: %+v", started)
	}
	if err := review(t, root, tokens["sam"], "start"); !errors.Is(err, accessreview.ErrOpen) {
		t.Errorf("a second review started while one was open: %v", err)
	}
	if err := review(t, root, tokens["dana"], "items"); err != nil {
		t.Errorf("items: %v", err)
	}
}

// Regression 2, against the real audit log and its pseudonyms: sam's
// session has been pruned and the log says they signed in ten days ago, so
// sam is not dormant; kit, with nothing for ninety-one days, is, first.
func TestActivityIsReadFromTheAuditLogUnderItsPseudonyms(t *testing.T) {
	root, _ := reviewed(t)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for i := range p.Bindings {
			p.Bindings[i].GrantedAt = time.Now().Add(-81 * reviewDay).Unix()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Only sessions are left of anybody's credentials: none of them used.
	ts, _ := loadTokens(root)
	ts.Tokens = nil
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	record(root, audit.Record{Action: "signin.passkey", Resource: "/", Outcome: audit.Success,
		Principal: "sam", Kind: audit.KindHuman, Verified: true})
	record(root, audit.Record{Action: "publish", Resource: "/", Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindHuman, Verified: true})
	if b, _ := os.ReadFile(auditPath(root)); strings.Contains(string(b), `"principal":"sam"`) {
		t.Fatal("the log is not pseudonymous, so this test is not testing the lookup")
	}

	in, err := reviewInputs(root, nil, time.Now().Add(10*reviewDay))
	if err != nil {
		t.Fatal(err)
	}
	items := accessreview.Snapshot(in)
	for _, it := range items {
		switch it.Principal {
		case "sam":
			if it.Dormant || it.LastActive.IsZero() {
				t.Errorf("sam, seen in the log ten days before: %+v", it)
			}
		case "kit":
			if !it.Dormant || it.Proposed != accessreview.Revoke || it.ID != "1" {
				t.Errorf("kit, with nothing for ninety-one days: %+v", it)
			}
		}
	}
}

// Regression 3, through the command: oneself under another spelling, a
// service token, and privileged access kept without a reason are refused;
// ordinary access kept without one is not.
func TestTheReviewRulesHoldAtTheCommandLine(t *testing.T) {
	root, tokens := reviewed(t)
	if err := cmdAuth(root, []string{"grant", "Dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := proposeSecondApproved(t, root, tokens["sam"]); err != nil {
		t.Fatal(err)
	}
	tokens["Dana"] = personToken(t, root, "Dana", auth.RoleAdmin)
	// A program's token for sam: a service, whatever sam may do.
	ts, _ := loadTokens(root)
	deploy, _, err := ts.Issue("deploy", "sam", auth.RoleAdmin, "/", 30*reviewDay, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	r := openReview(t, root)
	dana, kit, sam := itemFor(t, r, bindingOf("dana")), itemFor(t, r, bindingOf("kit")), itemFor(t, r, bindingOf("sam"))

	if err := review(t, root, tokens["Dana"], "decide", dana.ID, "keep", "--why", "owner"); err == nil ||
		!strings.Contains(err.Error(), "own") {
		t.Errorf("Dana reviewed dana: %v", err)
	}
	if err := review(t, root, deploy, "decide", kit.ID, "keep"); err == nil || !strings.Contains(err.Error(), "program") {
		t.Errorf("a service token decided: %v", err)
	}
	if err := review(t, root, tokens["dana"], "decide", sam.ID, "keep"); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("privileged access kept with no reason: %v", err)
	}
	if err := review(t, root, tokens["dana"], "decide", kit.ID, "keep"); err != nil {
		t.Errorf("ordinary access kept with no reason was refused: %v", err)
	}
	if err := review(t, root, tokens["dana"], "decide", kit.ID, "reduce"); err == nil {
		t.Error("reduce was accepted")
	}
	// A model at the agent interface is refused by the same rule.
	model := &Caller{Name: "lee", Kind: audit.KindAI, Model: "mcp-client", Verified: true}
	if _, _, err := reviewDecide(root, model, kit.ID, accessreview.Keep, ""); err == nil {
		t.Error("a model decided")
	}
}

// proposeSecondApproved approves what is waiting, as sam: making Dana an
// administrator took a second one.
func proposeSecondApproved(t *testing.T, root, sam string) (bool, error) {
	t.Helper()
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) == 0 {
		return false, err
	}
	flagToken = sam
	return true, cmdPending(root, []string{"approve", pend[0].ID})
}

// Regression 4. A publisher and an auditor of the compliance area may not
// decide; an administrator of the whole store may.
func TestOnlyAnAdministratorOfTheWholeStoreDecides(t *testing.T) {
	root, tokens := reviewed(t)
	if err := cmdAuth(root, []string{"grant", "pub", "publisher"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "aud", "auditor", "--for", "30d"}); err != nil {
		t.Fatal(err)
	}
	tokens["pub"] = personToken(t, root, "pub", auth.RolePublisher)
	tokens["aud"] = personToken(t, root, "aud", auth.RoleReader)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	kit := itemFor(t, openReview(t, root), bindingOf("kit"))
	for _, who := range []string{"pub", "aud"} {
		flagToken = tokens[who]
		if err := authoriseCommand(root, "access", []string{"review", "decide", kit.ID, "keep"}); err == nil {
			t.Errorf("%s passed the command's gate", who)
		}
		if err := review(t, root, tokens[who], "decide", kit.ID, "keep"); err == nil {
			t.Errorf("%s decided", who)
		}
		if err := review(t, root, tokens[who], "close"); err == nil {
			t.Errorf("%s closed the review", who)
		}
	}
	flagToken = tokens["dana"]
	if err := authoriseCommand(root, "access", []string{"review", "decide", kit.ID, "keep"}); err != nil {
		t.Errorf("an administrator was refused at the gate: %v", err)
	}
	if err := review(t, root, tokens["dana"], "decide", kit.ID, "keep"); err != nil {
		t.Errorf("an administrator was refused: %v", err)
	}
}

// Regression 5. A revoke takes the binding away at once, and what the
// person holds is refused on its next use; a revoked token stops working
// with its sessions. A revoke that would leave nobody administering the
// store is refused, decided before or not.
func TestARevokeAppliesAtOnceAndNeverLeavesNobodyInCharge(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	r := openReview(t, root)
	kit := itemFor(t, r, bindingOf("kit"))
	kitTok := itemFor(t, r, credentialOf("kit"))

	if err := review(t, root, tokens["dana"], "decide", kit.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	if pol.Evaluate("kit", auth.ActView, "/blog").Allowed {
		t.Fatal("kit's binding is still there")
	}
	if err := authorise(root, resolveCaller(root, tokens["kit"]), auth.ActEditDraft, "/blog/hello"); err == nil {
		t.Error("kit's token still writes /blog")
	}
	ts, _ := loadTokens(root)
	_, session, err := ts.Exchange(tokens["kit"], auth.RoleAuthor, "/", 15*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "decide", kitTok.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if works(root, tokens["kit"]) {
		t.Error("kit's token still authenticates after it was revoked")
	}
	ts, _ = loadTokens(root)
	for _, tok := range ts.Tokens {
		if tok.ID == session.ID && !tok.Revoked {
			t.Error("the session minted from kit's token outlived it")
		}
	}
	if e := lastEvent(t, root, "token.revoke"); e == nil || e.Detail["revoked_id"] != kitTok.Credential {
		t.Errorf("the revocation is not on the record the token path writes: %+v", e)
	}

	// sam revokes dana and, deciding at the same moment, dana revokes sam:
	// the second to land would leave nobody, and is refused on the policy
	// as it then stands.
	sam, dana := itemFor(t, r, bindingOf("sam")), itemFor(t, r, bindingOf("dana"))
	if err := review(t, root, tokens["sam"], "decide", dana.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if err := applyRevoke(root, human("dana"), sam); !errors.Is(err, errLastAdministrator) {
		t.Fatalf("the last administrator was revoked: %v", err)
	}
	if pol, _ := loadPolicy(root); !pol.Evaluate("sam", auth.ActGrant, "/").Allowed {
		t.Fatal("sam is no longer an administrator after a refused revoke")
	}
}

// Regression 6. Every review record is written, none carries the reason,
// and a token's revoke names it as a credential.
func TestTheReviewIsOnTheRecordWithoutItsReasons(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	r := openReview(t, root)
	const reason = "kit writes the release notes for Priya"
	if err := review(t, root, tokens["dana"], "decide", itemFor(t, r, bindingOf("kit")).ID, "keep", "--why", reason); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "decide", itemFor(t, r, credentialOf("kit")).ID, "revoke", "--why", reason); err != nil {
		t.Fatal(err)
	}
	decideAll(t, root, tokens)
	if err := review(t, root, tokens["dana"], "close"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"review.started", "review.keep", "review.revoke", "review.closed"} {
		if lastEvent(t, root, action) == nil {
			t.Errorf("no %s record: the log refused it, or nothing wrote it", action)
		}
	}
	revoke := lastEvent(t, root, "review.revoke")
	if revoke.Detail["credential"] == "" || revoke.Detail["kind"] != "credential" || revoke.Detail["reason"] != "given" {
		t.Errorf("review.revoke: %v", revoke.Detail)
	}
	for k := range revoke.Detail {
		if strings.Contains(k, "token") {
			t.Errorf("a detail key %q, which the log refuses", k)
		}
	}
	if revoke.Detail["principal"] == "kit" {
		t.Error("the principal is in clear in a pseudonymous log")
	}
	b, _ := os.ReadFile(auditPath(root))
	if strings.Contains(string(b), "Priya") || strings.Contains(string(b), "release notes") {
		t.Error("a reviewer's reason reached the audit log")
	}
	kept, _ := os.ReadFile(reviewStore(root).Dir + "/" + r.ID + ".json")
	if !strings.Contains(string(kept), reason) {
		t.Error("the reason is not kept in the review file")
	}
}

// Regression 7. Close is refused while anything is undecided; closing
// writes review.closed and the evidence; one close in six months is
// unproven, and two a quarter apart are covered.
func TestClosingWritesTheEvidenceAndTwoAreNeeded(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "close"); err == nil || !strings.Contains(err.Error(), "undecided") {
		t.Fatalf("closed with nothing decided: %v", err)
	}
	decideAll(t, root, tokens)
	if err := review(t, root, tokens["dana"], "close"); err != nil {
		t.Fatal(err)
	}
	closed := lastEvent(t, root, "review.closed")
	if closed == nil || closed.Detail["kept"] != "6" || closed.Detail["alone"] != "" {
		t.Fatalf("review.closed: %+v", closed)
	}
	if lastEvent(t, root, "control.operated") == nil {
		t.Error("the evidence is not in the audit chain")
	}

	controls, err := loadControls(root)
	if err != nil {
		t.Fatal(err)
	}
	var control assurance.Control
	for _, c := range controls {
		if c.ID == accessreview.ControlID {
			control = c
		}
	}
	if control.Cadence != assurance.Quarterly {
		t.Fatalf("the built-in control is not declared: %+v", controls)
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		t.Fatal(err)
	}
	period := assurance.Period{From: time.Now().Add(-182 * reviewDay), To: time.Now().Add(time.Minute)}
	if cov := assurance.Measure(control, evidence, period); cov.Observations != 1 || cov.Proven() {
		t.Errorf("one review in six months: %s", cov.Why())
	}
	earlier := &accessreview.Review{ID: "earlier", Closed: time.Now().Add(-91 * reviewDay), ClosedBy: "sam",
		Closer: audit.KindHuman, Summary: &accessreview.Summary{Items: 6, Kept: 6}}
	if err := recordReviewEvidence(root, earlier); err != nil {
		t.Fatal(err)
	}
	evidence, _ = loadEvidence(root)
	if cov := assurance.Measure(control, evidence, period); !cov.Proven() || !cov.Complete() {
		t.Errorf("two reviews a quarter apart: %s", cov.Why())
	}
}

// Regression 8. access.review-due fires on day ninety-one with the
// default, is quiet after a close, and follows a declared ac-02_odp.10.
func TestAReviewFallsDueAndAClosedOneAnswersIt(t *testing.T) {
	root, tokens := reviewed(t)
	scan := func(at time.Time) *posture.Finding {
		rep := posture.Scan(posture.State{Reviews: observeReviews(root, nil, at), Now: at}, nil)
		for i := range rep.Findings {
			if rep.Findings[i].Rule == "access.review-due" {
				return &rep.Findings[i]
			}
		}
		return nil
	}
	now := time.Now()
	if f := scan(now.Add(89 * reviewDay)); f != nil {
		t.Errorf("due on day eighty-nine: %s", f.Detail)
	}
	if f := scan(now.Add(91 * reviewDay)); f == nil {
		t.Error("not due on day ninety-one")
	}
	if !posture.Reminds("access.review-due") {
		t.Error("the security contact is not told when a review falls due")
	}

	// The organisation declares thirty days: due on day thirty-one.
	if err := odp.Save(paramsPath(root), &odp.Policy{Declared: []odp.Declared{
		{Param: "ac-02_odp.10", Value: "30 days", By: "dana", ApprovedBy: "sam"}}}); err != nil {
		t.Fatal(err)
	}
	if accessReviewEvery(root) != 30*reviewDay {
		t.Fatalf("the declared period is %s", accessReviewEvery(root))
	}
	if f := scan(now.Add(31 * reviewDay)); f == nil || !strings.Contains(f.Detail, "30 days") {
		t.Errorf("not due on day thirty-one under a thirty-day policy: %+v", f)
	}

	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	if f := scan(now.Add(31 * reviewDay)); f == nil || !strings.Contains(f.Fix, "close") {
		t.Errorf("an open review is not named in the finding: %+v", f)
	}
	decideAll(t, root, tokens)
	if err := review(t, root, tokens["dana"], "close"); err != nil {
		t.Fatal(err)
	}
	if f := scan(now.Add(29 * reviewDay)); f != nil {
		t.Errorf("still due after a close: %s", f.Detail)
	}
	if !Observe(root, t.TempDir(), posture.ServerFacts{}).Reviews.Checked {
		t.Error("the scan the server runs is not given the review facts")
	}
}

// Regression 9. A store with one administrator completes a review alone:
// their own access goes unreviewed and is counted, the record says alone,
// and approval.alone counts it.
//
// Not for a day after the other administrator was removed, as nothing else
// is approved alone then (dual.Store.Settling). Closing in that day used to
// succeed with dana's own access counted "unreviewable", nobody else being
// left to decide it, and without the record saying it was done alone: so
// removing sam was a way to sign off her own access with no trace of it.
func TestTheOnlyAdministratorCompletesAReviewAlone(t *testing.T) {
	root, tokens := reviewed(t)
	flagToken = tokens["dana"]
	if err := cmdAuth(root, []string{"revoke", "sam", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	for _, it := range openReview(t, root).Items {
		if !it.Holder("dana") {
			if err := review(t, root, tokens["dana"], "decide", it.ID, "keep", "--why", "needed"); err != nil {
				t.Fatal(err)
			}
		}
	}
	err := review(t, root, tokens["dana"], "close")
	if err == nil || !strings.Contains(err.Error(), "until") {
		t.Fatalf("closed alone the moment the other administrator was removed: %v", err)
	}
	if lastEvent(t, root, "review.closed") != nil {
		t.Fatal("review.closed was written for a close that was refused")
	}
	if lastEvent(t, root, "dual.alone-refused") == nil {
		t.Error("the refusal was not recorded")
	}
	removalAt(t, root, 24*time.Hour+time.Minute)
	if err := review(t, root, tokens["dana"], "close"); err != nil {
		t.Fatal(err)
	}
	closed := lastEvent(t, root, "review.closed")
	if closed == nil || closed.Detail["alone"] != "true" || closed.Detail["own_unreviewed"] != "2" {
		t.Fatalf("review.closed alone: %+v", closed)
	}
	rep := posture.Scan(posture.State{Audit: events(t, root), AuditRead: true, Now: time.Now()}, nil)
	found := false
	for _, f := range rep.Findings {
		found = found || f.Rule == "approval.alone"
	}
	if !found {
		t.Error("approval.alone does not count a review done alone")
	}
}

// Regression 10. A grant made after the review started is reported at
// the close as not reviewed by it.
func TestAGrantMadeDuringTheReviewIsReportedAsNotReviewed(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	flagToken = tokens["dana"]
	if err := cmdAuth(root, []string{"grant", "late", "publisher", "--on", "/news"}); err != nil {
		t.Fatal(err)
	}
	decideAll(t, root, tokens)
	flagToken = tokens["dana"]
	_, sum, err := reviewClose(root, resolveCaller(root, tokens["dana"]))
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.NotReviewed) != 1 || sum.NotReviewed[0].Principal != "late" {
		t.Fatalf("not reviewed: %+v", sum.NotReviewed)
	}
	if e := lastEvent(t, root, "review.closed"); e == nil || e.Detail["not_reviewed"] != "1" {
		t.Errorf("review.closed: %+v", e)
	}
}

// A mapping's revoke goes through provisioning's own removal, and is
// refused when the group's members are all the administrators there are.
func TestRevokingAMappingTakesItsGrantsBackUnlessNobodyWouldBeLeft(t *testing.T) {
	root, c := newSCIM(t)
	c.do("POST", "/Users", `{"userName":"ada@example.com","active":true}`)
	_, g := c.do("POST", "/Groups", `{"displayName":"Editors"}`)
	_, users := c.do("GET", "/Users", "")
	ada := users["Resources"].([]any)[0].(map[string]any)["id"].(string)
	c.do("PATCH", "/Groups/"+g["id"].(string), `{"schemas":["`+scim.SchemaPatch+`"],
		"Operations":[{"op":"add","path":"members","value":[{"value":"`+ada+`"}]}]}`)
	if pol, _ := loadPolicy(root); !pol.Evaluate("ada@example.com", auth.ActPublish, "/").Allowed {
		t.Fatal("provisioning did not make ada a publisher")
	}
	boss := personToken(t, root, "boss", auth.RoleAdmin)
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	if err := review(t, root, boss, "start"); err != nil {
		t.Fatal(err)
	}
	editors := itemFor(t, openReview(t, root), func(it accessreview.Item) bool { return it.Group == "Editors" })
	if editors.Members[0] != "ada@example.com" || editors.GrantedAt.IsZero() {
		t.Errorf("the mapping item: %+v", editors)
	}
	if err := review(t, root, boss, "decide", editors.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if pol, _ := loadPolicy(root); pol.Evaluate("ada@example.com", auth.ActPublish, "/").Allowed {
		t.Error("ada is still a publisher after the group's mapping was revoked")
	}
	if e := lastEvent(t, root, "scim.unmapped"); e == nil || e.Detail["group"] != "Editors" {
		t.Errorf("the removal is not on provisioning's own record: %+v", e)
	}

	// A group that holds the only administrators cannot be revoked away.
	if err := scimStore(root).Update(func(st *scim.State) error { st.Mapping["Admins"] = "admin"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := scimSync(root, "ada@example.com", []string{"admin"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("boss", auth.RoleAdmin, "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	item := accessreview.Item{Kind: accessreview.Mapping, Group: "Admins", Role: "admin",
		Members: []string{"ada@example.com"}}
	if err := scimStore(root).Update(func(st *scim.State) error {
		grp, _ := st.Group(g["id"].(string))
		st.Groups = append(st.Groups, scim.Group{ID: "g2", DisplayName: "Admins", Members: grp.Members})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := applyRevoke(root, human("boss"), item); !errors.Is(err, errLastAdministrator) {
		t.Fatalf("the group holding the only administrator was unmapped: %v", err)
	}
}

// The People screen, through its real routes and the command line's own
// functions: an administrator revokes kit, and kit's session is refused on
// its next request; a program's credential cannot decide at all.
func TestTheReviewOnThePeopleScreenAppliesAtOnce(t *testing.T) {
	root, tokens := reviewed(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{"blog/hello": map[string]any{"title": "Hello", "body": "x"}},
		"first", "kit"); err != nil {
		t.Fatal(err)
	}
	session := func(who string, role auth.Role) string {
		ts, _ := loadTokens(root)
		secret, _, err := ts.IssueSession("passkey:"+who, who, role, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveTokens(root, ts); err != nil {
			t.Fatal(err)
		}
		return secret
	}
	dana, kit := session("dana", auth.RoleAdmin), session("kit", auth.RoleAuthor)
	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	srv, err := admin.New(s, pol, toks, render.OneLayout(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body>{{ page.body }}</body></html>`))
	if err != nil {
		t.Fatal(err)
	}
	srv.UpdatePolicy = func(change func(*auth.Policy) error) (*auth.Policy, error) { return updatePolicy(root, change) }
	srv.SaveTokens = func(ts *auth.TokenStore) error { return saveTokens(root, ts) }
	srv.Audit = func(action, resource string, d map[string]string) { record(root, adminRecord(action, resource, d)) }
	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		p, err := loadPolicy(root)
		if err != nil {
			return nil, nil, err
		}
		ts, err := loadTokens(root)
		return p, ts, err
	}
	srv.AccessReview = accessReviewHooks(root)
	// In the grace before two factors are compulsory, the one state in
	// which a long-lived token alone still reaches the admin, so that it
	// is the review's own rule that refuses it below.
	srv.MFAFrom = time.Now().Add(14 * reviewDay)
	h := srv.Handler()
	do := func(method, path, secret string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	if w := do("GET", "/page/blog/hello", kit, nil); w.Code != http.StatusOK {
		t.Fatalf("kit cannot open their own page before the review: %d", w.Code)
	}
	if w := do("POST", "/people/review/start", tokens["dana"], nil); w.Code != http.StatusForbidden {
		t.Errorf("a long-lived token started a review on the screen: %d", w.Code)
	}
	if w := do("POST", "/people/review/start", dana, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	page := do("GET", "/people", dana, nil).Body.String()
	if !strings.Contains(page, "Review who has access") || !strings.Contains(page, `action="/people/review/decide"`) {
		t.Fatal("the People screen does not show the open review")
	}
	item := itemFor(t, openReview(t, root), bindingOf("kit"))
	w := do("POST", "/people/review/decide", dana, url.Values{"item": {item.ID}, "verdict": {"revoke"}})
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "item "+item.ID+": revoke") {
		t.Fatalf("decide: %d %s", w.Code, loc)
	}
	if w := do("GET", "/page/blog/hello", kit, nil); w.Code != http.StatusForbidden {
		t.Errorf("kit's session still opens /blog after the revoke: %d", w.Code)
	}
	if e := lastEvent(t, root, "review.revoke"); e == nil || e.Detail["kind"] != "binding" {
		t.Errorf("the screen's revoke is not on the record: %+v", e)
	}
}

// Posture drift mails a review falling due to the security contact,
// though it is Medium: a reminder written only to the audit log reminds
// nobody.
func TestAReviewFallingDueIsMailedToTheSecurityContact(t *testing.T) {
	root, _ := reviewed(t)
	if err := os.WriteFile(mailConfigPath(root), []byte(`{"host":"relay.example:587","from":"quilzo@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("security.contact", "mailto:security@example.com", "", "dana"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for i := range p.Bindings {
			p.Bindings[i].GrantedAt = time.Now().Add(-100 * reviewDay).Unix()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// No administrators' tokens, so the only check that starts failing for
	// a person is the one this is about.
	if err := saveJSON(tokensPath(root), &auth.TokenStore{}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var told []string
	old := deliverMail
	deliverMail = func(_ *mail.Mailer, m mail.Message) error {
		mu.Lock()
		defer mu.Unlock()
		told = append(told, m.To+" "+m.Subject)
		return nil
	}
	t.Cleanup(func() { deliverMail = old })

	if _, _, err := postureDrift(root, Observe(root, t.TempDir(), posture.ServerFacts{}), time.Now()); err != nil {
		t.Fatal(err)
	}
	finishBackground(10 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, m := range told {
		found = found || (strings.HasPrefix(m, "security@example.com ") && strings.Contains(m, "not been reviewed"))
	}
	if !found {
		t.Errorf("the security contact was not told a review is due: %q", told)
	}
}

// A revoke takes away the grant the reviewer was shown and nothing else
// that shares its principal, role and resource. Provisioning suspends
// somebody with a deny of reader on "/", the same three as the reader
// binding most people hold by hand, and a suspended person's items are
// dormant and proposed for revoke: a revoke matched on those three alone
// took the suspension with it, and their other grants worked again.
func TestARevokeLeavesASuspensionInPlace(t *testing.T) {
	root, tokens := reviewed(t)
	for _, g := range [][]string{{"grant", "lee", "reader"}, {"grant", "lee", "author", "--on", "/blog"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	// The identity provider deactivates lee.
	if err := scimSync(root, "lee", nil, true); err != nil {
		t.Fatal(err)
	}
	suspended := func() bool {
		t.Helper()
		pol, err := loadPolicy(root)
		if err != nil {
			t.Fatal(err)
		}
		return !pol.Evaluate("lee", auth.ActView, "/blog").Allowed
	}
	if !suspended() {
		t.Fatal("provisioning did not suspend lee")
	}
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	reader := itemFor(t, openReview(t, root), func(it accessreview.Item) bool {
		return it.Kind == accessreview.Binding && it.Principal == "lee" && it.Role == string(auth.RoleReader)
	})
	if err := review(t, root, tokens["dana"], "decide", reader.ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if !suspended() {
		t.Error("revoking lee's reader grant lifted provisioning's suspension, and lee's author grant on /blog works again")
	}
	pol, _ := loadPolicy(root)
	for _, b := range pol.Snapshot() {
		if b.Principal == "lee" && !b.Deny && b.Role == auth.RoleReader {
			t.Errorf("the reader grant the review revoked is still there: %+v", b)
		}
	}
}

// The check before a mapping's revoke keeps what provisioning took away.
// A suspended member who also holds admin by hand administers nothing,
// and counting them as an administrator let the last group that made
// anybody one be unmapped.
func TestAMappingRevokeCountsASuspendedAdministratorAsNobody(t *testing.T) {
	root, _ := newSCIM(t)
	if err := scimStore(root).Update(func(st *scim.State) error {
		st.Users = append(st.Users, scim.User{ID: "u-ada", UserName: "ada@example.com", Active: true},
			scim.User{ID: "u-bea", UserName: "bea@example.com", Active: false})
		st.Groups = append(st.Groups, scim.Group{ID: "g-admins", DisplayName: "Admins",
			Members: []string{"u-ada", "u-bea"}})
		st.Mapping["Admins"] = "admin"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := scimSync(root, "ada@example.com", []string{"admin"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("boss", auth.RoleAdmin, "/")
		return p.Grant(auth.Binding{Principal: "bea@example.com", Role: auth.RoleAdmin, Resource: "/",
			GrantedBy: "boss"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := scimSync(root, "bea@example.com", nil, true); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	if pol.Evaluate("bea@example.com", auth.ActGrant, "/").Allowed || !pol.Evaluate("ada@example.com", auth.ActGrant, "/").Allowed {
		t.Fatal("the store is not as the test needs it: ada administers through the group, bea is suspended")
	}
	item := accessreview.Item{Kind: accessreview.Mapping, Group: "Admins", Role: "admin",
		Members: []string{"ada@example.com"}}
	if err := applyRevoke(root, human("boss"), item); !errors.Is(err, errLastAdministrator) {
		t.Fatalf("the group that made the only working administrator was unmapped: %v", err)
	}
}

// Nobody decides a group they are in, including one the identity
// provider put them in after the review started: the snapshot's members
// say who was in it then, and the reviewer's own access is what it is now.
func TestJoiningAGroupDuringTheReviewMakesItYourOwn(t *testing.T) {
	root, c := newSCIM(t)
	c.do("POST", "/Users", `{"userName":"ada@example.com","active":true}`)
	_, g := c.do("POST", "/Groups", `{"displayName":"Editors"}`)
	_, users := c.do("GET", "/Users", "")
	ada := users["Resources"].([]any)[0].(map[string]any)["id"].(string)
	add := func(id string) {
		c.do("PATCH", "/Groups/"+g["id"].(string), `{"schemas":["`+scim.SchemaPatch+`"],
		"Operations":[{"op":"add","path":"members","value":[{"value":"`+id+`"}]}]}`)
	}
	add(ada)
	boss := personToken(t, root, "boss", auth.RoleAdmin)
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	if err := review(t, root, boss, "start"); err != nil {
		t.Fatal(err)
	}
	editors := itemFor(t, openReview(t, root), func(it accessreview.Item) bool { return it.Group == "Editors" })

	_, u := c.do("POST", "/Users", `{"userName":"boss","active":true}`)
	add(u["id"].(string))
	err := review(t, root, boss, "decide", editors.ID, "keep")
	if err == nil || !strings.Contains(err.Error(), "own access") {
		t.Fatalf("boss kept the mapping of a group boss is now in: %v", err)
	}
	if _, done := openReview(t, root).Decided(editors.ID); done {
		t.Error("the refused decision was recorded")
	}
}

// Asking for help passes the command gate without authority, so a word
// "help" anywhere on the line let `access review items help` past it, and
// items, which asked nothing itself, listed who holds what, with every
// token's id, to anybody who could run the command. Each subcommand now
// asks for itself, and help is answered with how to use it.
func TestTheItemsAreNotListedToSomebodyWhoAskedForHelp(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	kitTok := itemFor(t, openReview(t, root), credentialOf("kit"))
	t.Cleanup(func(old *out.Writer) func() { return func() { w = old } }(w))
	printed := func(run func() error) (string, error) {
		var b strings.Builder
		w = &out.Writer{Mode: out.JSON, Out: &b, Err: io.Discard}
		err := run()
		return b.String(), err
	}
	for _, as := range []string{tokens["kit"], ""} {
		for _, args := range [][]string{{"review", "items", "help"}, {"review", "items", "--help"},
			{"review", "items", "-h"}, {"review", "help"}, {"review", "-h"}} {
			flagToken = as
			if err := authoriseCommand(root, "access", args); err != nil {
				continue
			}
			text, err := printed(func() error { return cmdAccess(root, args) })
			if strings.Contains(text, kitTok.Credential) || strings.Contains(text, "dana") {
				t.Errorf("%v, as somebody who may not grant, listed the review: %v\n%s", args, err, text)
			}
		}
	}
	if text, err := printed(func() error { return review(t, root, tokens["kit"], "items") }); err == nil {
		t.Errorf("an author listed the review:\n%s", text)
	}
	if text, err := printed(func() error { return review(t, root, tokens["dana"], "items") }); err != nil ||
		!strings.Contains(text, kitTok.Credential) {
		t.Errorf("an administrator could not list the review: %v\n%s", err, text)
	}
}

// Activity is something the person did: a record of their proved identity
// that succeeded. Anything else in the log under their name is somebody
// else's doing, and counted as theirs it kept a dormant account off the top
// of the review: `USER=kit quilzo publish` with no token writes a refused
// record under kit's name, a refused command writes one, and the lockout
// writes signin.held under the name of the account somebody is guessing at.
func TestActivityIsWhatThePersonDidNotWhatWasTriedInTheirName(t *testing.T) {
	root, _ := reviewed(t)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for i := range p.Bindings {
			p.Bindings[i].GrantedAt = time.Now().Add(-120 * reviewDay).Unix()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	ts.Tokens = nil
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	// Somebody at the keyboard calling themselves kit, with no token.
	t.Setenv("USER", "kit")
	flagToken = ""
	if err := authoriseCommand(root, "publish", nil); err == nil {
		t.Fatal("publish ran without a token on a store with a policy")
	}
	// kit's name on a refused act, and on a sign-in held by the lockout.
	record(root, audit.Record{Action: "publish", Resource: "/", Outcome: audit.Denied,
		Principal: "kit", Kind: audit.KindHuman, Verified: true})
	record(root, adminRecord("signin.held", "/", map[string]string{"by": "kit", "source": "203.0.113.9",
		"why": "locked"}))
	// And sam, who did something.
	record(root, audit.Record{Action: "publish", Resource: "/", Outcome: audit.Success,
		Principal: "sam", Kind: audit.KindHuman, Verified: true})

	in, err := reviewInputs(root, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range accessreview.Snapshot(in) {
		switch it.Principal {
		case "kit":
			if !it.Dormant || !it.LastActive.IsZero() {
				t.Errorf("kit did nothing for a hundred and twenty days, and is counted active: %+v", it)
			}
		case "sam":
			if it.Dormant {
				t.Errorf("sam published today: %+v", it)
			}
		}
	}
}

// Deciding a group's mapping looks at the group as it stands and, for a
// revoke, at the policy without what its members were provisioned. Both
// asked every member about every user or every binding, and a group of
// forty thousand took most of a minute in the request that decided it.
func TestDecidingALargeGroupIsQuick(t *testing.T) {
	const n = 40000
	st := &scim.State{Mapping: map[string]string{"Everybody": "reader"}}
	everybody := scim.Group{ID: "g", DisplayName: "Everybody"}
	pol := &auth.Policy{Bindings: []auth.Binding{{Principal: "boss", Role: auth.RoleAdmin, Resource: "/"}}}
	for i := 0; i < n; i++ {
		id, name := fmt.Sprint("u", i), fmt.Sprintf("u%d@example.com", i)
		st.Users = append(st.Users, scim.User{ID: id, UserName: name, Active: true})
		everybody.Members = append(everybody.Members, id)
		pol.Bindings = append(pol.Bindings, auth.Binding{Principal: name, Role: auth.RoleReader, Resource: "/",
			GrantedBy: scimBy})
	}
	st.Groups = []scim.Group{everybody}
	start := time.Now()
	means, members := groupIn(st, "Everybody")
	after := withoutWhatTheyWereProvisioned(pol, members)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the group of %d and the policy without what they were provisioned took %v", n, took)
	}
	if means != "reader" || len(members) != n || len(after.Bindings) != 1 || after.Bindings[0].Principal != "boss" {
		t.Errorf("the group means %q, has %d members, and leaves %d bindings", means, len(members), len(after.Bindings))
	}
}

// The only administrator, put in a group by the identity provider after
// the review started, may not decide the group's mapping (it is their own
// now), and nobody else can. Close judged their own by the snapshot alone,
// so the item waited for a decision nobody could give, and the review
// could neither close nor be replaced by another.
func TestTheOnlyAdministratorJoiningAGroupCanStillClose(t *testing.T) {
	root, c := newSCIM(t)
	c.do("POST", "/Users", `{"userName":"ada@example.com","active":true}`)
	_, g := c.do("POST", "/Groups", `{"displayName":"Editors"}`)
	_, users := c.do("GET", "/Users", "")
	ada := users["Resources"].([]any)[0].(map[string]any)["id"].(string)
	add := func(id string) {
		c.do("PATCH", "/Groups/"+g["id"].(string), `{"schemas":["`+scim.SchemaPatch+`"],
		"Operations":[{"op":"add","path":"members","value":[{"value":"`+id+`"}]}]}`)
	}
	add(ada)
	boss := personToken(t, root, "boss", auth.RoleAdmin)
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	if err := review(t, root, boss, "start"); err != nil {
		t.Fatal(err)
	}
	_, u := c.do("POST", "/Users", `{"userName":"boss","active":true}`)
	add(u["id"].(string))
	r := openReview(t, root)
	editors := itemFor(t, r, func(it accessreview.Item) bool { return it.Group == "Editors" })
	for _, it := range r.Items {
		if it.ID == editors.ID || it.Holder("boss") {
			continue
		}
		if err := review(t, root, boss, "decide", it.ID, "keep", "--why", "needed"); err != nil {
			t.Fatal(err)
		}
	}
	if err := review(t, root, boss, "decide", editors.ID, "keep", "--why", "needed"); err == nil {
		t.Fatal("boss decided the mapping of a group boss is now in")
	}
	if err := review(t, root, boss, "close"); err != nil {
		t.Fatalf("the only administrator could not close: %v", err)
	}
	closed := lastEvent(t, root, "review.closed")
	if closed == nil || closed.Detail["alone"] != "true" || closed.Detail["own_unreviewed"] == "0" {
		t.Errorf("the group boss joined is not counted as their own and unreviewed: %+v", closed)
	}
}

// A group every administrator is in, the whole staff mapped to reader,
// is every administrator's own access, and nobody may decide it. The
// review waited for that decision for ever, and with one review open at a
// time the store could never review its access again. It closes with the
// group undecided, counted, and said in the record, as a review done alone
// says what of the administrator's own went unreviewed.
func TestAGroupEveryAdministratorIsInDoesNotHoldTheReviewOpen(t *testing.T) {
	root, tokens := reviewed(t)
	if err := scimStore(root).Update(func(st *scim.State) error {
		st.Users = append(st.Users, scim.User{ID: "u-dana", UserName: "dana", Active: true},
			scim.User{ID: "u-sam", UserName: "sam", Active: true})
		st.Groups = append(st.Groups, scim.Group{ID: "g-staff", DisplayName: "Staff",
			Members: []string{"u-dana", "u-sam"}})
		st.Mapping["Staff"] = "reader"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	r := openReview(t, root)
	staff := itemFor(t, r, func(it accessreview.Item) bool { return it.Group == "Staff" })
	for _, it := range r.Items {
		if it.ID == staff.ID {
			continue
		}
		as := tokens["dana"]
		if it.Holder("dana") {
			as = tokens["sam"]
		}
		if err := review(t, root, as, "decide", it.ID, "keep", "--why", "needed"); err != nil {
			t.Fatal(err)
		}
	}
	for _, who := range []string{"dana", "sam"} {
		if err := review(t, root, tokens[who], "decide", staff.ID, "keep"); err == nil {
			t.Fatalf("%s decided a group they are in", who)
		}
	}
	if err := review(t, root, tokens["dana"], "close"); err != nil {
		t.Fatalf("a group every administrator is in held the review open: %v", err)
	}
	closed := lastEvent(t, root, "review.closed")
	if closed == nil || closed.Detail["unreviewable"] != "1" || closed.Detail["alone"] != "" {
		t.Errorf("review.closed does not say one item was every administrator's own: %+v", closed)
	}
}

// Who may decide is asked again once the decision holds the review's lock.
// It was asked only before: a decision waiting for the lock behind
// somebody else's was carried out on authority checked earlier, so an
// administrator whose access had just been revoked by another's decision
// still revoked whatever they had queued.
func TestADecisionIsAuthorisedWhenItIsMadeNotWhenItWasAsked(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	kit := itemFor(t, openReview(t, root), bindingOf("kit"))
	sam := resolveCaller(root, tokens["sam"])
	unlock, err := atomicfile.Lock(filepath.Join(root, "access", "reviews", ".lock"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := reviewDecide(root, sam, kit.ID, accessreview.Revoke, "")
		done <- err
	}()
	time.Sleep(300 * time.Millisecond) // sam is asked, and waits for the lock
	if _, err := updatePolicy(root, func(p *auth.Policy) error { p.Revoke("sam", auth.RoleAdmin, "/"); return nil }); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-done; err == nil {
		t.Error("sam, no longer an administrator, revoked kit's access")
	}
	pol, _ := loadPolicy(root)
	if !pol.Evaluate("kit", auth.ActEditDraft, "/blog/post").Allowed {
		t.Error("kit's access is gone")
	}
}

// humanOutput runs a review command with the words a person reads, and
// returns them.
func humanOutput(t *testing.T, run func() error) (string, error) {
	t.Helper()
	old := w
	t.Cleanup(func() { w = old })
	var b strings.Builder
	w = &out.Writer{Mode: out.Human, Out: &b, Err: io.Discard}
	err := run()
	return b.String(), err
}

// A decision on the command line is what was typed and nothing is dropped
// from it. "help" given as the reason answered with the usage, recorded
// nothing and exited as though it had decided; a reason typed without
// quotes kept its first word; and one typed without --why was not kept,
// with the decision recorded either way.
func TestADecisionOnTheCommandLineDropsNothingTyped(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	kit := itemFor(t, openReview(t, root), bindingOf("kit"))
	sam := itemFor(t, openReview(t, root), bindingOf("sam"))
	for _, args := range [][]string{
		{"decide", kit.ID, "keep", "edits", "the", "handbook"},
		{"decide", kit.ID, "keep", "--why", "edits", "the", "handbook"},
		{"decide", sam.ID, "keep", "--why", "second", "administrator"},
	} {
		if err := review(t, root, tokens["dana"], args...); err == nil || !strings.Contains(err.Error(), "in quotes after --why") {
			t.Errorf("%v: %v", args, err)
		}
	}
	if len(openReview(t, root).Decisions) != 0 {
		t.Fatalf("a decision with words left over was recorded: %+v", openReview(t, root).Decisions)
	}
	text, err := humanOutput(t, func() error {
		return review(t, root, tokens["dana"], "decide", sam.ID, "keep", "--why", "help")
	})
	if err != nil || strings.Contains(text, "usage:") {
		t.Fatalf("a reason of \"help\" was answered with the usage: %v\n%s", err, text)
	}
	if d, ok := openReview(t, root).Decided(sam.ID); !ok || d.Why != "help" {
		t.Errorf("the decision with the reason \"help\" was not recorded: %+v", d)
	}
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		text, err := humanOutput(t, func() error { flagToken = ""; return cmdAccess(root, args) })
		if err != nil || !strings.Contains(text, "quilzo access review decide ITEM keep|revoke") {
			t.Errorf("quilzo access %v: %v\n%s", args, err, text)
		}
	}
}

// The list says what People says beside each card: which items are the
// reviewer's own, for another administrator, what was decided in the past
// tense and why, and what a revoke took.
func TestTheListSaysWhatPeopleSays(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	r := openReview(t, root)
	sam, kit := itemFor(t, r, bindingOf("sam")), itemFor(t, r, bindingOf("kit"))
	if err := review(t, root, tokens["dana"], "decide", sam.ID, "keep", "--why", "runs the second shift"); err != nil {
		t.Fatal(err)
	}
	text, err := humanOutput(t, func() error { return review(t, root, tokens["dana"], "decide", kit.ID, "revoke") })
	if err != nil || !strings.Contains(text, "from kit's next request, it gives them nothing") {
		t.Errorf("a revoke does not say what it took: %v\n%s", err, text)
	}
	text, err = humanOutput(t, func() error { return review(t, root, tokens["dana"], "items") })
	if err != nil {
		t.Fatal(err)
	}
	dana := itemFor(t, r, bindingOf("dana"))
	for _, want := range []string{
		dana.ID + "  dana is admin on /  undecided, your own: another administrator decides it",
		"sam is admin on /  kept by dana", "why: runs the second shift",
		"kit is author on /blog  revoked by dana",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the list does not say %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "keep by") || strings.Contains(text, "revoke by") {
		t.Errorf("a decision is listed as an instruction:\n%s", text)
	}
	text, _ = humanOutput(t, func() error { return review(t, root, tokens["sam"], "items") })
	if strings.Contains(text, "dana is admin on /  undecided, your own") {
		t.Error("dana's own item is listed as sam's")
	}
}

// With no review open, the command says when the last one closed and when
// the next is due, as People does beside its Start button, and closing one
// says when the next is due.
func TestWithNoReviewOpenTheCommandSaysWhenOneIsDue(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "items"); err == nil || !strings.Contains(err.Error(), "none has closed yet") {
		t.Errorf("before any review: %v", err)
	}
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	decideAll(t, root, tokens)
	text, err := humanOutput(t, func() error { return review(t, root, tokens["dana"], "close") })
	next := time.Now().Add(accessreview.DefaultEvery).UTC().Format("2 Jan 2006")
	if err != nil || !strings.Contains(text, "the next review is due by "+next) {
		t.Errorf("closing does not say when the next is due: %v\n%s", err, text)
	}
	err = review(t, root, tokens["dana"], "items")
	if err == nil || !strings.Contains(err.Error(), "the last closed on "+time.Now().UTC().Format("2 Jan 2006")) ||
		!strings.Contains(err.Error(), "the next is due by "+next) {
		t.Errorf("after a close: %v", err)
	}
}

// The only administrator's own items are not said to wait for another
// administrator, who does not exist: the review closes without them.
func TestTheOnlyAdministratorIsToldTheReviewClosesWithoutTheirOwn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	dana := personToken(t, root, "dana", auth.RoleAdmin)
	if err := review(t, root, dana, "start"); err != nil {
		t.Fatal(err)
	}
	text, err := humanOutput(t, func() error { return review(t, root, dana, "items") })
	if err != nil || !strings.Contains(text, "your own: with no other administrator to decide it, the review closes without it") ||
		strings.Contains(text, "another administrator decides it") {
		t.Errorf("the only administrator's own items: %v\n%s", err, text)
	}
}

// A second start is refused before the snapshot is taken.
//
// It took the snapshot first, which reads the whole audit log for when
// each person last acted, and only then found a review open: on a store
// with years of log, every refused start read all of it for nothing.
// Shown here by leaving one of the snapshot's inputs unreadable, which a
// start that reads nothing it would snapshot never notices.
func TestASecondStartIsRefusedBeforeTheSnapshotIsTaken(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scimPath(root), []byte("{not the provisioning state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["sam"], "start"); !errors.Is(err, accessreview.ErrOpen) {
		t.Fatalf("a start with a review open took the snapshot before asking: %v", err)
	}
}

// A close whose record cannot be written leaves the review open, so it
// can be closed again once the log can be written, and the evidence is
// written then.
//
// The review was saved as closed first and its records written after,
// so when the audit log refused review.closed the review stood closed
// with no record that it was done and no evidence for the control, and
// closing again said no review was open: the one way to write that
// evidence was gone.
func TestAClosedReviewIsNotClosedUntilItsEvidenceIsWritten(t *testing.T) {
	root, tokens := reviewed(t)
	if err := review(t, root, tokens["dana"], "start"); err != nil {
		t.Fatal(err)
	}
	decideAll(t, root, tokens)
	// A log writer configured and not answering: every record is refused,
	// and nothing falls back to writing the file.
	if err := os.WriteFile(logSocketPath(root), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "close"); err == nil {
		t.Fatal("closed with the audit log refusing every record")
	}
	if r, err := reviewStore(root).Current(); err != nil || r == nil {
		t.Fatalf("the review was closed with no record of it: %v", err)
	}
	if lastEvent(t, root, "review.closed") != nil {
		t.Fatal("control: review.closed was written with the log refusing")
	}

	if err := os.Remove(logSocketPath(root)); err != nil {
		t.Fatal(err)
	}
	if err := review(t, root, tokens["dana"], "close"); err != nil {
		t.Fatalf("closing again once the log can be written: %v", err)
	}
	if r, _ := reviewStore(root).Current(); r != nil {
		t.Fatal("the review is still open")
	}
	closed, operated := 0, 0
	for _, e := range events(t, root) {
		switch e.Action {
		case "review.closed":
			closed++
		case "control.operated":
			operated++
		}
	}
	if closed != 1 || operated != 1 {
		t.Errorf("review.closed %d time(s) and control.operated %d, want once each", closed, operated)
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(evidence); n != 1 {
		t.Errorf("%d piece(s) of evidence, want 1: %+v", n, evidence)
	}
}
