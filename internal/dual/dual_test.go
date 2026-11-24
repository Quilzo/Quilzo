// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package dual

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// One administrator proposes and another approves; nobody approves their
// own, unless they are the only one, and then the record says so.
func TestAChangeWaitsForASecondAdministrator(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "dual.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	r, err := s.Propose(Grant, "make pat an administrator", map[string]string{"who": "pat"}, "on call", "dana", false, now)
	if err != nil || r.State != Waiting {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.Decide(r.ID, "dana", true, false, now); err == nil {
		t.Fatal("dana approved her own request")
	}
	if got, err := s.Decide(r.ID, "lee", true, false, now); err != nil || got.State != Done || got.DecidedBy != "lee" || got.Alone {
		t.Fatalf("lee approving: %+v %v", got, err)
	}
	if _, err := s.Decide(r.ID, "lee", true, false, now); err == nil {
		t.Error("a request was decided twice")
	}

	solo, _ := s.Propose(Setting, "weaken x", nil, "", "dana", true, now)
	if solo.State != Done || !solo.Alone || StateWords(solo, now) != "approved alone by dana" {
		t.Errorf("alone: %+v", solo)
	}

	late, _ := s.Propose(AuditLog, "move the log", nil, "", "dana", false, now)
	if _, err := s.Decide(late.ID, "lee", true, false, now.Add(Wait+time.Minute)); err == nil {
		t.Error("an expired request was approved")
	}
	declined, _ := s.Propose(Grant, "x", nil, "", "dana", false, now)
	if got, _ := s.Decide(declined.ID, "lee", false, false, now); got.State != Declined {
		t.Errorf("declined: %+v", got)
	}
	if pend, _ := s.Pending(now); len(pend) != 1 || pend[0].ID != late.ID {
		t.Errorf("pending: %+v", pend)
	}
}

// An approved token is issued only to whoever asked, once, within a day.
func TestAnApprovedTokenIsRedeemedOnceByWhoeverAsked(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "dual.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	r, _ := s.Propose(Token, "an admin token for deploy", nil, "", "dana", false, now)
	if _, err := s.Redeem(r.ID, "dana", now); err == nil {
		t.Fatal("a token was issued before anybody approved it")
	}
	if got, _ := s.Decide(r.ID, "lee", true, false, now); got.State != Approved {
		t.Fatalf("approved: %+v", got)
	}
	if _, err := s.Redeem(r.ID, "lee", now); err == nil {
		t.Error("the approver received the token")
	}
	if _, err := s.Redeem(r.ID, "dana", now.Add(Redeem+time.Minute)); err == nil {
		t.Error("a token was issued days after it was approved")
	}
	if got, err := s.Redeem(r.ID, "dana", now.Add(time.Hour)); err != nil || got.State != Done {
		t.Fatalf("redeeming: %+v %v", got, err)
	}
	if _, err := s.Redeem(r.ID, "dana", now.Add(time.Hour)); err == nil {
		t.Error("a token was issued twice")
	}
	other, _ := s.Propose(Token, "x", nil, "", "dana", false, now)
	if _, err := s.Withdraw(other.ID, "lee", now); err == nil {
		t.Error("somebody else withdrew dana's request")
	}
	if got, err := s.Withdraw(other.ID, "dana", now); err != nil || got.State != Withdrawn {
		t.Errorf("withdrawing: %+v %v", got, err)
	}
}

// A group mapped to admin, or to a job that holds admin anywhere, makes
// administrators; one mapped to anything less does not. A day written after
// what a mapping grants (scim.MappedUntil) does not hide what that is.
func TestWhichMappingsMakeAdministrators(t *testing.T) {
	for to, want := range map[string]bool{
		"admin": true, "analyst": true, "compliance": true,
		"publisher": false, "reader": false, "support": false, "auditor": false,
		"approve": false, "Admin": false, "": false,
		"auditor until 2026-12-31": false, "analyst until 2026-12-31": true, "admin until soon": true,
	} {
		if got := MapsToAdministrator(to); got != want {
			t.Errorf("%q makes administrators: %v, want %v", to, got, want)
		}
	}
}

// An enrolment link is received the way a token is: approved, it waits
// for whoever asked, and only they receive it, once. Marked done on
// approval, as other kinds are, its secret would never reach anybody.
func TestAnApprovedEnrolmentLinkWaitsForWhoeverAsked(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "dual.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	r, _ := s.Propose(Enrol, "a passkey enrolment link for lee", EnrolChange{Principal: "lee"}, "", "dana", false, now)
	if r.About()["for"] != "lee" {
		t.Errorf("about: %v", r.About())
	}
	if got, _ := s.Decide(r.ID, "lee", true, false, now); got.State != Approved {
		t.Fatalf("approved: %+v", got)
	}
	if _, err := s.Redeem(r.ID, "lee", now); err == nil {
		t.Fatal("the approver received the link")
	}
	if got, err := s.Redeem(r.ID, "dana", now); err != nil || got.State != Done {
		t.Fatalf("redeem: %+v %v", got, err)
	}
	if _, err := s.Redeem(r.ID, "dana", now); err == nil {
		t.Error("a link was received twice")
	}
}

// After an administrator stops being one, the one left waits a day before
// approving alone, and a second administrator ends the wait at once.
func TestARemovedAdministratorStartsADaysWait(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "dual.json")}
	at := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	set := func(names ...string) map[string]bool {
		out := map[string]bool{}
		for _, n := range names {
			out[n] = true
		}
		return out
	}
	settling := func(now time.Time) *Removal {
		t.Helper()
		rm, err := s.Settling(now)
		if err != nil {
			t.Fatal(err)
		}
		return rm
	}

	// One administrator, and somebody else's access going: nothing waits.
	if err := s.NoteAdministrators(set("dana"), set("dana"), at); err != nil || settling(at) != nil {
		t.Fatalf("a store with one administrator waits: %v", err)
	}
	if err := s.NoteAdministrators(set("dana"), set(), at); err != nil || settling(at) != nil {
		t.Fatalf("a store that never had two waits: %v", err)
	}

	if err := s.NoteAdministrators(set("dana", "lee"), set("dana"), at); err != nil {
		t.Fatal(err)
	}
	rm := settling(at.Add(23 * time.Hour))
	if rm == nil || rm.Principal != "lee" || !rm.Until().Equal(at.Add(Settle)) {
		t.Fatalf("23 hours after lee was removed: %+v", rm)
	}
	if !strings.Contains(rm.Refusal(), "until 09:00 UTC on 4 Nov 2026") {
		t.Errorf("the refusal does not say until when: %s", rm.Refusal())
	}
	if rm := settling(at.Add(Settle)); rm != nil {
		t.Fatalf("a day after the removal, still waiting: %+v", rm)
	}

	// Two again ends it; one again starts another day.
	if err := s.NoteAdministrators(set("dana"), set("dana", "sam"), at.Add(time.Hour)); err != nil || settling(at.Add(time.Hour)) != nil {
		t.Fatalf("two administrators again, and still waiting: %v", err)
	}
	if err := s.NoteAdministrators(set("dana", "sam"), set("dana"), at.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rm := settling(at.Add(25 * time.Hour)); rm == nil || rm.Principal != "sam" {
		t.Fatalf("the second removal started no wait of its own: %+v", rm)
	}
	// The record is kept with the requests, and a request written after it
	// keeps it.
	if _, err := s.Propose(Grant, "x", nil, "", "dana", false, at.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rm := settling(at.Add(3 * time.Hour)); rm == nil {
		t.Fatal("writing a request lost the removal")
	}
}

// Whoever asked is not the second administrator for their own request
// under another spelling of their name: another case, spaces around it, or
// a mailto: in front.
func TestTheProposerIsNotTheirOwnSecondAdministratorWhateverTheSpelling(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	s := Store{Path: filepath.Join(t.TempDir(), "dual.json")}
	r, err := s.Propose(Grant, "make pat an administrator", map[string]string{"who": "pat"}, "on call", "Dana", false, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, by := range []string{"dana", " DANA ", "mailto:dana"} {
		if got, err := s.Decide(r.ID, by, true, false, now); err == nil {
			t.Fatalf("%q approved Dana's request as somebody else: %+v", by, got)
		}
	}
	got, err := s.Decide(r.ID, "mailto:dana", true, true, now)
	if err != nil || !got.Alone {
		t.Fatalf("the only administrator approving their own request: %+v %v", got, err)
	}
}

// An administrator holds a way in when a token of theirs works, or when
// one made since they became an administrator was used or was a sign-in:
// revoking it, or its running out, does not make their next one their
// first. One that stopped working unused, or from before they were an
// administrator, was never an administrator's way in.
func TestAWayInIsOneThatWorksOrWasAnAdministratorsToUse(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	granted := now.Add(-24 * time.Hour)
	pol := &auth.Policy{}
	for _, who := range []string{"ada", "theo"} {
		if err := pol.Grant(auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/", GrantedAt: granted.Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	tok := func(made, ends, used time.Time, change func(*auth.Token)) []auth.Token {
		t := auth.Token{Principal: "Theo", Role: auth.RoleAdmin, Resource: "/", CreatedAt: made.Unix(), ExpiresAt: ends.Unix()}
		if !used.IsZero() {
			t.LastUsed = used.Unix()
		}
		if change != nil {
			change(&t)
		}
		return []auth.Token{t}
	}
	hour := time.Hour
	for name, c := range map[string]struct {
		tokens []auth.Token
		want   bool
	}{
		"nothing":                        {nil, false},
		"somebody else's":                {[]auth.Token{{Principal: "ada", CreatedAt: now.Unix(), ExpiresAt: now.Add(hour).Unix()}}, false},
		"one that works, unused":         {tok(now.Add(-hour), now.Add(hour), time.Time{}, nil), true},
		"used, then revoked":             {tok(now.Add(-hour), now.Add(hour), now, func(t *auth.Token) { t.Revoked = true }), true},
		"used, then run out":             {tok(now.Add(-2*hour), now.Add(-hour), now.Add(-90*time.Minute), nil), true},
		"a sign-in that ended":           {tok(now.Add(-2*hour), now.Add(-hour), time.Time{}, func(t *auth.Token) { t.Session = true }), true},
		"run out unused":                 {tok(now.Add(-2*hour), now.Add(-hour), time.Time{}, nil), false},
		"revoked unused":                 {tok(now.Add(-hour), now.Add(hour), time.Time{}, func(t *auth.Token) { t.Revoked = true }), false},
		"used before they were made one": {tok(granted.Add(-2*hour), granted.Add(-hour), granted.Add(-90*time.Minute), nil), false},
		// An analyst's, who administered an area and was then made an
		// administrator of the site: it is the one they have acted with
		// since, and revoking it did not make their next one their first.
		"from before, used since, then revoked": {tok(granted.Add(-2*hour), now.Add(hour), now.Add(-hour), func(t *auth.Token) { t.Revoked = true }), true},
		"from before, used since, then run out": {tok(granted.Add(-2*hour), now.Add(-time.Minute), now.Add(-hour), nil), true},
		"a sign-in from before, ended":          {tok(granted.Add(-2*hour), granted.Add(-hour), time.Time{}, func(t *auth.Token) { t.Session = true }), false},
	} {
		if got := WayIn(pol, c.tokens, "theo", now); got != c.want {
			t.Errorf("%s: a way in is %v, want %v", name, got, c.want)
		}
	}
	// With no day on the grant, everything they ever used counts.
	undated := &auth.Policy{Bindings: []auth.Binding{{Principal: "theo", Role: auth.RoleAdmin, Resource: "/"}}}
	if !WayIn(undated, tok(granted.Add(-2*hour), granted.Add(-hour), granted.Add(-90*time.Minute), nil), "theo", now) {
		t.Error("a grant with no day on it let an old token go uncounted")
	}
}

// A way in is a credential its holder could approve a request with. A
// token is a ceiling, so one that carries less than an administrator's
// role, reaches only part of the site or refuses every write never made
// its holder a second administrator, however alive it is and however much
// it has been used.
//
// Any token of theirs counted. Theo, an author with a token for the command
// line, was made an administrator, and the link that would add his passkey
// then waited for a second administrator: the only other one was Theo,
// whose token is refused "this credential carries author and grant needs
// admin". So did a token narrower than his role, issued after the grant.
func TestAWayInIsOneAnAdministratorCouldApproveWith(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	pol := &auth.Policy{}
	for _, who := range []string{"ada", "theo"} {
		if err := pol.Grant(auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/",
			GrantedAt: now.Add(-24 * time.Hour).Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	held := func(change func(*auth.Token)) []auth.Token {
		// Made since the grant, used, and still working.
		t := auth.Token{Principal: "theo", Role: auth.RoleAdmin, Resource: "/", CreatedAt: now.Add(-time.Hour).Unix(),
			ExpiresAt: now.Add(time.Hour).Unix(), LastUsed: now.Add(-time.Minute).Unix()}
		change(&t)
		return []auth.Token{t}
	}
	for name, c := range map[string]struct {
		change func(*auth.Token)
		want   bool
	}{
		"an administrator's over the whole site": {func(*auth.Token) {}, true},
		"an administrator's with no path on it":  {func(t *auth.Token) { t.Resource = "" }, true},
		"an author's":                            {func(t *auth.Token) { t.Role = auth.RoleAuthor }, false},
		"a publisher's sign-in exchanged from it": {func(t *auth.Token) {
			t.Role, t.Parent = auth.RolePublisher, "parent"
		}, false},
		"an administrator's over /blog alone":    {func(t *auth.Token) { t.Resource = "/blog" }, false},
		"an administrator's that refuses writes": {func(t *auth.Token) { t.Scope = auth.Scope{ReadOnly: true} }, false},
	} {
		if got := WayIn(pol, held(c.change), "theo", now); got != c.want {
			t.Errorf("%s: a way in is %v, want %v", name, got, c.want)
		}
	}
}

// What stands in the way of somebody's first way in is the asker's
// requests they would decide, and not a way in for them: an enrolment link
// for them or a token as them, which gives the asker nothing the first way
// in does not. Counted, each ask refused alone was left waiting in the way
// of the next.
func TestAWayInForTheSubjectIsNotARequestTheyWouldDecide(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "dual.json")}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, r := range []struct {
		kind    string
		payload any
		by      string
	}{
		{Enrol, EnrolChange{Principal: "Theo"}, "ada"},
		{Token, TokenChange{Args: []string{"theo-cli", "--principal", "theo", "--role", "admin"}}, "ada"},
		{Token, TokenChange{Args: []string{"lee-cli", "--principal=lee", "--role", "admin"}}, "ada"},
		{Grant, GrantChange{Bindings: []auth.Binding{{Principal: "theo", Role: auth.RoleAdmin, Resource: "/blog"}}}, "ada"},
		{Setting, nil, "theo"},
	} {
		if _, err := s.Propose(r.kind, "x", r.payload, "", r.by, false, now); err != nil {
			t.Fatal(err)
		}
	}
	open, err := s.OpenBy("Ada", "theo", now)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range open {
		kinds = append(kinds, r.Kind+" "+r.About()["for"]+r.About()["subject"])
	}
	if want := []string{Token + " lee", Grant + " theo"}; !slices.Equal(kinds, want) {
		t.Errorf("ada's requests theo would decide are %v, want %v", kinds, want)
	}
	if late, _ := s.OpenBy("ada", "theo", now.Add(Wait+time.Minute)); len(late) != 0 {
		t.Errorf("requests that are over still stand in the way: %+v", late)
	}
}

// Single sign-on could sign somebody in when their name is one it takes:
// an address in its domains, any address when it has none, and any name at
// all when it names people by something that is not an address.
func TestWhoSingleSignOnCouldSignIn(t *testing.T) {
	for _, c := range []struct {
		sso  SingleSignOn
		name string
		want bool
	}{
		{SAML([]string{"northwind.example"}), "lee@northwind.example", true},
		{SAML([]string{"northwind.example"}), "Lee@Northwind.Example", true},
		{SAML([]string{"northwind.example"}), "lee@elsewhere.example", false},
		{SAML([]string{"northwind.example"}), "lee", false},
		{SAML(nil), "lee", true},
		{SAML(nil), "lee@anywhere.example", true},
		{OpenIDConnect("email", []string{"northwind.example"}), "lee@elsewhere.example", true},
		{OpenIDConnect("email", nil), "lee", false},
		{OpenIDConnect("", nil), "lee@northwind.example", true},
		{OpenIDConnect("preferred_username", []string{"northwind.example"}), "lee@northwind.example", true},
		{OpenIDConnect("preferred_username", []string{"northwind.example"}), "lee@elsewhere.example", false},
		{OpenIDConnect("sub", []string{"northwind.example"}), "248289761001", true},
		{OpenIDConnect("sub", nil), "lee@elsewhere.example", true},
	} {
		if got := c.sso.Covers(c.name); got != c.want {
			t.Errorf("%+v could sign %q in: %v, want %v", c.sso, c.name, got, c.want)
		}
	}
}
