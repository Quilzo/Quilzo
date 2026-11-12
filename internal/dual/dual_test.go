// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package dual

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
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
