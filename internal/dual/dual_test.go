// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package dual

import (
	"path/filepath"
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
