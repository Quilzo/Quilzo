// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package enrol

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A link names one person, works once, ends, and is replaced by the next
// one for the same person; the file holds no secret anybody could use.
func TestALinkWorksOnceForOnePersonWithinADay(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	if _, _, err := s.Issue("dana", "root", MaxLife+time.Minute, now); err == nil {
		t.Error("a link longer than a day was made")
	}
	if _, _, err := s.Issue(" ", "root", time.Hour, now); err == nil {
		t.Error("a link for nobody was made")
	}
	secret, l, err := s.Issue("dana", "root", MaxLife, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, Prefix) || l.Principal != "dana" || !l.Expires.Equal(now.Add(MaxLife)) {
		t.Fatalf("%q %+v", secret, l)
	}
	if b, _ := os.ReadFile(s.Path); strings.Contains(string(b), strings.TrimPrefix(secret, Prefix)) {
		t.Fatal("the secret itself was written down")
	}
	if got, err := s.Peek(secret, now); err != nil || got.Principal != "dana" {
		t.Fatalf("peek: %+v %v", got, err)
	}
	if _, err := s.Peek(secret, now.Add(MaxLife)); !errors.Is(err, ErrNoLink) {
		t.Errorf("an ended link worked: %v", err)
	}
	if _, err := s.Take(secret, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Take(secret, now); !errors.Is(err, ErrNoLink) {
		t.Error("a link worked twice")
	}

	first, _, _ := s.Issue("lee", "root", time.Hour, now)
	second, _, _ := s.Issue("LEE", "root", time.Hour, now)
	if _, err := s.Peek(first, now); err == nil {
		t.Error("an earlier link still worked after a new one for the same person")
	}
	if _, err := s.Peek(second, now); err != nil {
		t.Errorf("the new link: %v", err)
	}
	if _, err := s.Peek("not-a-link", now); err == nil {
		t.Error("a made-up secret named a link")
	}
	if gone, _ := s.Revoke("lee", now); !gone {
		t.Error("revoking found nothing")
	}
	if waiting, _ := s.Waiting(now); len(waiting) != 0 {
		t.Errorf("links still waiting: %+v", waiting)
	}
}
