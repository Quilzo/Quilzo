// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/site"
)

// Promoting into production is publishing, and takes every check that
// publishing takes.
//
// It took none. On a fresh store with `review require 1` and no
// provenance, `quilzo publish` refused, and `quilzo env promote draft
// production` put the draft live; with a staging environment, the draft
// went to staging unchecked (staging is not public) and from there to
// production the same way.
func TestPromotingIntoProductionTakesThePublishChecks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := newStoreWithDraft(t)
	if err := cmdReview(root, []string{"require", "1"}); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := runPublish(t, root, "--no-a11y-check"); err == nil {
		t.Fatal("control: publish did not refuse")
	}
	_ = cmdEnv(root, []string{"promote", "draft", "production"})
	if live := s.GetRef(site.RefLive); live != "" {
		t.Fatal("env promote draft production put an unchecked draft live")
	}

	if err := cmdEnv(root, []string{"add", "staging", "--before", "production"}); err != nil {
		t.Fatal(err)
	}
	// Staging is not what the public sees, so the draft goes there as
	// before, to be looked at.
	if err := cmdEnv(root, []string{"promote", "draft", "staging"}); err != nil {
		t.Fatal(err)
	}
	if s.GetRef("env-staging") != s.GetRef(site.RefDraft) {
		t.Fatal("the draft did not reach staging")
	}
	_ = cmdEnv(root, []string{"promote", "staging", "production", "--no-a11y-check"})
	_ = cmdEnv(root, []string{"promote", "draft", "production", "--skip", "--no-a11y-check"})
	if live := s.GetRef(site.RefLive); live != "" {
		t.Fatal("an unchecked draft reached production by way of staging")
	}
}

// The checks are about the commit being promoted, not about the draft: an
// approval names the bytes it agreed to. And a promotion that passes them
// publishes as publishing does, telling the webhooks and the agents.
func TestPromotionIsCheckedOnWhatItPromotes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	page := t.TempDir() + "/p.json"
	if err := os.WriteFile(page, []byte(`{"title":"T","body":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "index=" + page, "-m", "first"},
		{"provenance", "set", "index", "--source", "humanEdits", "--author", "dana"},
	} {
		if err := runCmd(t, root, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdReview(root, []string{"require", "1"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEnv(root, []string{"add", "staging", "--before", "production"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEnv(root, []string{"promote", "draft", "staging"}); err != nil {
		t.Fatal(err)
	}
	s, _ := open(root)
	staged := s.GetRef("env-staging")

	// The draft moves on, and the later draft is approved; what is in
	// staging never was.
	if err := runCmd(t, root, "add", "about="+page, "-m", "second"); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, root, "provenance", "set", "about", "--source", "humanEdits", "--author", "dana"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdReview(root, []string{"approve"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdEnv(root, []string{"promote", "staging", "production", "--no-a11y-check"}); err == nil ||
		s.GetRef(site.RefLive) == staged {
		t.Fatal("staging went live on the approval of a different draft")
	}

	// The approved draft, through staging, goes live and is told.
	if err := cmdEnv(root, []string{"promote", "draft", "staging"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEnv(root, []string{"promote", "staging", "production", "--no-a11y-check"}); err != nil {
		t.Fatal(err)
	}
	live := s.GetRef(site.RefLive)
	if live == "" || live != s.GetRef("env-staging") {
		t.Fatalf("live is %q after an approved promotion", live)
	}
	evs, _, err := adminEvents(root).Read(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	told := false
	for _, e := range evs {
		told = told || (e.Type == event.PagePublished && e.Commit == live)
	}
	if !told {
		t.Error("promoting into production told nobody it was published")
	}
}

// Promoting what production already holds moves nothing, so nothing is
// published and no check about publishing applies: it says so and
// succeeds, as it did before promotion into production became publishing.
// Routed through publishing whole, it did not. Once a store required an
// approval, a pipeline that promoted staging again after staging had gone
// live was refused, on the approval of the version already live.
func TestPromotingWhatProductionHoldsMovesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, _ := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	page := t.TempDir() + "/p.json"
	if err := os.WriteFile(page, []byte(`{"title":"T","body":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "index=" + page, "-m", "first"},
		{"provenance", "set", "index", "--source", "humanEdits", "--author", "dana"},
	} {
		if err := runCmd(t, root, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"add", "staging", "--before", "production"},
		{"promote", "draft", "staging"},
		{"promote", "staging", "production", "--no-a11y-check"},
	} {
		if err := cmdEnv(root, args); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := open(root)
	live := s.GetRef(site.RefLive)
	if live == "" || live != s.GetRef("env-staging") {
		t.Fatalf("control: staging did not go live: %q", live)
	}
	if err := cmdReview(root, []string{"require", "1"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEnv(root, []string{"promote", "staging", "production", "--no-a11y-check"}); err != nil {
		t.Fatalf("promoting what production already holds was refused: %v", err)
	}
	if s.GetRef(site.RefLive) != live {
		t.Fatal("promoting what production already holds moved it")
	}
}
