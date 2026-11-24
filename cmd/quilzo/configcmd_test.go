// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
)

// `quilzo config` says a duration in the largest whole unit it is, as the
// Settings screen does, and takes one in days.
//
// show, list and explain printed what the file holds, so the access
// review's ninety days was "default 2160h" and a token's thirty was 720h,
// and `config set access.review.every 60d` was refused as not a duration.
func TestConfigSaysAndTakesDurationsInDays(t *testing.T) {
	root := demoStore(t)
	if err := cmdConfig(root, []string{"set", "token.ttl.max", "720h"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "access.review.every", "60d"}); err != nil {
		t.Fatalf("sixty days was refused: %v", err)
	}
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"show"}, []string{"token.ttl.max              30d", "default 90d", "access.review.every        60d"}},
		{[]string{"list"}, []string{"access.review.every          90d"}},
		{[]string{"explain", "access.review.every"}, []string{"default 90d"}},
		// Last, as it puts the setting back: it said "back to its default,
		// 2160h" just after `config list` called that default 90d.
		{[]string{"unset", "access.review.every"}, []string{"back to its default, 90d"}},
	} {
		got, err := humanOutput(t, func() error { return cmdConfig(root, c.args) })
		if err != nil {
			t.Fatalf("config %v: %v", c.args, err)
		}
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("config %v does not say %q:\n%s", c.args, want, got)
			}
		}
		if strings.Contains(got, "2160h") || strings.Contains(got, "720h") {
			t.Errorf("config %v still says a whole number of days in hours:\n%s", c.args, got)
		}
	}
}

// A token longer than token.ttl.max is refused with the ceiling said as
// `config show` says it, and the command to raise it given in the same
// form.
//
// The message printed both durations with time.Duration's String, so a
// hundred-day token was "a 2400h0m0s token is longer than token.ttl.max
// (2160h0m0s)", about a setting `config show` calls 90d, and the command
// it offered was `quilzo config set token.ttl.max 2400h0m0s`.
func TestATokenOverTheCeilingIsRefusedInDays(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	err := tokenIssue(root, []string{"long", "--principal", "lee", "--role", "reader", "--ttl", "2400h"})
	if err == nil {
		t.Fatal("control: a hundred-day token was issued under a ninety-day ceiling")
	}
	for _, want := range []string{"a 100d token is longer than token.ttl.max (90d)", "quilzo config set token.ttl.max 100d"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "0m0s") {
		t.Errorf("the refusal says a duration as time.Duration's String does:\n%v", err)
	}
}

// `config list` names each section once, with every setting of it beneath.
//
// It printed a heading whenever the section changed from the setting
// before, in the order the settings are declared, and they are not declared
// section by section: "agents" came twice, "site" three times and "admin"
// four, so somebody looking for the agents' settings found half of them and
// stopped.
func TestConfigListNamesEachSectionOnce(t *testing.T) {
	got, err := humanOutput(t, configList)
	if err != nil {
		t.Fatal(err)
	}
	seen, settings := map[string]int{}, 0
	section := ""
	for _, line := range strings.Split(got, "\n") {
		switch {
		case line != "" && !strings.HasPrefix(line, " "):
			section = strings.TrimSpace(line)
			seen[section]++
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   "):
			key, _, _ := strings.Cut(strings.TrimSpace(line), " ")
			if g, _, _ := strings.Cut(key, "."); strings.Contains(key, ".") && g != section {
				t.Errorf("%s is listed under %q", key, section)
			}
			if strings.Contains(key, ".") {
				settings++
			}
		}
	}
	for s, n := range seen {
		if n > 1 {
			t.Errorf("the section %q is headed %d times", s, n)
		}
	}
	if settings != len(config.All()) {
		t.Errorf("%d settings are listed of %d", settings, len(config.All()))
	}
}
