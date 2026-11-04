// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
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
