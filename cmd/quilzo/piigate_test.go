// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

// A card number or a credential on a draft page stops the publish, wherever
// on the page it sits, and the refusal does not repeat it; an email address
// is advice, and the site's own and the documentation's examples are not
// even that.
func TestPersonalDataIsCaughtBeforeItIsPublic(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	draft := func(pages map[string]any) {
		t.Helper()
		if _, err := site.SaveDraft(s, pages, "draft", "test"); err != nil {
			t.Fatal(err)
		}
	}
	run := func() (string, string) {
		t.Helper()
		refused, advice, err := contentGates(root, s, "").Run()
		if err != nil {
			t.Fatal(err)
		}
		r := ""
		if refused != nil {
			r = refused.Check.Name + ": " + refused.Error()
		}
		var a []string
		for _, f := range advice {
			a = append(a, f.String())
		}
		return r, strings.Join(a, "\n")
	}

	draft(map[string]any{"refund": map[string]any{
		"title": "Your refund",
		"sections": []any{map[string]any{"kind": "prose",
			"body": "Refunded to the card 4539 1488 0343 6467, as jane.doe@gmail.com asked."}},
	}})
	refused, advice := run()
	if !strings.HasPrefix(refused, "personal data") || !strings.Contains(refused, "ending 6467") {
		t.Fatalf("a card number in a section published: %q", refused)
	}
	if strings.Contains(refused, "4539") || strings.Contains(refused, "1488 0343") {
		t.Fatalf("the refusal repeats the number: %q", refused)
	}
	if !strings.Contains(advice, "j…@gmail.com") {
		t.Fatalf("the customer's address was not mentioned: %q", advice)
	}

	draft(map[string]any{"setup": map[string]any{
		"title": "Setting up",
		"body":  "Then paste sk-proj-Ab3_kL9-mN2pQ7rS1tU4vW8xY0zA5bC6dE into the box.",
	}})
	if refused, _ := run(); !strings.HasPrefix(refused, "personal data") {
		t.Fatalf("a credential on a page published: %q", refused)
	}

	draft(map[string]any{"docs": map[string]any{
		"title": "Testing payments",
		"body": "Use 4242 4242 4242 4242, the IBAN GB82 WEST 1234 5698 7654 32, " +
			"the key AKIAIOSFODNN7EXAMPLE, and write to support@example.com.",
	}})
	if refused, advice := run(); refused != "" || advice != "" {
		t.Fatalf("documentation's own examples were treated as somebody's: %q / %q", refused, advice)
	}
}
