// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// bundleTemplates is a template directory of one layout, for rendering a
// copy of the site.
func bundleTemplates(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "page.html"),
		[]byte(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body><h1>{{ page.title }}</h1></body></html>`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An agent card that does not validate leaves the site without a card, not
// without a copy.
//
// The builder handed a card that failed validation back as an error, the
// public server answered that with 500, and the static copy refuses any
// optional address that answers neither 200 nor 404. So turning the card on
// for a site whose address is not https yet — any site before its
// certificate — failed `quilzo ipfs id`, `ipfs write` and the content_id
// tool alike, with a message about the card.
func TestAnAgentCardThatDoesNotValidateDoesNotStopACopy(t *testing.T) {
	root := publishedShop(t)
	tpl := bundleTemplates(t)
	if err := cmdConfig(root, []string{"set", "site.agent_card", "true"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "site.base_url", "http://marginalia.example"}); err != nil {
		t.Fatal(err)
	}
	files, err := renderBundle(root, tpl)
	if err != nil {
		t.Fatalf("a card that does not validate stopped the copy: %v", err)
	}
	if _, ok := files[".well-known/agent-card.json"]; ok {
		t.Error("a card that does not validate went into the copy")
	}

	// At an https address the card validates, and is copied.
	if err := cmdConfig(root, []string{"set", "site.base_url", "https://marginalia.example"}); err != nil {
		t.Fatal(err)
	}
	if files, err = renderBundle(root, tpl); err != nil {
		t.Fatal(err)
	}
	if _, ok := files[".well-known/agent-card.json"]; !ok {
		t.Error("a valid card is missing from the copy")
	}
}
