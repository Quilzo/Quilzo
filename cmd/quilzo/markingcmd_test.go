// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// markedStore is a store whose draft holds a page marked above the
// deployment's banner, and whose live publication holds an unmarked one.
func markedStore(t *testing.T) (string, *store.Store) {
	t.Helper()
	root := connectStore(t)
	for _, kv := range [][2]string{
		{"marking.levels", "OFFICIAL,SECRET"},
		{"marking.banner", "OFFICIAL"},
	} {
		if err := cmdConfig(root, []string{"set", kv[0], kv[1]}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"},
		"plans": map[string]any{"title": "Plans", "classification": "SECRET"},
	}, "second", "test"); err != nil {
		t.Fatal(err)
	}
	if err := checkMarking(root, s, ""); err == nil {
		t.Fatal("a page marked SECRET under an OFFICIAL banner was let through " +
			"with the configuration readable; the test proves nothing")
	}
	return root, s
}

// breakConfig leaves the configuration unreadable, as a hand edit that
// does not parse does.
func breakConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(configPath(root), []byte(`{"marking.banner": `), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(root); err == nil {
		t.Fatal("the configuration still reads")
	}
}

// The classification gate is in the set that says nothing in it is
// waivable, and it returned nil when the configuration could not be read:
// "a store with no config marks nothing". A missing file already reads as
// the defaults; an unreadable one is not missing, it is a scheme nobody can
// see, and a page marked above the banner went through.
func TestAnUnreadableConfigurationRefusesThePublication(t *testing.T) {
	root, s := markedStore(t)
	breakConfig(t, root)
	err := checkMarking(root, s, "")
	if err == nil {
		t.Fatal("the configuration could not be read and the classification " +
			"gate let the publication through")
	}
	if !strings.Contains(err.Error(), "configuration") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}
	// The gate set, which is what every surface asks.
	blocking, _, gerr := contentGates(root, s, "")[0].Run()
	if gerr == nil && len(blocking) == 0 {
		t.Error("the classification gate passed with the configuration unreadable")
	}
}

// The same gate let a publication through when the pages it was asked
// about could not be read: nothing was checked, and nothing was refused.
func TestAPublicationWhosePagesCannotBeReadIsRefused(t *testing.T) {
	root, s := markedStore(t)
	missing := strings.Repeat("ab", 32)
	if err := checkMarking(root, s, missing); err == nil {
		t.Fatal("a publication whose pages could not be read passed the " +
			"classification gate")
	}
}

// The other places that read the scheme for themselves did the same: an
// export and a static site went out with no banner, and a transfer record
// carried none, when the configuration could not be read. A file with no
// marking does not look like one whose marking was lost.
func TestNothingLeavesUnmarkedWhenTheConfigurationCannotBeRead(t *testing.T) {
	root, _ := markedStore(t)
	breakConfig(t, root)

	if err := cmdExport(root, []string{"--to", filepath.Join(t.TempDir(), "out")}); err == nil {
		t.Error("an export was written with the configuration unreadable, " +
			"so with no banner")
	}

	carried := t.TempDir()
	if err := os.WriteFile(filepath.Join(carried, "index.md"), []byte("Home"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transferRecord(root, []string{carried, "--approved-by", "ada",
		"--carried-by", "bo", "--reason", "release"}); err == nil {
		t.Error("a transfer was recorded with the configuration unreadable, " +
			"so with no banner")
	}

	if _, err := siteFor(root, &Design{Layouts: render.OneLayout(`<!doctype html><title>x</title>`)},
		siteOpts{}); err == nil {
		t.Error("the site was built with the configuration unreadable, so " +
			"with no banner on any page")
	}
}

// A scheme that does not parse is refused in a transfer record, as it is
// in an export: the record carried no banner and said nothing.
func TestATransferRecordRefusesASchemeThatDoesNotParse(t *testing.T) {
	root, _ := markedStore(t)
	if err := cmdConfig(root, []string{"set", "marking.banner", "TOP SECRET"}); err == nil {
		// The setting may refuse it itself; then write it as a hand edit would.
		t.Log("the setting accepted a banner outside the levels")
	} else {
		raw, rerr := os.ReadFile(configPath(root))
		if rerr != nil {
			t.Fatal(rerr)
		}
		edited := strings.Replace(string(raw), `"OFFICIAL"`, `"TOP SECRET"`, 1)
		if edited == string(raw) {
			t.Fatalf("cannot find the banner to edit in %s", raw)
		}
		if err := os.WriteFile(configPath(root), []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := markingFrom(cfg); err == nil {
		t.Fatal("the scheme still parses; the test proves nothing")
	}
	carried := t.TempDir()
	if err := os.WriteFile(filepath.Join(carried, "index.md"), []byte("Home"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transferRecord(root, []string{carried, "--approved-by", "ada",
		"--carried-by", "bo", "--reason", "release"}); err == nil {
		t.Error("a transfer was recorded under a scheme that does not parse, " +
			"so with no banner")
	}
}

// `quilzo export` puts the deployment's banner on every file it writes,
// because an export is the copy that ends up on removable media. The same
// export over the machine interface (export_site) carried none, scheme or
// no scheme, and said nothing when the scheme could not be read.
func TestAnExportOverMCPCarriesTheBanner(t *testing.T) {
	root := connectStore(t)
	for _, kv := range [][2]string{
		{"marking.levels", "OFFICIAL,SECRET"},
		{"marking.banner", "OFFICIAL"},
	} {
		if err := cmdConfig(root, []string{"set", kv[0], kv[1]}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	call := mcpAs(t, root, withRole("dana", auth.RoleAdmin))
	if got := call("quilzo_read", "export_site", nil); refused(got) || !strings.Contains(got, "OFFICIAL") {
		t.Errorf("an export over MCP carries no banner: %s", got)
	}
	breakConfig(t, root)
	if got := call("quilzo_read", "export_site", nil); !refused(got) {
		t.Errorf("an export over MCP went out with the configuration unreadable, so "+
			"with no banner: %s", got)
	}
}
