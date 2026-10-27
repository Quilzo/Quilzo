// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/webhook"
)

// What the public site writes and an older version kept at the store's
// root is moved to its own directory, whole, and webhook deliveries leave
// the file that holds the endpoints. A file already in its new place is the
// one kept.
func TestTheSitesStateMovesOutOfTheStoresRoot(t *testing.T) {
	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("shield.json", `{"protections":[]}`)
	write("followers.json", `{"followers":["https://example.social/@a"]}`)
	write("model-usage.jsonl", `{"in":1}`+"\n")
	if err := saveJSON(hooksPath(root), hookFile{
		Endpoints:  []webhook.Endpoint{{URL: "https://hooks.example/q"}},
		Deliveries: []webhook.Delivery{{ID: "d1", URL: "https://hooks.example/q", Succeeded: true}},
	}); err != nil {
		t.Fatal(err)
	}
	// Already moved, and an old copy left beside it: the moved one stays.
	if err := os.MkdirAll(filepath.Join(root, "fediverse"), 0o700); err != nil {
		t.Fatal(err)
	}
	write("fediverse/announced.json", `{"commit":"new"}`)
	write("announced.json", `{"commit":"old"}`)

	if err := moveSiteState(root); err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{
		"shield.json": shield.Path(root), "followers.json": fediverseFollowersPath(root),
		"model-usage.jsonl": usagePath(root),
	} {
		if _, err := os.Stat(filepath.Join(root, from)); !os.IsNotExist(err) {
			t.Errorf("%s is still at the root: %v", from, err)
		}
		if _, err := os.Stat(to); err != nil {
			t.Errorf("%s did not reach %s: %v", from, to, err)
		}
	}
	if b, _ := os.ReadFile(fediverseAnnouncedPath(root)); string(b) != `{"commit":"new"}` {
		t.Errorf("the moved file was overwritten: %s", b)
	}
	if _, err := os.Stat(filepath.Join(root, "announced.json")); err != nil {
		t.Error("an old copy beside a moved one was removed rather than left to look at")
	}
	raw := &hookFile{}
	if err := loadJSON(hooksPath(root), raw); err != nil || len(raw.Deliveries) != 0 || len(raw.Endpoints) != 1 {
		t.Errorf("webhooks.json still holds deliveries, or lost its endpoints: %+v %v", raw, err)
	}
	f, err := loadHooks(root)
	if err != nil || len(f.Endpoints) != 1 || len(f.Deliveries) != 1 {
		t.Fatalf("the endpoints and deliveries as read: %+v %v", f, err)
	}
	// And running again changes nothing.
	if err := moveSiteState(root); err != nil {
		t.Fatal(err)
	}
	if f, _ := loadHooks(root); len(f.Deliveries) != 1 {
		t.Errorf("a second run moved the deliveries again: %+v", f.Deliveries)
	}
}
