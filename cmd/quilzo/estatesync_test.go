// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/mcp"
)

// vantaStore is a store with the Vanta connector installed and a fake Vanta
// answering: Jane has left and her laptop still checks in.
func vantaStore(t *testing.T) (string, *int) {
	t.Helper()
	root := connectStore(t)
	seen := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	calls := pointConnectorsAt(t, func(w http.ResponseWriter, r *http.Request) {
		page := func(data string) string {
			return `{"results":{"data":[` + data + `],"pageInfo":{"hasNextPage":false}}}`
		}
		switch r.URL.Path {
		case "/oauth/token":
			io.WriteString(w, `{"access_token":"tok-abcdefgh","expires_in":3600}`)
		case "/v1/people":
			io.WriteString(w, page(`{"id":"p1","emailAddress":"jane@acme.com",
				"name":{"display":"Jane Doe"},"employment":{"status":"FORMER"}},
				{"id":"p2","emailAddress":"sam@acme.com","name":{"display":"Sam Okafor"},
				"employment":{"status":"CURRENT"},"tasksSummary":{"details":
				{"completeTrainings":{"status":"OVERDUE"}}}}`))
		case "/v1/monitored-computers":
			io.WriteString(w, page(`{"id":"c1","serialNumber":"FVFGPGV2Q6L5",
				"lastCheckDate":"`+seen+`","operatingSystem":{"type":"macOS"},
				"owner":{"emailAddress":"jane@acme.com"}}`))
		default:
			io.WriteString(w, page(``))
		}
	})
	if err := cmdConnect(root, []string{"add", "vanta"}); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"vanta-client-id": "vci",
		"vanta-client-secret": "vcs"} {
		t.Setenv("QUILZO_CONNECT_SECRET", v)
		if err := cmdConnect(root, []string{"secret", name}); err != nil {
			t.Fatal(err)
		}
	}
	return root, calls
}

func TestASyncReadsEveryToolAndBuilds(t *testing.T) {
	root, _ := vantaStore(t)
	// A second tool installed with no credential: reported, not skipped
	// in silence and not stopping the rest.
	if err := cmdConnect(root, []string{"add", "knowbe4"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEstate(root, []string{"sync"}); err != nil {
		t.Fatal(err)
	}
	rep, err := loadSyncReport(root)
	if err != nil || rep == nil {
		t.Fatalf("no report: %v", err)
	}
	var kb, v syncTool
	for _, tl := range rep.Tools {
		switch tl.Name {
		case "knowbe4":
			kb = tl
		case "vanta":
			v = tl
		}
	}
	if !strings.Contains(kb.Error, "no credential") {
		t.Errorf("knowbe4 without a credential: %+v", kb)
	}
	if v.Error != "" || v.Records == 0 {
		t.Errorf("vanta: %+v", v)
	}
	if rep.Found == 0 {
		t.Error("the leaver's laptop was not found by the build")
	}
	if _, err := os.Stat(filepath.Join(estateDir(root), "sync.lock")); err == nil {
		t.Error("the sync lock was left behind")
	}
}

func TestTwoSyncsDoNotOverlap(t *testing.T) {
	root, calls := vantaStore(t)
	unlock, err := lockSync(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	before := *calls
	if _, err := estateSync(root, time.Now().UTC(), &Caller{Name: "ada",
		Kind: audit.KindHuman, Verified: true}, false); err == nil ||
		!strings.Contains(err.Error(), "already running") {
		t.Errorf("a second sync started beside the first: %v", err)
	}
	if *calls != before {
		t.Error("the second sync reached the tool, and would have revoked " +
			"the first one's Vanta token")
	}
}

func TestTheScheduleSyncsWhenDueAndNotBefore(t *testing.T) {
	root, calls := vantaStore(t)
	job := estateJob(root)
	if n, err := job.Do(time.Now()); n != 0 || err != nil || *calls != 0 {
		t.Fatalf("with no schedule set the job did something: %d %v", n, err)
	}
	if err := cmdEstate(root, []string{"auto", "--every", "30m"}); err == nil {
		t.Error("a half-hourly schedule was accepted")
	}
	if err := cmdEstate(root, []string{"auto", "--every", "24h"}); err != nil {
		t.Fatal(err)
	}
	if n, err := job.Do(time.Now()); err != nil || n != 1 {
		t.Fatalf("the first tick with a schedule did not sync: %d %v", n, err)
	}
	after := *calls
	if n, _ := job.Do(time.Now().Add(time.Hour)); n != 0 || *calls != after {
		t.Error("synced again an hour after a daily sync")
	}
	if n, _ := job.Do(time.Now().Add(25 * time.Hour)); n != 1 {
		t.Error("did not sync a day later")
	}
	s, _ := loadEstateSchedule(root)
	if s.By == "" {
		t.Error("the schedule does not say on whose authority it runs")
	}
	if err := cmdEstate(root, []string{"auto", "--off"}); err != nil {
		t.Fatal(err)
	}
	before := *calls
	job.Do(time.Now().Add(72 * time.Hour))
	if *calls != before {
		t.Error("synced after the schedule was turned off")
	}
}

func TestAnAgentGetsTheEstateInNumbersOnly(t *testing.T) {
	root, _ := vantaStore(t)
	if err := cmdEstate(root, []string{"sync"}); err != nil {
		t.Fatal(err)
	}
	srv := mcp.NewServer("quilzo", "test")
	srv.Authorise = func(mcp.Operation) error { return nil }
	registerEstateOps(srv, root, &Caller{Name: "dana", Kind: audit.KindHuman,
		Verified: true})
	text, merr := callTool(t, srv, "quilzo_read", "estate_summary", nil)
	if merr != nil {
		t.Fatal(merr.Message)
	}
	for _, private := range []string{"Jane", "jane@", "Sam", "sam@acme",
		"p1", "FVFGPGV2Q6L5"} {
		if strings.Contains(text, private) {
			t.Errorf("the summary names %q", private)
		}
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("not JSON: %s", text)
	}
	if got["people"] != float64(2) || got["leavers_with_live_devices"] != float64(1) {
		t.Errorf("summary: %s", text)
	}
}
