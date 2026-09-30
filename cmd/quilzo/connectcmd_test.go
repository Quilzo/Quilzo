// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/out"
)

func connectStore(t *testing.T) string {
	t.Helper()
	old := w
	w = out.New(true)
	t.Cleanup(func() { w = old })
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestAShippedConnectorInstallsAsAReadableFileForItsRegion(t *testing.T) {
	root := connectStore(t)
	if err := cmdConnect(root, []string{"add", "knowbe4", "--region", "eu"}); err != nil {
		t.Fatal(err)
	}
	m, err := readManifest(filepath.Join(connectDir(root), "knowbe4.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("the installed file does not load: %v", err)
	}
	if m.Host != "eu.api.knowbe4.com" {
		t.Errorf("an EU account was pointed at %s, which answers 401 or "+
			"nothing for it", m.Host)
	}
	if err := cmdConnect(root, []string{"add", "knowbe4"}); err == nil {
		t.Error("adding it again replaced the file without --replace")
	}
	if err := cmdConnect(root, []string{"add", "knowbe4", "--region",
		"evil.example.com", "--replace"}); err == nil {
		t.Error("a hostname was accepted as a region")
	}
	if err := cmdConnect(root, []string{"add", "nosuchtool"}); err == nil {
		t.Error("a connector that does not ship was installed")
	}
	info, _ := os.Stat(filepath.Join(connectDir(root), "knowbe4.json"))
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("the connector file is %v", info.Mode().Perm())
	}
}

// route sends every host a manifest names to one local server.
type toLocal struct{ base *url.URL }

func (d toLocal) Do(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme, u.Host = d.base.Scheme, d.base.Host
	fresh, err := http.NewRequestWithContext(req.Context(), req.Method,
		u.String(), req.Body)
	if err != nil {
		return nil, err
	}
	fresh.Header = req.Header.Clone()
	return http.DefaultClient.Do(fresh)
}

func pointConnectorsAt(t *testing.T, h http.HandlerFunc) *int {
	t.Helper()
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		calls++
		h(w, r)
	}))
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	old := connectDoer
	connectDoer = func(time.Duration) connector.Doer { return toLocal{u} }
	t.Cleanup(func() { connectDoer = old })
	return &calls
}

func installManifest(t *testing.T, root string, m connector.Manifest) {
	t.Helper()
	os.MkdirAll(connectDir(root), 0o700)
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(connectDir(root), m.Name+".json"),
		b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_CONNECT_SECRET", "k3y")
	if err := cmdConnect(root, []string{"secret", m.Auth.Secret}); err != nil {
		t.Fatal(err)
	}
}

// The daily budget holds across runs, not only within one.
func TestADailyLimitIsKeptAcrossRuns(t *testing.T) {
	root := connectStore(t)
	calls := pointConnectorsAt(t, func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Query().Get("page")
		fmt.Fprintf(w, `[{"id":"%s"}]`, p)
	})
	installManifest(t, root, connector.Manifest{
		Name: "kb", Tool: "KnowBe4", Host: "us.api.knowbe4.com",
		Auth: connector.Auth{Kind: connector.Bearer, Secret: "kb-key"},
		Rate: connector.Rate{PerDay: 3},
		Endpoints: []connector.Endpoint{{Name: "users", Path: "/v1/users",
			Produces: connector.Identities, Reads: []string{"id"},
			Map: map[string]string{"id": "id"},
			Page: connector.Pagination{Kind: connector.PageNumber,
				Param: "page", Size: 1}}},
	})

	// Two pages of an endless list, then the day is spent.
	if err := cmdConnect(root, []string{"run", "kb"}); err != nil {
		t.Fatal(err)
	}
	if *calls != 3 {
		t.Fatalf("the first run sent %d requests with a day of 3", *calls)
	}
	if err := cmdConnect(root, []string{"run", "kb"}); err == nil ||
		!strings.Contains(err.Error(), "tomorrow") {
		t.Errorf("a second run on a spent day: %v", err)
	}
	if *calls != 3 {
		t.Errorf("a spent day still sent %d more", *calls-3)
	}
	budgets, _ := loadBudgets(root)
	if budgets["kb"].Used != 3 {
		t.Errorf("recorded %+v", budgets["kb"])
	}
	// A new day starts again.
	budgets["kb"] = dayBudget{Day: "2000-01-01", Used: 3}
	saveBudgets(root, budgets)
	if err := cmdConnect(root, []string{"run", "kb"}); err != nil {
		t.Fatal(err)
	}
	if *calls != 6 {
		t.Errorf("yesterday's use held back today: %d calls", *calls)
	}
}

// Asking for a per-device endpoint reads the devices first, and the
// checkpoint of an endpoint read per record is never saved as one number.
func TestRunningAPerRecordEndpointReadsItsParentFirst(t *testing.T) {
	root := connectStore(t)
	pointConnectorsAt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/devices" {
			fmt.Fprint(w, `{"devices":[{"id":"7"}]}`)
			return
		}
		fmt.Fprint(w, `{"apps":[{"name":"Slack"}]}`)
	})
	installManifest(t, root, connector.Manifest{
		Name: "mdm", Tool: "MDM", Host: "mdm.example.com",
		Auth: connector.Auth{Kind: connector.Bearer, Secret: "mdm-key"},
		Endpoints: []connector.Endpoint{
			{Name: "devices", Path: "/devices", Produces: connector.Identities,
				Records: "devices", Reads: []string{"id"},
				Map: map[string]string{"id": "id"}},
			{Name: "apps", Path: "/devices/{key}/apps",
				Produces: connector.Software, Records: "apps",
				Reads: []string{"name"}, Map: map[string]string{"app": "name"},
				Each: &connector.Each{Of: "devices", Key: "id"}},
		},
	})
	if err := cmdConnect(root, []string{"run", "mdm", "apps"}); err != nil {
		t.Fatal(err)
	}
	states, _ := loadStates(root)
	if _, ok := states["mdm/apps"]; ok {
		t.Error("a per-record endpoint saved a checkpoint")
	}
}
