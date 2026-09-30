// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
)

// From two real connectors to the findings register, and back out again
// when the thing stops being true.
func TestTheEstateFindsWhatTwoToolsDisagreeOnAndLetsItGo(t *testing.T) {
	root := connectStore(t)
	seen := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	removed := false
	pointConnectorsAt(t, func(w http.ResponseWriter, r *http.Request) {
		page := func(data string) string {
			return `{"results":{"data":[` + data + `],"pageInfo":{"hasNextPage":false,"endCursor":"x"}}}`
		}
		switch r.URL.Path {
		case "/oauth/token", "/oauth/v2/token":
			io.WriteString(w, `{"access_token":"1000.abcdef.123456","expires_in":3600}`)
		case "/v1/people":
			io.WriteString(w, page(`{"id":"p1","emailAddress":"jane@acme.com",
				"name":{"display":"Jane Doe"},"employment":{"status":"FORMER"}}`))
		case "/v1/monitored-computers":
			io.WriteString(w, page(`{"id":"c1","serialNumber":"FVFGPGV2Q6L5",
				"lastCheckDate":"`+seen+`","diskEncryption":{"outcome":"PASS"},
				"operatingSystem":{"type":"windows"},
				"owner":{"emailAddress":"jane@acme.com"}}`))
		case "/v1/tests", "/v1/policies":
			io.WriteString(w, page(``))
		case "/dcapi/inventory/viewData/scanComputers":
			status := ""
			if removed {
				// Wiped and gone from the endpoint manager, and Vanta's
				// agent stops reporting it too (below).
				io.WriteString(w, `{"messageResponse":[],"Links":{"next":null}}`)
				return
			}
			fmt.Fprintf(w, `{"messageResponse":[{"resource_id":"301",
				"servicetag":"fvfgpgv2-q6l5","os_name":"Windows 11",
				"agent_last_contact_time":"%d"%s}],"Links":{"next":null}}`,
				time.Now().Add(-time.Hour).UnixMilli(), status)
		case "/dcapi/inventory/computers/301/diskEncryptionStatus":
			io.WriteString(w, `{"diskEncryptionStatusDetails":[{"logicalDriveName":"C:",
				"encryptionStatus":"Not Encrypted","logicalDiskType":"Primary"}]}`)
		case "/dcapi/inventory/computers/301/assetSummary":
			io.WriteString(w, `{"missingPatchesCount":2}`)
		case "/dcapi/inventory/computers/301/softwareInfo":
			io.WriteString(w, `{"data":[],"links":{"next":null}}`)
		case "/dcapi/threats/systemreport/vulnerabilities":
			io.WriteString(w, `{"message_response":{"systemreport":[]}}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	for _, c := range []string{"vanta", "endpointcentral"} {
		if err := cmdConnect(root, []string{"add", c}); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{
		"vanta-client-id": "vci", "vanta-client-secret": "vcs",
		"zoho-client-id": "1000.C", "zoho-client-secret": "zs",
		"endpointcentral-refresh-token": "1000.r"} {
		t.Setenv("QUILZO_CONNECT_SECRET", value)
		if err := cmdConnect(root, []string{"secret", name}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() {
		t.Helper()
		for _, c := range []string{"vanta", "endpointcentral"} {
			if err := cmdConnect(root, []string{"run", c, "--save"}); err != nil {
				t.Fatalf("%s: %v", c, err)
			}
		}
	}
	read()
	for _, f := range []string{"vanta.jsonl", "endpointcentral.json"} {
		info, err := os.Stat(filepath.Join(toolsDir(root), f))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s, which holds people's records, is %v", f,
				info.Mode().Perm())
		}
	}
	if err := cmdEstate(root, []string{"build"}); err != nil {
		t.Fatal(err)
	}
	reg, _, err := finding.Load(findingsPath(root))
	if err != nil {
		t.Fatal(err)
	}
	bySource := map[string]finding.Finding{}
	for _, f := range reg.All(time.Now()) {
		bySource[f.Source] = f
	}
	leaver, ok := bySource["estate/leaver-device"]
	if !ok || !strings.Contains(leaver.Title, "Jane Doe") {
		t.Fatalf("the leaver's laptop was not raised: %v", bySource)
	}
	enc, ok := bySource["estate/encryption-disagrees"]
	if !ok || !strings.Contains(enc.Title, "encrypted according to vanta") {
		t.Errorf("Vanta's pass beside an unencrypted C: was not raised: %v",
			bySource)
	}

	// The laptop is wiped: gone from the endpoint manager, and quiet in
	// Vanta for two months.
	removed = true
	seen = time.Now().UTC().AddDate(0, -2, 0).Format(time.RFC3339)
	read()
	if err := cmdEstate(root, []string{"build"}); err != nil {
		t.Fatal(err)
	}
	reg, _, _ = finding.Load(findingsPath(root))
	f, _ := reg.Get(leaver.ID)
	if f.State != finding.Stale {
		t.Errorf("the leaver finding is %s after the laptop went quiet; "+
			"stale is what a finding no longer reported is", f.State)
	}
}
