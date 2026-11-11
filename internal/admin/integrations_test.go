// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// A call through the gateway that a person approves is shown with its
// arguments and decided here.
func TestAHeldGatewayCallIsDecidedOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	var decided []string
	srv.Integrations = &Integrations{
		Held: func() ([]GatewayHeld, error) {
			return []GatewayHeld{{ID: "gq_0123456789ab", Integration: "tracker", Tool: "create_issue", For: "rae",
				App: "https://app.example.com/meta", Args: `{"title":"Printer on fire"}`, Asked: time.Now()}}, nil
		},
		Decide: func(id string, approve bool, act Actor) error {
			by := act.Name
			decided = append(decided, fmt.Sprintf("%s %v %s", id, approve, by))
			return nil
		},
	}
	body := get(t, srv, "/integrations", token).Body.String()
	for _, want := range []string{"Calls waiting for a person", "gq_0123456789ab", "Printer on fire", "through https://app.example.com/meta"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen lacks %q", want)
		}
	}
	w := postForm(t, srv, "/integrations/held", token, url.Values{"id": {"gq_0123456789ab"}, "decision": {"approve"}}.Encode())
	if w.Code != http.StatusSeeOther || len(decided) != 1 || decided[0] != "gq_0123456789ab true editor" {
		t.Fatalf("%d %v", w.Code, decided)
	}
	postForm(t, srv, "/integrations/held", token, url.Values{"id": {"gq_0123456789ab"}, "decision": {"decline"}}.Encode())
	if len(decided) != 2 || decided[1] != "gq_0123456789ab false editor" {
		t.Fatalf("%v", decided)
	}
}

// An export of the audit log from the Integrations screen is recorded as
// auditlog.export, with the detail `quilzo siem` and `quilzo auditlog
// export` record, and keeps the revealed it was recorded with before.
//
// It was siem.export, with only the format, the count and revealed, so a
// rule or a filter for auditlog.export missed every export made in the
// browser, and the range the export covered was not recorded at all.
func TestAnExportFromTheScreenIsRecordedAsTheCommandLinesAre(t *testing.T) {
	srv, token := setup(t)
	dir := t.TempDir()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := l.Append(audit.Record{Action: "publish", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	srv.Integrations = &Integrations{Events: func() ([]audit.Event, error) { return events, nil }}
	var action string
	var detail map[string]string
	srv.Audit = func(a, _ string, d map[string]string) { action, detail = a, d }

	if w := postForm(t, srv, "/integrations/siem", token, "format=jsonl"); w.Code != http.StatusOK {
		t.Fatalf("the export answered %d", w.Code)
	}
	if action != "auditlog.export" {
		t.Errorf("the export was recorded as %q", action)
	}
	for k, want := range map[string]string{"format": "jsonl", "events": "3", "range": "1-3",
		"identifiers_requested": "false", "pseudonymous": "true", "revealed": "false"} {
		if detail[k] != want {
			t.Errorf("the record's %s is %q, want %q (%v)", k, detail[k], want, detail)
		}
	}
}
