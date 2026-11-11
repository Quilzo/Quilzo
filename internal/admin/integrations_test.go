// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/siem"
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

// siemLog is a genuine chain kept with a key, as every log this program
// keeps is.
func siemLog(t *testing.T) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	key, _ := audit.NewKey()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Key: key, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range []string{"/a", "/b", "/c"} {
		if _, err := l.Append(audit.Record{Action: "publish", Resource: res, Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// The page says the export carries an envelope so the receiver can check
// nothing was added or dropped, and the download held the events alone: the
// envelope was computed and thrown away. Ticking "Show identifiers" on a log
// that holds pseudonyms, which is every log this program keeps, changed
// nothing in the export, and the envelope said the export was not
// pseudonymous while every principal in it was a pseudonym, and the log
// recorded revealed=true. The download now carries its envelope unless it is
// asked not to, and what is recorded is what happened.
func TestTheSIEMDownloadCarriesItsEnvelopeAndSaysWhatItReveals(t *testing.T) {
	srv, token := setup(t)
	events := siemLog(t)
	srv.Integrations = &Integrations{Events: func() ([]audit.Event, error) { return events, nil }}
	var recorded []map[string]string
	srv.Audit = func(action, resource string, d map[string]string) {
		if action == "siem.export" {
			recorded = append(recorded, d)
		}
	}

	page := get(t, srv, "/integrations", token).Body.String()
	if !strings.Contains(page, `name="envelope" value="1" checked`) {
		t.Errorf("the export form does not offer the envelope, ticked")
	}

	w := postForm(t, srv, "/integrations/siem", token, "format=jsonl&envelope=1&reveal=1")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("an export with its envelope answered %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name], _ = io.ReadAll(r)
		r.Close()
	}
	var env siem.Envelope
	if err := json.Unmarshal(files["envelope.json"], &env); err != nil {
		t.Fatalf("no envelope in the download (%v): %v", keysOf(files), err)
	}
	var exported []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(files["audit-jsonl.log"])), "\n") {
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("the export is not JSON Lines of events: %v", err)
		}
		exported = append(exported, e)
	}
	if err := siem.VerifyEnvelope(exported, env); err != nil {
		t.Errorf("the download does not verify against its own envelope: %v", err)
	}
	if !env.Pseudonymous {
		t.Error("asking for identifiers on a pseudonymous log made the envelope say the export is not pseudonymous")
	}
	if len(recorded) != 1 || recorded[0]["revealed"] != "false" || recorded[0]["identifiers_requested"] != "true" ||
		recorded[0]["pseudonymous"] != "true" || recorded[0]["range"] != "1-3" {
		t.Errorf("the export was recorded as %v", recorded)
	}

	// Without the envelope, one file, as before.
	w = postForm(t, srv, "/integrations/siem", token, "format=jsonl")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" ||
		strings.Count(strings.TrimSpace(w.Body.String()), "\n") != 2 {
		t.Errorf("an export without its envelope answered %d %q:\n%s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
