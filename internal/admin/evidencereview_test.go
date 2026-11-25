// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
)

var reHidden = regexp.MustCompile(`<input type="hidden" name="([a-z]+)" value="([^"]*)">`)

// hiddenFields is what a page's form sends without the person typing it.
func hiddenFields(body string) url.Values {
	out := url.Values{}
	for _, m := range reHidden.FindAllStringSubmatch(body, -1) {
		out.Set(m[1], html.UnescapeString(m[2]))
	}
	return out
}

// What is written is what the person was shown. A column map changed by
// somebody else between the preview and the press of the button would
// have had the button write facts nobody looked at, as the person who
// pressed it; the import is refused instead, and says to look again.
func TestConfirmWritesWhatWasPreviewed(t *testing.T) {
	srv, token := setup(t)
	recording(t)
	reg := register.Open(srv.Store)
	evidence.Recorder(reg)
	by := register.Actor{Name: "editor", Kind: audit.KindHuman, Verified: true, May: func(auth.Action, string) error { return nil }}
	m := register.ColumnMap{Name: "laptops", Makes: "Observation", Format: "csv",
		Columns: []register.MapColumn{{Field: "about", Column: "Serial", Asset: "device"}},
		Facts:   []register.MapFact{{Fact: "disk.encrypted", Column: "Encrypted"}, {Fact: "owner.label", Column: "Owner"}}}
	if _, err := reg.Put(by, "a column map, confirmed", m); err != nil {
		t.Fatal(err)
	}
	csv := []byte("Serial,Encrypted,Owner\nC02X1,true,ann\nC02X2,false,bob\n")
	w := postFile(t, srv, token, evidenceImportPath, "laptops.csv", csv, map[string]string{"format": "csv", "map": "laptops"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<h1>Check what the file would write</h1>") {
		t.Fatalf("the preview answered %d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
	form := hiddenFields(w.Body.String())

	swapped := m
	swapped.Facts = []register.MapFact{{Fact: "disk.encrypted", Column: "Owner"}, {Fact: "owner.label", Column: "Encrypted"}}
	if _, err := reg.Put(by, "the column map, changed", swapped); err != nil {
		t.Fatal(err)
	}
	done := postForm(t, srv, "/evidence/import/confirm", token, form.Encode())
	if done.Code != http.StatusUnprocessableEntity || !strings.Contains(done.Body.String(), "look at what it would write again") {
		t.Fatalf("confirming after the map changed answered %d\n%s", done.Code, firstLines(done.Body.String(), 30))
	}
	accessible(t, "/evidence/import/confirm (changed)", done.Body.String())
	if counts, _ := reg.Counts(); counts[register.KindObservation] != 0 {
		t.Fatalf("facts nobody was shown were written: %v", counts)
	}

	// Shown again, through the map as it is now, the press writes it.
	again := postFile(t, srv, token, evidenceImportPath, "laptops.csv", csv, map[string]string{"format": "csv", "map": "laptops"})
	ok := postForm(t, srv, "/evidence/import/confirm", token, hiddenFields(again.Body.String()).Encode())
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("confirming what was shown answered %d\n%s", ok.Code, firstLines(ok.Body.String(), 30))
	}
}

// Nothing is sealed for an import the audit log could not record: the
// server is wired to the log, the log cannot take an entry, and the screen
// says so and leaves the raw store as it was.
func TestImportRefusedWhileTheAuditLogCannotRecord(t *testing.T) {
	srv, token := setup(t)
	was := evidence.Recorder
	evidence.Recorder = func(reg *register.Register) {
		reg.Audit = func(audit.Record) error { return errors.New("the audit log's disk is full") }
		reg.Ready = func() error { return errors.New("the audit log's disk is full") }
	}
	t.Cleanup(func() { evidence.Recorder = was })
	w := postFile(t, srv, token, evidenceImportPath, "prowler.json", evidenceFixture(t, "ocsf/prowler-1.2.0.json"),
		map[string]string{"format": "ocsf"})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "disk is full") {
		t.Fatalf("an import the audit log could not record answered %d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
	if _, err := os.Stat(filepath.Join(srv.Store.Root(), "evidence", "raw")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a file was sealed for an import that could not be recorded: %v", err)
	}
}

// Somebody who may only read the register's area is refused the writes of
// the evidence screens at the door: no key pinned, no map confirmed, no
// file sealed and nothing erased.
func TestAReaderWritesNothingFromTheEvidenceScreens(t *testing.T) {
	srv, _ := setup(t)
	recording(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "aud", Role: auth.RoleReader, Resource: register.Area}); err != nil {
		t.Fatal(err)
	}
	aud, _, err := srv.Tokens.IssueSession("aud", "aud", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/evidence", aud); w.Code != http.StatusOK {
		t.Fatalf("a reader of the register is refused its list of evidence: %d", w.Code)
	}
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public()
	der, _ := x509.MarshalPKIXPublicKey(pub)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	m := `{"name":"laptops","kind":"Observation","format":"csv","columns":[{"field":"about","column":"Serial","asset":"device"}],` +
		`"facts":[{"fact":"disk.encrypted","column":"Encrypted"}]}`
	for path, form := range map[string]url.Values{
		"/evidence/keys":           {"name": {"release-signing"}, "key": {key}},
		"/evidence/map":            {"map": {m}},
		"/evidence/expire":         {},
		"/evidence/import/confirm": {"file": {"sha256:" + strings.Repeat("0", 64)}, "format": {"ocsf"}},
	} {
		if w := postForm(t, srv, path, aud, form.Encode()); w.Code != http.StatusForbidden {
			t.Errorf("a reader's post to %s answered %d", path, w.Code)
		}
	}
	if w := postFile(t, srv, aud, evidenceImportPath, "prowler.json", evidenceFixture(t, "ocsf/prowler-1.2.0.json"),
		map[string]string{"format": "ocsf"}); w.Code != http.StatusForbidden {
		t.Errorf("a reader's import answered %d", w.Code)
	}
	if counts, _ := register.Open(srv.Store).Counts(); counts[register.KindPinnedKey] != 0 || counts[register.KindColumnMap] != 0 {
		t.Errorf("a reader wrote to the register: %v", counts)
	}
	if _, err := os.Stat(filepath.Join(srv.Store.Root(), "evidence")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a reader's import filled the raw store: %v", err)
	}
}

// The preview seals the file it reads, and that sealing is recorded as the
// person who sent it, though nothing is written to the register until they
// confirm: a file previewed and never confirmed is still in the raw store
// for thirteen months, and the audit log says who put it there.
func TestPreviewSealIsRecorded(t *testing.T) {
	srv, token := setup(t)
	audited := recording(t)
	w := postFile(t, srv, token, evidenceImportPath, "prowler.json", evidenceFixture(t, "ocsf/prowler-1.2.0.json"),
		map[string]string{"format": "ocsf"})
	if w.Code != http.StatusOK {
		t.Fatalf("the preview answered %d", w.Code)
	}
	digest := string(evidence.DigestOf(evidenceFixture(t, "ocsf/prowler-1.2.0.json")))
	if len(*audited) != 1 || (*audited)[0].Action != evidence.SealAction || (*audited)[0].Principal != "editor" ||
		(*audited)[0].Detail["digest"] != digest {
		t.Fatalf("the preview's sealing is recorded as %+v", *audited)
	}
	if register.Open(srv.Store).Head() != "" {
		t.Fatal("the preview wrote to the register")
	}
}
