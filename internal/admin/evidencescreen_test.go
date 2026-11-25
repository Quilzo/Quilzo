// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
)

// recording wires the evidence screens' writes to a list of audit entries,
// as cmd/quilzo wires them to the store's audit log.
func recording(t *testing.T) *[]audit.Record {
	t.Helper()
	var got []audit.Record
	was := evidence.Recorder
	evidence.Recorder = func(reg *register.Register) {
		reg.Audit = func(r audit.Record) error { got = append(got, r); return nil }
	}
	t.Cleanup(func() { evidence.Recorder = was })
	return &got
}

func evidenceFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// postFile posts a file and fields to an address, as the import form does.
func postFile(t *testing.T, srv *Server, token, path, filename string, body []byte, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if body != nil {
		fw, _ := mw.CreateFormFile("file", filename)
		_, _ = fw.Write(body)
	}
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// accessible fails the test for every blocking finding of the checker on
// a page.
func accessible(t *testing.T, path, body string) {
	t.Helper()
	for _, f := range a11y.Check(path, body).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("%s: %s (%s): %s", path, f.Rule, f.Criterion, f.Detail)
		}
	}
}

// A file brought in from the Import screen is sealed and read, and the
// person is shown every record it would write, with where it was read and
// its grade, before anything is written: the register is untouched until
// they confirm. Confirming writes it as them, recorded in the audit log,
// and the file's own page says it checks.
func TestImportPreviewWritesNothingUntilConfirmed(t *testing.T) {
	srv, token := setup(t)
	audited := recording(t)
	reg := register.Open(srv.Store)

	w := postFile(t, srv, token, evidenceImportPath, "prowler.json", evidenceFixture(t, "ocsf/prowler-1.2.0.json"),
		map[string]string{"format": "ocsf"})
	if w.Code != http.StatusOK {
		t.Fatalf("the preview answered %d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
	body := w.Body.String()
	for _, want := range []string{"<h1>Check what the file would write</h1>", "Nothing has been written yet",
		"check.s3-bucket-public-access", "/1/status_code", "Uploaded", `action="/evidence/import/confirm"`, "What it proposes"} {
		if !strings.Contains(body, want) {
			t.Errorf("the preview does not show %q", want)
		}
	}
	accessible(t, "/evidence/import (preview)", body)
	// The sealing is recorded, and nothing else: no record is written.
	if reg.Head() != "" || len(*audited) != 1 || (*audited)[0].Action != evidence.SealAction {
		t.Fatalf("the preview wrote to the register, or recorded %+v", *audited)
	}
	digest := evidence.DigestOf(evidenceFixture(t, "ocsf/prowler-1.2.0.json"))
	if _, err := evidence.New(reg).Raw.Open(digest); err != nil {
		t.Fatalf("the file was not sealed as it arrived: %v", err)
	}

	done := postForm(t, srv, "/evidence/import/confirm", token, url.Values{"file": {string(digest)}, "format": {"ocsf"}}.Encode())
	if done.Code != http.StatusSeeOther || !strings.HasPrefix(done.Header().Get("Location"), "/evidence/file/") {
		t.Fatalf("confirming answered %d to %q\n%s", done.Code, done.Header().Get("Location"), firstLines(done.Body.String(), 20))
	}
	counts, err := reg.Counts()
	if err != nil || counts[register.KindObservation] != 3 || counts[register.KindRawFile] != 1 {
		t.Fatalf("the register holds %v, %v", counts, err)
	}
	if len(*audited) == 0 || (*audited)[0].Principal != "editor" || (*audited)[0].Kind != audit.KindHuman {
		t.Fatalf("the write was recorded as %+v", *audited)
	}
	page := get(t, srv, done.Header().Get("Location"), token)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Checks") || !strings.Contains(page.Body.String(), "Written:") {
		t.Fatalf("the file's page answered %d\n%s", page.Code, firstLines(page.Body.String(), 40))
	}
	accessible(t, done.Header().Get("Location"), page.Body.String())
	for _, path := range []string{"/evidence", evidenceImportPath, "/evidence/keys"} {
		w := get(t, srv, path, token)
		if w.Code != http.StatusOK {
			t.Fatalf("%s answered %d", path, w.Code)
		}
		accessible(t, path, w.Body.String())
	}
	if list := get(t, srv, "/evidence", token).Body.String(); !strings.Contains(list, "<caption>Files brought in as evidence") ||
		!strings.Contains(list, string(digest)) {
		t.Errorf("the list does not show the file\n%s", firstLines(list, 60))
	}
}

// A form sent without a file or a format is answered with what is wrong,
// in a summary at the top that links to each field and beside each field,
// and the fields are marked invalid.
func TestImportFormNamesItsErrors(t *testing.T) {
	srv, token := setup(t)
	recording(t)
	w := postFile(t, srv, token, evidenceImportPath, "", nil, map[string]string{"format": ""})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an empty form answered %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`id="kit-errors"`, `href="#import-file"`, `href="#import-format"`, `id="import-file-error"`,
		`aria-invalid="true"`, "choose the file to bring in"} {
		if !strings.Contains(body, want) {
			t.Errorf("the form's errors do not show %q", want)
		}
	}
	accessible(t, "/evidence/import (errors)", body)
}

// A table brought in with no map gets a draft, read from its headings; a
// person confirms it, and the sealed file is then previewed through it.
func TestMapDraftedConfirmedAndUsed(t *testing.T) {
	srv, token := setup(t)
	recording(t)
	csv := []byte("Serial,Hostname,Encrypted\nC02X1,mac-01,true\nC02X2,mac-02,false\n")
	w := postFile(t, srv, token, evidenceImportPath, "laptops.csv", csv, map[string]string{"format": "csv", "kind": "Observation"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<h1>Confirm a column map</h1>") {
		t.Fatalf("a table with no map answered %d\n%s", w.Code, firstLines(w.Body.String(), 30))
	}
	accessible(t, "/evidence/import (draft)", w.Body.String())
	d, err := evidence.DraftMap(evidence.FormatCSV, csv, "Observation", "laptops", "")
	if err != nil {
		t.Fatal(err)
	}
	m := d.Map
	m.Name = "laptops"
	text, _ := jsonText(m)
	done := postForm(t, srv, "/evidence/map", token, url.Values{"map": {text}, "file": {string(evidence.DigestOf(csv))},
		"format": {"csv"}}.Encode())
	if done.Code != http.StatusSeeOther {
		t.Fatalf("confirming the map answered %d\n%s", done.Code, firstLines(done.Body.String(), 30))
	}
	prev := get(t, srv, done.Header().Get("Location"), token)
	if prev.Code != http.StatusOK || !strings.Contains(prev.Body.String(), "disk.encrypted") && !strings.Contains(prev.Body.String(), "encrypted") {
		t.Fatalf("the sealed table previewed through the map answered %d\n%s", prev.Code, firstLines(prev.Body.String(), 40))
	}
	bad := postForm(t, srv, "/evidence/map", token, url.Values{"map": {`{"name":"x","kind":"Observation","format":"csv","columns":[{"field":"grade","column":"Serial"}],"facts":[{"fact":"a","column":"Serial"}]}`}}.Encode())
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), "the importer") {
		t.Errorf("a map that reads the grade from a column answered %d", bad.Code)
	}
}

// A person pins a key on the screen, and its fingerprint is shown to check
// against what its owner published.
func TestKeyPinnedFromTheScreen(t *testing.T) {
	srv, token := setup(t)
	recording(t)
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public()
	der, _ := x509.MarshalPKIXPublicKey(pub)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	w := postForm(t, srv, "/evidence/keys", token, url.Values{"name": {"release-signing"}, "title": {"the build service"}, "key": {key}}.Encode())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Pinned release-signing, with the fingerprint sha256:") {
		t.Fatalf("pinning answered %d\n%s", w.Code, firstLines(w.Body.String(), 40))
	}
	accessible(t, "/evidence/keys (pinned)", w.Body.String())
	bad := postForm(t, srv, "/evidence/keys", token, url.Values{"name": {"x"}, "key": {"not a key"}}.Encode())
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), `id="key-key-error"`) {
		t.Errorf("a key that is none answered %d", bad.Code)
	}
}

// A server started without its audit log wired to the register writes
// nothing to it, and says so, rather than writing a record nobody can show
// was written by whom.
func TestImportRefusedWithoutAnAuditLog(t *testing.T) {
	srv, token := setup(t)
	was := evidence.Recorder
	evidence.Recorder = nil
	t.Cleanup(func() { evidence.Recorder = was })
	w := postFile(t, srv, token, evidenceImportPath, "prowler.json", evidenceFixture(t, "ocsf/prowler-1.2.0.json"),
		map[string]string{"format": "ocsf"})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "without its audit log") {
		t.Fatalf("an unwired server answered %d", w.Code)
	}
}

func jsonText(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
