// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package outpost

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/attest"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/marking"
)

var when = time.Date(2027, 3, 10, 9, 0, 0, 0, time.UTC)

func key(t *testing.T, seed byte) *audit.HeadSigner {
	t.Helper()
	s, err := audit.NewHeadSigner(bytes.Repeat([]byte{seed}, audit.SeedSize), bytes.Repeat([]byte{seed + 1}, audit.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// published is the head.pub.json the internal instance publishes for key.
func published(t *testing.T, k *audit.HeadSigner) []byte {
	t.Helper()
	ed, ml := k.Verifier().PublicKeys()
	body, _ := json.Marshal(map[string]string{"key_id": k.Verifier().KeyID(),
		"ed25519": base64.StdEncoding.EncodeToString(ed), "mldsa": base64.StdEncoding.EncodeToString(ml),
		"note": "the public half of the head keys"})
	return body
}

// instance is a public instance pinned to the internal key.
func instance(t *testing.T, internal *audit.HeadSigner) *Instance {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "public")
	if err := Init(dir, published(t, internal), when); err != nil {
		t.Fatal(err)
	}
	in, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func attestations() *attest.File {
	return &attest.File{Format: 1, Organisation: "Fernhollow Ltd",
		Attestations: []attest.Attestation{{ID: "soc2-2026", Kind: attest.Report, Title: "SOC 2 Type II report",
			Framework: "SOC 2", PeriodStart: "2026-01-01", PeriodEnd: "2026-12-31", Issuer: "Ashby & Rowe LLP",
			Issued: "2027-02-14"}},
		Policies: []attest.Policy{{Title: "Information security policy", Version: "4.2", Approved: "2027-01-20"}}}
}

func feed(t *testing.T, k *audit.HeadSigner, sizes ...int) []byte {
	t.Helper()
	f := HeadFeed{Format: 1, KeyID: k.Verifier().KeyID()}
	for i, n := range sizes {
		sh, err := k.Sign(audit.Head{Size: n, Root: strings.Repeat("0", 63) + string(rune('a'+i)),
			At: when.Add(time.Duration(i) * time.Hour).Format(time.RFC3339)})
		if err != nil {
			t.Fatal(err)
		}
		f.Heads = append(f.Heads, sh)
	}
	body, _ := json.Marshal(f)
	return body
}

// projection writes what an internal instance sends, records the transfer
// at made and signs it with by (nil leaves it unsigned).
func projection(t *testing.T, files map[string][]byte, made time.Time, by *audit.HeadSigner) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := marking.RecordTransfer(dir, marking.Transfer{Approved: "dana, sam", Carried: "quilzo public send",
		Reason: "the 2026 report is in", From: "internal", To: "public"}, made); err != nil {
		t.Fatal(err)
	}
	if by != nil {
		if err := marking.SignTransfer(dir, by); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func goodFiles(t *testing.T, k *audit.HeadSigner) map[string][]byte {
	t.Helper()
	att, _ := attestations().Encode()
	return map[string][]byte{
		AttestationsFile: att,
		FeedFile:         feed(t, k, 10, 25),
		SecurityTxtFile:  []byte("Contact: mailto:security@fernhollow.example\nExpires: 2027-12-31T00:00:00Z\n"),
	}
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// A transfer with no signature is refused, and nothing it carried is served.
func TestPublicRefusesUnsignedTransfer(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	_, err := in.Import(projection(t, goodFiles(t, internal), when, nil), when)
	if !errors.Is(err, marking.ErrUnsigned) {
		t.Fatalf("an unsigned transfer was not refused as unsigned: %v", err)
	}
	if body := get(t, in.Handler(), "/").Body.String(); strings.Contains(body, "Fernhollow") ||
		!strings.Contains(body, "Nothing has been published here yet") {
		t.Error("what an unsigned transfer carried is served")
	}
}

// A transfer signed by any key but the pinned one is refused, however
// well-formed, and so is a head in the feed that the pinned key did not
// sign.
func TestPublicRefusesWrongKey(t *testing.T) {
	internal, other := key(t, 1), key(t, 7)
	in := instance(t, internal)
	if _, err := in.Import(projection(t, goodFiles(t, other), when, other), when); err == nil ||
		!strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a transfer signed by another key was taken: %v", err)
	}
	files := goodFiles(t, internal)
	files[FeedFile] = feed(t, other, 10)
	if _, err := in.Import(projection(t, files, when, internal), when); err == nil {
		t.Error("a head feed signed by another key was taken")
	}
	if strings.Contains(get(t, in.Handler(), "/").Body.String(), "Fernhollow") {
		t.Error("a refused transfer is served")
	}
}

// A transfer signed by the pinned key is served: the page, the file it is
// drawn from, security.txt and the head feed, exactly as sent.
func TestASignedTransferIsServed(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	files := goodFiles(t, internal)
	rc, err := in.Import(projection(t, files, when, internal), when)
	if err != nil {
		t.Fatal(err)
	}
	if rc.KeyID != internal.Verifier().KeyID() || rc.Approved != "dana, sam" || len(rc.Files) != 3 {
		t.Errorf("the receipt does not say what was taken: %+v", rc)
	}
	h := in.Handler()
	page := get(t, h, "/")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "SOC 2 Type II report") {
		t.Fatalf("the page is not served: %d", page.Code)
	}
	for _, f := range a11y.Check("/", page.Body.String()).Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("%s (%s): %s", f.Rule, f.Criterion, f.Detail)
		}
	}
	if csp := page.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the page's policy is %q", csp)
	}
	for path, name := range map[string]string{"/heads.json": FeedFile, "/.well-known/security.txt": SecurityTxtFile,
		"/attestations.json": AttestationsFile} {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK || rec.Body.String() != string(files[name]) {
			t.Errorf("%s is not served as sent: %d", path, rec.Code)
		}
	}
	// A restart serves the same, checked again from disk.
	again, err := Open(in.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(get(t, again.Handler(), "/").Body.String(), "SOC 2 Type II report") {
		t.Error("after a restart the projection is not served")
	}
}

// A transfer may carry the projection and nothing else: a file outside the
// closed list is refused, so nothing but published projections can reach
// the public host this way.
func TestATransferCarriesOnlyTheProjection(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	files := goodFiles(t, internal)
	files["tokens.json"] = []byte(`{"tokens": []}`)
	if _, err := in.Import(projection(t, files, when, internal), when); err == nil ||
		!strings.Contains(err.Error(), "tokens.json") {
		t.Errorf("a transfer carrying tokens.json was taken: %v", err)
	}
	files = goodFiles(t, internal)
	files[AttestationsFile] = []byte(`{"format": 1, "organisation": "X", "attestations": [], "policies": [], "score": 97}`)
	if _, err := in.Import(projection(t, files, when, internal), when); err == nil {
		t.Error("attestations carrying a score were taken")
	}
}

// An older transfer than the one served is refused, so a replayed transfer
// cannot put back what was withdrawn.
func TestAnOlderTransferIsRefused(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	older := projection(t, goodFiles(t, internal), when, internal)
	newer := projection(t, goodFiles(t, internal), when.Add(time.Hour), internal)
	if _, err := in.Import(newer, when.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Import(older, when.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("an older transfer replaced a newer one: %v", err)
	}
}

// The public handler serves the projection and nothing else: no admin, no
// API, no agent interface, no register, no write but the transfer intake.
func TestTheHandlerServesNothingElse(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	if _, err := in.Import(projection(t, goodFiles(t, internal), when, internal), when); err != nil {
		t.Fatal(err)
	}
	h := in.Handler()
	for _, path := range []string{"/admin", "/security", "/api/v1/pages", "/api/v1/profile", "/mcp", "/register",
		"/signin", "/people", "/.well-known/oauth-authorization-server", "/heads.json/../admin", "/public.css/x"} {
		if rec := get(t, h, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x")))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST / answered %d", rec.Code)
	}
	if css := get(t, h, "/public.css"); css.Code != http.StatusOK || !strings.Contains(css.Body.String(), "prefers-reduced-motion") {
		t.Errorf("the stylesheet is not served: %d", css.Code)
	}
}

// Over HTTP, the internal instance posts the same signed transfer, packed;
// the intake takes it only signed by the pinned key, and only up to its
// limits.
func TestTheIntakeTakesASignedEnvelopeOnly(t *testing.T) {
	internal, other := key(t, 1), key(t, 7)
	in := instance(t, internal)
	h := in.Handler()
	post := func(body []byte) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, IntakePath, bytes.NewReader(body)))
		return rec
	}
	bad, err := Pack(projection(t, goodFiles(t, other), when, other))
	if err != nil {
		t.Fatal(err)
	}
	if rec := post(bad); rec.Code != http.StatusForbidden {
		t.Errorf("an envelope signed by another key answered %d", rec.Code)
	}
	unsigned, err := Pack(projection(t, goodFiles(t, internal), when, nil))
	if err == nil {
		if rec := post(unsigned); rec.Code != http.StatusForbidden {
			t.Errorf("an unsigned envelope answered %d", rec.Code)
		}
	}
	if rec := post([]byte(`{"transfer": "e30=", "files": {"../../etc/passwd": "eA=="}}`)); rec.Code < 400 {
		t.Errorf("an envelope naming a path outside the projection answered %d", rec.Code)
	}
	if rec := post(bytes.Repeat([]byte("x"), MaxEnvelope+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an envelope over the limit answered %d", rec.Code)
	}
	good, err := Pack(projection(t, goodFiles(t, internal), when, internal))
	if err != nil {
		t.Fatal(err)
	}
	if rec := post(good); rec.Code != http.StatusOK {
		t.Fatalf("a signed envelope answered %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(get(t, h, "/").Body.String(), "SOC 2 Type II report") {
		t.Error("a signed envelope's projection is not served")
	}
}

// An instance holds the pinned public key and nothing secret: its own files
// are the configuration and what it was sent.
func TestAnInstanceHoldsOnlyThePinnedKeyAndTheProjection(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	if _, err := in.Import(projection(t, goodFiles(t, internal), when, internal), when); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(in.Dir(), func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		name := fi.Name()
		switch {
		case name == ConfigFile, name == CurrentFile, name == marking.TransferName, name == marking.TransferSigName:
		case name == AttestationsFile, name == FeedFile, name == SecurityTxtFile:
		default:
			t.Errorf("the instance holds %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Init(filepath.Join(t.TempDir(), "p"), []byte(`{"key_id": "x", "ed25519": "AAAA"}`), when); err == nil {
		t.Error("an instance was pinned to a key that is not one")
	}
}
