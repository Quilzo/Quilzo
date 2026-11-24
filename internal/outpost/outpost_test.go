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
	// Signed by another key and carrying the pinned key's own heads, which
	// anybody who fetched the public feed holds: only the transfer's own
	// signature tells this one from the internal instance's.
	if _, err := in.Import(projection(t, goodFiles(t, internal), when, other), when); err == nil ||
		!strings.Contains(err.Error(), "not signed by the pinned key") {
		t.Errorf("a transfer signed by another key, carrying the pinned key's heads, was taken: %v", err)
	}
	files := goodFiles(t, internal)
	files[FeedFile] = feed(t, other, 10)
	if _, err := in.Import(projection(t, files, when, internal), when); err == nil {
		t.Error("a head feed signed by another key was taken")
	}
	// And a feed that names the pinned key over heads another key signed:
	// what the feed says of itself is not what checks it.
	forged := HeadFeed{Format: 1, KeyID: internal.Verifier().KeyID()}
	sh, err := other.Sign(audit.Head{Size: 10, Root: strings.Repeat("0", 64), At: when.Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	sh.KeyID = ""
	forged.Heads = append(forged.Heads, sh)
	files[FeedFile], _ = json.Marshal(forged)
	if _, err := in.Import(projection(t, files, when, internal), when); err == nil {
		t.Error("a head feed naming the pinned key over heads another key signed was taken")
	}
	if strings.Contains(get(t, in.Handler(), "/").Body.String(), "Fernhollow") {
		t.Error("a refused transfer is served")
	}
}

// feedOf is a feed of heads as given, signed by k.
func feedOf(t *testing.T, k *audit.HeadSigner, heads ...audit.Head) []byte {
	t.Helper()
	f := HeadFeed{Format: 1, KeyID: k.Verifier().KeyID()}
	for _, h := range heads {
		sh, err := k.Sign(h)
		if err != nil {
			t.Fatal(err)
		}
		f.Heads = append(f.Heads, sh)
	}
	body, _ := json.Marshal(f)
	return body
}

// The head feed is publication: whoever fetched it holds heads the record
// has to go on matching. So a newer transfer may add heads and let the
// oldest go, and may not take back what was published: a feed whose newest
// head commits to fewer entries than the one served (the record went back),
// one with a head of a size already published under another root (the
// record was rewritten), or none at all. Nor may one feed hold two heads of
// one size with different roots.
func TestAFeedThatGoesBackIsRefused(t *testing.T) {
	internal := key(t, 1)
	root := func(c string) string { return strings.Repeat(c, 64) }
	at := func(h int) string { return when.Add(time.Duration(h) * time.Hour).Format(time.RFC3339) }
	in := instance(t, internal)
	files := goodFiles(t, internal)
	files[FeedFile] = feedOf(t, internal, audit.Head{Size: 10, Root: root("a"), At: at(0)},
		audit.Head{Size: 25, Root: root("b"), At: at(1)})
	if _, err := in.Import(projection(t, files, when, internal), when); err != nil {
		t.Fatal(err)
	}
	made := when
	send := func(feed []byte) error {
		t.Helper()
		made = made.Add(time.Minute)
		f := goodFiles(t, internal)
		if feed == nil {
			delete(f, FeedFile)
		} else {
			f[FeedFile] = feed
		}
		_, err := in.Import(projection(t, f, made, internal), made)
		return err
	}
	for what, feed := range map[string][]byte{
		"whose newest head commits to fewer entries than the one served": feedOf(t, internal,
			audit.Head{Size: 10, Root: root("a"), At: at(0)}, audit.Head{Size: 12, Root: root("c"), At: at(2)}),
		"that publishes a head of a size already published under another root": feedOf(t, internal,
			audit.Head{Size: 25, Root: root("d"), At: at(2)}, audit.Head{Size: 30, Root: root("e"), At: at(3)}),
		"that holds two heads of one size with different roots": feedOf(t, internal,
			audit.Head{Size: 25, Root: root("b"), At: at(1)}, audit.Head{Size: 25, Root: root("f"), At: at(2)},
			audit.Head{Size: 40, Root: root("g"), At: at(3)}),
		"with no head feed at all": nil,
	} {
		if err := send(feed); err == nil {
			t.Errorf("a transfer %s was taken", what)
		}
	}
	if raw := get(t, in.Handler(), "/heads.json").Body.String(); !strings.Contains(raw, root("b")) {
		t.Error("a refused feed replaced the one served")
	}
	// Growing it, with the oldest head let go, is what a feed does.
	if err := send(feedOf(t, internal, audit.Head{Size: 25, Root: root("b"), At: at(1)},
		audit.Head{Size: 31, Root: root("h"), At: at(4)})); err != nil {
		t.Errorf("a feed that grows was refused: %v", err)
	}
	// And a feed sent again from a store that lost its list of heads sent,
	// whose one head is newer than every head served, is taken.
	if err := send(feedOf(t, internal, audit.Head{Size: 40, Root: root("i"), At: at(5)})); err != nil {
		t.Errorf("a feed of one newer head was refused: %v", err)
	}
}

// A projection is checked again when the instance starts: one changed on
// disk since it was taken is not served, and the instance says why.
func TestAProjectionChangedOnDiskIsNotServed(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	rc, err := in.Import(projection(t, goodFiles(t, internal), when, internal), when)
	if err != nil {
		t.Fatal(err)
	}
	served := filepath.Join(in.Dir(), "projections", rc.Served, AttestationsFile)
	body, err := os.ReadFile(served)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(served, bytes.Replace(body, []byte("Fernhollow Ltd"), []byte("Mallory Ltd"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	again, err := Open(in.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if page := get(t, again.Handler(), "/").Body.String(); strings.Contains(page, "Mallory") || strings.Contains(page, "Fernhollow") {
		t.Error("a projection changed on disk is served")
	}
	if st := again.Status(); st.Served != nil || st.Problem == "" {
		t.Errorf("the instance does not say why it serves nothing: %+v", st)
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
	// security.txt is checked for RFC 9116's shape too: a page, or a file
	// with no contact, is not one.
	for what, body := range map[string]string{
		"markup":       "<html><script>alert(1)</script></html>\n",
		"no contact":   "Expires: 2027-12-31T00:00:00Z\n",
		"no expiry":    "Contact: mailto:security@fernhollow.example\n",
		"a stray line": "Contact: mailto:security@fernhollow.example\nExpires: 2027-12-31T00:00:00Z\nsend reports here\n",
	} {
		files = goodFiles(t, internal)
		files[SecurityTxtFile] = []byte(body)
		if _, err := in.Import(projection(t, files, when, internal), when); err == nil {
			t.Errorf("a security.txt with %s was taken", what)
		}
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
	// Signed by another key, with the pinned key's own heads in it.
	bad, err := Pack(projection(t, goodFiles(t, internal), when, other))
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

// Transfers posted at once while the page is being read are taken one at
// a time, and the page always serves one whole projection.
func TestConcurrentTransfersAndReadsAreSafe(t *testing.T) {
	internal := key(t, 1)
	in := instance(t, internal)
	h := in.Handler()
	var bodies [][]byte
	for i := 0; i < 4; i++ {
		b, err := Pack(projection(t, goodFiles(t, internal), when.Add(time.Duration(i)*time.Minute), internal))
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, b)
	}
	done := make(chan struct{})
	for _, b := range bodies {
		go func(b []byte) {
			defer func() { done <- struct{}{} }()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, IntakePath, bytes.NewReader(b)))
		}(b)
		go func() {
			defer func() { done <- struct{}{} }()
			_ = get(t, h, "/")
			_ = get(t, h, "/heads.json")
		}()
	}
	for i := 0; i < 2*len(bodies); i++ {
		<-done
	}
	if st := in.Status(); st.Served == nil {
		t.Error("none of the transfers was taken")
	}
}
