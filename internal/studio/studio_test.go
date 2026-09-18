// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package studio

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/throttle"
)

// wired builds a studio with a library, a policy and one usable token.
func wired(t *testing.T) (*Server, string) {
	t.Helper()
	lib, err := medialib.Open(filepath.Join(t.TempDir(), "media"))
	if err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "ada", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.Issue("studio", "ada", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		Tokens: ts, Policy: pol,
		Library:  func() (*medialib.Library, error) { return lib, nil },
		Options:  func() media.Options { return media.Options{} },
		Throttle: throttle.New(throttle.Default()),
	}, secret
}

func signedIn(t *testing.T, srv *Server, secret, path string,
	body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {

	t.Helper()
	method := http.MethodGet
	var reader *bytes.Buffer = bytes.NewBuffer(nil)
	if body != nil {
		method, reader = http.MethodPost, body
	}
	req := httptest.NewRequest(method, path, reader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if secret != "" {
		req.AddCookie(&http.Cookie{Name: CookieName, Value: secret})
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// The recorder page carries a nonce, and nothing else does.
//
// The whole reason this is a separate server is that one page runs a script.
// A blanket policy on the server would be a policy somebody widens once for
// the recorder and leaves widened for the sign-in form, so the page that takes
// a credential is served under a policy that executes nothing.
func TestOnlyTheRecorderPermitsAScript(t *testing.T) {
	srv, secret := wired(t)

	in := signedIn(t, srv, secret, "/", nil, "")
	csp := in.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") {
		t.Fatalf("the recorder does not scope its script to a nonce: %s", csp)
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "*",
		"http:", "https:"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("the recorder's policy permits %q: %s", forbidden, csp)
		}
	}

	out := signedIn(t, srv, "", "/", nil, "")
	outCSP := out.Header().Get("Content-Security-Policy")
	if strings.Contains(outCSP, "script-src") &&
		!strings.Contains(outCSP, "script-src 'none'") {
		t.Errorf("the sign-in page permits a script: %s", outCSP)
	}
}

// Two responses never share a nonce.
//
// A value reused across responses means an injection into either page carries
// one that works on the next, which is the property that makes a nonce worth
// having at all.
func TestTheNonceIsFreshPerResponse(t *testing.T) {
	srv, secret := wired(t)
	first := signedIn(t, srv, secret, "/", nil, "").Header().
		Get("Content-Security-Policy")
	second := signedIn(t, srv, secret, "/", nil, "").Header().
		Get("Content-Security-Policy")
	if first == second {
		t.Error("two responses carried the same nonce")
	}
	re := regexp.MustCompile(`'nonce-([A-Za-z0-9+/]+)'`)
	if re.FindStringSubmatch(first) == nil {
		t.Fatalf("no nonce in %s", first)
	}
	// And the tag carries the same value as the header it was served with.
	rec := signedIn(t, srv, secret, "/", nil, "")
	got := re.FindStringSubmatch(rec.Header().Get("Content-Security-Policy"))
	if got == nil {
		t.Fatal("no nonce on the second look")
	}
	if !strings.Contains(rec.Body.String(), `<script nonce="`+got[1]+`">`) {
		t.Error("the script tag does not carry the nonce from its own header")
	}
}

// The script uses no sink that turns a string into markup or code.
//
// This page runs in a writable origin and handles bytes from a media device.
// Fetching a library would mean a CDN in the policy — reopening what the nonce
// closes — so there is nothing here but the standard library of the browser.
func TestTheScriptUsesNoDangerousSinks(t *testing.T) {
	srv, secret := wired(t)
	body := signedIn(t, srv, secret, "/", nil, "").Body.String()
	script := body[strings.Index(body, "<script"):]
	for _, sink := range []string{"innerHTML", "outerHTML", "eval(",
		"document.write", "new Function", "setTimeout(\"", "setInterval(\""} {
		if strings.Contains(script, sink) {
			t.Errorf("the script uses %s", sink)
		}
	}
	// The credential is HttpOnly and the upload is same-origin, so the script
	// never needs to see it — which is what stops an injection carrying it
	// anywhere.
	if strings.Contains(script, "document.cookie") {
		t.Error("the script reads the cookie")
	}
}

// It loads nothing from anywhere else, which is what lets the policy name no
// host at all.
func TestThePageLoadsNothingExternal(t *testing.T) {
	srv, secret := wired(t)
	for _, page := range []string{
		signedIn(t, srv, secret, "/", nil, "").Body.String(),
		signedIn(t, srv, "", "/", nil, "").Body.String(),
	} {
		for _, ext := range []string{"http://", "https://", "//cdn",
			"integrity=", "<iframe"} {
			if strings.Contains(page, ext) {
				t.Errorf("the page references %q", ext)
			}
		}
	}
}

// Nobody uploads without a credential that may write.
func TestUploadingNeedsACredentialThatMayWrite(t *testing.T) {
	srv, _ := wired(t)
	body, ct := oneRecording(t, "clip.webm", webmBytes())
	if rec := signedIn(t, srv, "", "/upload", body, ct); rec.Code != 401 {
		t.Errorf("an unauthenticated upload answered %d", rec.Code)
	}

	// A token whose own role is narrower than its holder's rights.
	ts := srv.Tokens
	readonly, _, err := ts.Issue("read", "ada", auth.RoleReader, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	body2, ct2 := oneRecording(t, "clip.webm", webmBytes())
	if rec := signedIn(t, srv, readonly, "/upload", body2, ct2); rec.Code != 401 {
		t.Errorf("a reader's token uploaded a recording, answering %d",
			rec.Code)
	}
}

// A recording lands in the library, through the same door an upload uses.
func TestARecordingIsStored(t *testing.T) {
	srv, secret := wired(t)
	body, ct := oneRecording(t, "screen.webm", webmBytes())
	rec := signedIn(t, srv, secret, "/upload", body, ct)
	if rec.Code != http.StatusOK {
		t.Fatalf("the upload answered %d: %s", rec.Code, rec.Body.String())
	}

	lib, err := srv.Library()
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("nothing was stored")
	}
	if files[0].UploadedBy != "ada" {
		t.Errorf("it is recorded as uploaded by %q", files[0].UploadedBy)
	}
	if files[0].Source != "studio" {
		t.Errorf("its source is %q", files[0].Source)
	}
	// The reply says the next thing to do, because a recording in the library
	// is not yet a recording on a page and the gate that will refuse the page
	// is one nobody has met yet.
	if !strings.Contains(rec.Body.String(), "captions") {
		t.Errorf("the reply does not mention captions: %s", rec.Body.String())
	}
}

// Anything that is not a recording is refused by the parse.
//
// The browser sends video/webm and the browser is not the authority: the bytes
// are. A page could post a PNG or an HTML file to this endpoint.
func TestOnlyARecordingIsAccepted(t *testing.T) {
	srv, secret := wired(t)
	for name, payload := range map[string][]byte{
		"markup":  []byte("<html><script>alert(1)</script></html>"),
		"nothing": []byte("not any format at all"),
		"a picture": append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a},
			make([]byte, 64)...),
	} {
		body, ct := oneRecording(t, "clip.webm", payload)
		rec := signedIn(t, srv, secret, "/upload", body, ct)
		if rec.Code == http.StatusOK {
			t.Errorf("%s was accepted as a recording", name)
		}
	}
	lib, _ := srv.Library()
	if files, _ := lib.List(); len(files) != 0 {
		t.Errorf("%d file(s) were stored by a refused upload", len(files))
	}
}

// A wrong token counts against the limiter.
//
// The admin's sign-in form was measured taking forty wrong tokens without
// once answering 429, because failures there never reached the counter. A new
// door with the same shape gets the limiter from the start.
func TestWrongTokensAreThrottled(t *testing.T) {
	srv, _ := wired(t)
	var refused, limited int
	for i := 0; i < 30; i++ {
		form := bytes.NewBufferString("token=not-a-real-token")
		req := httptest.NewRequest(http.MethodPost, "/signin", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.1.2.3:5555"
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusUnauthorized:
			refused++
		case http.StatusTooManyRequests:
			limited++
		}
	}
	if limited == 0 {
		t.Errorf("thirty wrong tokens produced %d refusals and never a 429; "+
			"this is the door the admin's own form was measured leaving open",
			refused)
	}
}

// Signing in sets a cookie that cannot be read by script and does not travel.
func TestTheCredentialIsHttpOnlyAndSameSite(t *testing.T) {
	srv, secret := wired(t)
	form := bytes.NewBufferString("token=" + secret)
	req := httptest.NewRequest(http.MethodPost, "/signin", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("signing in answered %d: %s", rec.Code, rec.Body.String())
	}
	set := rec.Header().Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", CookieName} {
		if !strings.Contains(set, want) {
			t.Errorf("the cookie is missing %s: %s", want, set)
		}
	}
}

// Nothing here is cached, because everything here is either a credential
// prompt or somebody's screen.
func TestNothingIsCached(t *testing.T) {
	srv, secret := wired(t)
	for _, path := range []string{"/", "/studio.css"} {
		rec := signedIn(t, srv, secret, path, nil, "")
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s is served with Cache-Control %q", path, got)
		}
	}
}

// oneRecording builds a multipart body carrying a file.
func oneRecording(t *testing.T, name string, payload []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("alt", "a walkthrough"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

// webmBytes is a structurally valid WebM header and some padding, which is
// what media.Accept requires of the container.
func webmBytes() []byte {
	b := append([]byte{0x1A, 0x45, 0xDF, 0xA3}, []byte("webm")...)
	return append(b, make([]byte, 4096)...)
}
