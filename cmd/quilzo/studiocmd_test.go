// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/studio"
)

// studioStore is a store where ada may write drafts and holds a token, and
// the studio serving it.
func studioStore(t *testing.T) (root, secret, id string, srv *studio.Server) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root = connectStore(t)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "ada", Role: auth.RoleAuthor, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	secret, id = issueFor(t, root, "ada")
	srv, err := studioServer(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, secret, id, srv
}

// issueFor issues somebody an author's token in the store on disk, as
// `quilzo token issue` in another process would.
func issueFor(t *testing.T, root, who string) (secret, id string) {
	t.Helper()
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, tok, err := ts.Issue("studio", who, auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	return secret, tok.ID
}

var recordingNo struct {
	sync.Mutex
	n byte
}

// uploadAs puts a recording through the studio with a token, and returns
// the status it answered.
func uploadAs(t *testing.T, srv *studio.Server, secret string) int {
	t.Helper()
	recordingNo.Lock()
	recordingNo.n++
	n := recordingNo.n
	recordingNo.Unlock()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "screen.webm")
	if err != nil {
		t.Fatal(err)
	}
	// A WebM header and padding that differs per recording, so each is a
	// file of its own in a library that files by hash.
	webm := append([]byte{0x1A, 0x45, 0xDF, 0xA3}, []byte("webm")...)
	webm = append(webm, bytes.Repeat([]byte{n}, 4096)...)
	if _, err := part.Write(webm); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: studio.CookieName, Value: secret})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

// The studio follows the store's tokens and grants while it runs.
//
// It read both once, when it started, so a token revoked with `quilzo
// token revoke` or through the admin went on signing in and putting
// recordings in the library until somebody restarted the studio, while
// its own sign-in page told the holder that revoking it stops this surface
// too. A token issued, or a grant withdrawn, after it started was as
// invisible.
func TestTheStudioFollowsRevocationWithoutARestart(t *testing.T) {
	root, first, firstID, srv := studioStore(t)
	if code := uploadAs(t, srv, first); code != http.StatusOK {
		t.Fatalf("a recording with a good token answered %d", code)
	}

	// Issued after the studio started.
	second, _ := issueFor(t, root, "ada")
	if code := uploadAs(t, srv, second); code != http.StatusOK {
		t.Errorf("a token issued after the studio started answered %d", code)
	}

	// Revoked from the command line.
	if err := tokenRevoke(root, []string{firstID}); err != nil {
		t.Fatal(err)
	}
	if code := uploadAs(t, srv, first); code != http.StatusUnauthorized {
		t.Errorf("a revoked token put a recording in the library (%d)", code)
	}

	// The person's grant withdrawn, their token left alone.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("ada", auth.RoleAuthor, "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code := uploadAs(t, srv, second); code != http.StatusUnauthorized {
		t.Errorf("a token whose holder lost the right to write drafts put a "+
			"recording in the library (%d)", code)
	}
}

// Requests read the store at the same time without stepping on each other.
func TestTheStudioReloadsUnderConcurrentRequests(t *testing.T) {
	root, secret, _, srv := studioStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: studio.CookieName, Value: secret})
			srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	issueFor(t, root, "ada")
	wg.Wait()
}
