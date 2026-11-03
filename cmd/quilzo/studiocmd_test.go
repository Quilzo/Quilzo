// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/shield"
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

// A token the shield has suspended does not record either.
//
// The admin, the API and the site's API load their tokens through the
// shield's gate, so `quilzo shield suspend` or a lockdown stops a token at
// each of them; the studio loaded its own and asked nothing, and a token
// suspended for leaking went on putting recordings in the library there.
func TestTheStudioHonoursTheShield(t *testing.T) {
	root, secret, id, srv := studioStore(t)
	other, _ := issueFor(t, root, "ada")
	if _, _, err := shield.Apply(root, shield.Protection{Kind: shield.Token,
		Target: id, Reason: "leaked in a log", By: "dana",
		Until: time.Now().Add(time.Hour)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code := uploadAs(t, srv, secret); code != http.StatusUnauthorized {
		t.Errorf("a token the shield suspended put a recording in the library (%d)", code)
	}
	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a token the shield suspended signed in (%d)", rec.Code)
	}
	if code := uploadAs(t, srv, other); code != http.StatusOK {
		t.Errorf("a token nobody suspended was refused with it (%d)", code)
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

// What the studio records is made out to the person whose token did it.
//
// It was made out to whoever started the studio: the audit hook resolved
// the caller of the process, so its token file or QUILZO_TOKEN, and every
// recording anybody put in the library through the page was in the log as
// the operator's. A refused sign-in was written as the operator's success.
func TestTheStudioRecordsTheTokenHolder(t *testing.T) {
	root, secret, _, srv := studioStore(t)
	// The operator who ran `quilzo studio`, with a token of their own.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "olu", Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	operator, _ := issueFor(t, root, "olu")
	t.Setenv("QUILZO_TOKEN", operator)

	signIn := func(token string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/signin",
			strings.NewReader("token="+token))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	signIn(secret)
	if code := uploadAs(t, srv, secret); code != http.StatusOK {
		t.Fatalf("the upload answered %d", code)
	}
	signIn("not-a-token")

	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	ada, olu := loggedAs(t, root, "ada"), loggedAs(t, root, "olu")
	seen := map[string]audit.Event{}
	for _, e := range evs {
		if strings.HasPrefix(e.Action, "studio.") {
			seen[e.Action] = e
		}
	}
	for _, action := range []string{"studio.signin", "studio.upload"} {
		e, ok := seen[action]
		if !ok {
			t.Errorf("no %s was recorded", action)
			continue
		}
		if e.Principal != ada || !e.Verified || e.Kind != audit.KindHuman {
			t.Errorf("%s is recorded as %s (verified %v, %s); ada's token did it",
				action, e.Principal, e.Verified, e.Kind)
		}
	}
	if e, ok := seen["studio.signin.refused"]; !ok {
		t.Error("a refused sign-in was not recorded")
	} else if e.Principal == olu || e.Verified || e.Outcome != audit.Denied {
		t.Errorf("a refused sign-in is recorded as %s's %s (verified %v)",
			e.Principal, e.Outcome, e.Verified)
	}
}
