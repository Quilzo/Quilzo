// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package studio records the screen, which no form post can do.
//
// # The tension, stated first
//
// The admin's Content-Security-Policy is `default-src 'none'` and a test
// asserts that its screens execute nothing. getDisplayMedia and MediaRecorder
// are JavaScript APIs: there is no form post that reaches a screen, and there
// will not be one. So either recording does not happen here, or something
// runs a script.
//
// Three ways to resolve that, and the operator chose the third.
//
//	Record outside and upload the file. Zero new surface, and not the feature.
//
//	A fourth nonce route in the admin, after /playground and /passkeys. It
//	breaks no existing test — but it puts a media-processing script on the
//	loopback admin, and this project's own words are that "the argument for
//	that header is that the site has no scripts rather than that it has some
//	the CSP catches".
//
//	A separate server. Which is the pattern this codebase already reaches for:
//	internal/telegram/miniapp.go is "its own server rather than a route on the
//	admin or the public site, because it has a different exposure and therefore
//	needs a different policy". A capture surface is authenticated, writable and
//	full of script — three properties neither of the others has.
//
// So: a fourth server, and the admin's claim stays exactly true.
//
// # What it is not
//
// It is not a second admin. It has no sessions list, no OIDC, no passkeys, no
// page editor and no publish button. It holds one capability — put one
// recording in the asset library — and everything it needs to check that
// comes from the packages the admin uses rather than from a copy of them:
// auth.TokenStore verifies the credential, auth.Policy decides, and
// internal/throttle counts the failures. Re-implementing any of that here
// would be a second version of the most security-sensitive code in the
// project, which is the trade this package exists to avoid making twice.
//
// # What the recording gets on the way in
//
// Everything an upload gets, because it goes through the same door:
// medialib.Put accepts it by parsing it, files it under the hash of its own
// bytes, reads its dimensions and length, and takes a poster frame. And the
// accessibility gate will refuse to publish a page showing it until somebody
// attaches captions — which is the part that makes this a different product
// from the ones it resembles rather than a worse one.
package studio

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/throttle"
)

// MaxRecording caps one upload.
//
// Larger than the admin's form limit, because this arrives through fetch with
// a progress bar attached: the reason that one is 64 MiB is that a multipart
// form post has no progress and no resumption, and neither of those is true
// here. Still bounded, and still under the format table's own ceiling for
// audio and video.
const MaxRecording = 256 << 20

// CookieName is where the credential lives, on this origin only.
const CookieName = "quilzo_studio"

// Server is the capture surface.
type Server struct {
	// Tokens verifies a credential. The same store the admin and the command
	// line read, so revoking a token stops it here too.
	Tokens *auth.TokenStore
	// Policy decides whether the holder may write. Editing a draft, because
	// that is what putting a recording in the library is.
	Policy *auth.Policy
	// Library is where a recording goes.
	Library func() (*medialib.Library, error)
	// Options are the media settings, read per upload.
	Options func() media.Options
	// Throttle counts failed credentials. Not optional in practice: the
	// admin's sign-in form was measured taking forty wrong tokens without
	// once answering 429, and this is the same shape of door.
	Throttle *throttle.Limiter
	// Audit records what happened, so a recording arriving in the library has
	// the same trail as a file somebody uploaded.
	Audit func(action, resource string, detail map[string]string)
	// Now is the clock, for tests.
	Now func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handler is everything this server serves.
//
// Four routes. A fifth would be a reason to ask whether this is still a
// capture surface or has become an application.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.page)
	mux.HandleFunc("/signin", s.signIn)
	mux.HandleFunc("/upload", s.upload)
	mux.HandleFunc("/studio.css", s.stylesheet)
	return headers(mux)
}

// headers sets what does not depend on the route.
//
// Deliberately not the Content-Security-Policy: this server's whole point is
// that one route carries a nonce and the rest carry none, so the policy is
// written per response beside the thing it permits. A blanket policy here
// would be a policy somebody widens once for the recorder and leaves widened
// for the sign-in form.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// nonce is a fresh value for one response.
//
// Per response, never per process. Two responses sharing one nonce means an
// injection into either page carries a value that works on the next — which
// is the property that makes a nonce worth having, and the admin's passkey
// screens have a test asserting exactly this.
func nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// policyFor writes the header for a page that runs the recorder.
//
// blob: in media-src is the one widening beyond the admin's policy that this
// feature actually needs. A recording exists in the page as a Blob before it
// is anywhere else, and previewing it — which is the difference between
// "upload and hope" and "watch it back first" — means a blob: URL in a video
// element. It permits no host: a blob URL belongs to the document that made
// it and cannot name anything outside it.
func policyFor(n string) string {
	return "default-src 'none'; " +
		"script-src 'nonce-" + n + "'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"media-src 'self' blob:; " +
		"connect-src 'self'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
}

// caller is who a request is acting as, or nil.
func (s *Server) caller(r *http.Request) *auth.Token {
	if s.Tokens == nil {
		return nil
	}
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	tok, err := s.Tokens.Authenticate(c.Value, s.now())
	if err != nil {
		return nil
	}
	return tok
}

// mayWrite reports whether this caller may put a recording in the library.
func (s *Server) mayWrite(tok *auth.Token) bool {
	if tok == nil || s.Policy == nil {
		return false
	}
	// Edit-draft, because storing an asset is part of preparing content — the
	// same action the admin's upload is checked against.
	//
	// Both halves, and in this order. The policy says what the person may do;
	// CheckCredential says what this particular token may do, which can be
	// narrower — a token issued as a reader must not write even when its
	// holder could, and one scoped to /blog must not reach the library at
	// all. The admin asks both for the same reason and through the same two
	// functions.
	if !s.Policy.Evaluate(tok.Principal, auth.ActEditDraft, "/").Allowed {
		return false
	}
	return auth.CheckCredential(tok.Role, tok.Resource, tok.Scope,
		auth.ActEditDraft, "/") == nil
}

// signIn takes a token and puts it in a cookie on this origin.
//
// The same credential the admin and the command line take, verified by the
// same store, so revoking it stops this surface too. What this deliberately
// does not have is a session: there is no list to show, nothing to revoke
// separately, and no second notion of identity to get out of step with the
// one in internal/auth.
func (s *Server) signIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Throttled, because the admin's own sign-in box was not and it was
	// measured: forty wrong tokens through the form returned forty 401s and
	// never once a 429, while two through the cookie path were enough to
	// start refusing. A new door with the same shape gets the limiter from
	// the start.
	sub := throttle.Subject{Source: sourceOf(r)}
	if s.Throttle != nil {
		if d := s.Throttle.Check(sub); !d.Allowed {
			http.Error(w, fmt.Sprintf(
				"too many attempts; try again in %s", d.RetryAfter.Round(time.Second)),
				http.StatusTooManyRequests)
			return
		}
	}

	secret := strings.TrimSpace(r.FormValue("token"))
	tok, err := s.Tokens.Authenticate(secret, s.now())
	if err != nil || !s.mayWrite(tok) {
		if s.Throttle != nil {
			s.Throttle.Fail(sub)
		}
		if s.Audit != nil {
			s.Audit("studio.signin.refused", "/", map[string]string{
				"source": sourceOf(r)})
		}
		http.Error(w, "that token cannot put a recording in this library",
			http.StatusUnauthorized)
		return
	}
	if s.Throttle != nil {
		s.Throttle.Succeed(sub)
	}

	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: secret, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		// No Secure flag, and no lie about it: this listens on loopback, the
		// way the admin does, and is reached over whatever tunnel the
		// operator already trusts. Setting Secure on a plain-http loopback
		// origin means the cookie is never stored and the feature silently
		// does not work.
		MaxAge: int((12 * time.Hour).Seconds()),
	})
	if s.Audit != nil {
		s.Audit("studio.signin", "/", map[string]string{"principal": tok.Principal})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sourceOf is who a request is from, for the limiter.
//
// The remote address rather than a header. An X-Forwarded-For somebody else
// sets is a counter somebody else resets, and this server is meant to be on
// loopback where there is no proxy to believe.
func sourceOf(r *http.Request) string {
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
