// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/throttle"
	"github.com/quilzo/quilzo/internal/vector"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/dpop"
	"github.com/quilzo/quilzo/internal/sameorigin"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Server is the content API.
type Server struct {
	Store  *store.Store
	Policy *auth.Policy
	Tokens *auth.TokenStore

	// Ref decides what is served. Live by default: an API that answers with the
	// draft hands anybody with a read token the unpublished content, and "it is
	// only the API" is not a distinction an editor made when they saved.
	Ref string
	// Writable turns on PUT. Off by default, because a read API and a write API
	// are different products with different blast radii, and defaulting to
	// both means every deployment has the larger one.
	Writable bool

	// MaxPage and MaxBody are the configured limits. Zero means the
	// compile-time default, which is what an embedded use and every test
	// wants. See limits.go: both were settings nothing read.
	MaxPage int
	MaxBody int

	Limits Limits
	// Now is injectable for tests.
	Now func() time.Time

	// Types validates writes, so the API cannot put content into the store that
	// the CLI and the admin would have refused.
	Types func() (*schema.Store, error)
	// Index is the decoded-collection cache, shared with the admin when both
	// run in one process. Nil means every listing pays the full scan, which is
	// correct for a test and wrong for anything serving traffic.
	Index *collection.Cache
	// Records serves the collections API. Nil means those routes report that
	// this server does not serve records, which is different from serving an
	// empty one.
	Records *Records
	// Vectors answers similarity queries. Nil means the two vector routes 404,
	// which is the honest state for a server that has not built an index —
	// better than answering with no results, which reads as "nothing is
	// similar" rather than "nothing was indexed".
	Vectors  func() *vector.Index
	Tokenise func(string) []string
	// SessionAuth accepts the admin's session cookie in place of a bearer
	// token, for same-origin requests only. Off unless this server is mounted
	// inside the admin, which is the one place a session exists.
	SessionAuth bool
	// Origin is the admin's own origin as it works it out, for taking its
	// session cookie (sameOrigin): its scheme behind a proxy that ends TLS
	// is a setting (admin.behind_tls_proxy), not this connection's. Nil is
	// this connection's scheme and Host.
	Origin func(r *http.Request) string
	// ReloadTokens re-reads the credential store when it has changed on disk.
	// Nil means never, which is only right for a test.
	ReloadTokens func()
	// ReloadPolicy re-reads the access rules when they have changed on disk,
	// for the same reason. Without it this server decided against the policy
	// it was started with: a grant made while it ran was refused here while
	// the admin, the CLI and /mcp allowed it, and a revoked grant kept working
	// here until a restart. Nil means never, which is only right for a test.
	ReloadPolicy func()
	// Throttle slows repeated authentication failures. Nil disables it, which
	// is for tests; the CLI wires one in from configuration.
	Throttle *throttle.Limiter
	// OnAuthFailure fires when the alerting threshold is crossed, so the host
	// can write an audit record. This package does not open the audit log: it
	// does not know where the log lives, and since the writer was separated
	// out it must not.
	OnAuthFailure func(source string, failures int)
	// OnWrite records a successful write, so the audit trail does not have a
	// hole shaped like the API.
	OnWrite func(principal, page, commit string)
	// OnDelete records a successful deletion of a record, as collection/id.
	// A deletion was told to OnWrite, so the audit log held api.write for
	// it, with the same resource as the write that made the record, and
	// nothing anywhere said it had been deleted. Nil tells OnWrite, so a
	// host told of writes alone has no hole in its trail for deletions.
	OnDelete func(principal, record, commit string)
	// OnBadToken is told every credential presented that did not
	// authenticate, and why, for the shield's decoys and guess counting
	// (internal/shield). Nil tells nobody.
	OnBadToken func(r *http.Request, presented string, err error)
	// OnTokenUsed is told every token that authenticated, so the host can
	// write down when it was last used. This server never saves the store,
	// and the use Authenticate notes in its copy was lost with it: a token
	// used here every day was listed as used "never", and `token stale`
	// offered it for revocation. Nil tells nobody.
	OnTokenUsed func(tok auth.Token)
	// Idle ends a sign-in session nobody has used for a while, and reports
	// whether it did, for a host that keeps that clock: the admin, which
	// mounts this server under `quilzo serve`. Without it a session used
	// only here, in a header or in the cookie, was never idle and lasted
	// the whole of session.max. Nil ends none.
	Idle func(r *http.Request, tok *auth.Token) bool
	// Shield reports whether the shield has turned the content API off for
	// a while. Nil means never.
	Shield func() (until time.Time, on bool)

	limiter *limiter
	// proofs remembers the DPoP proofs spent at the routes that take a
	// token bound to a key, so a proof is good for one request.
	proofs dpop.Replays
}

// Handler routes the API.
func (s *Server) Handler() http.Handler {
	if s.limiter == nil {
		s.limiter = newLimiter(s.Limits)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/pages/", s.page)
	mux.HandleFunc("/api/v1/pages", s.list)
	mux.HandleFunc("/api/v1/collections", s.collections)
	mux.HandleFunc("/api/v1/records/", s.records)
	mux.HandleFunc("/api/v1/similar/", s.similar)
	mux.HandleFunc("/api/v1/replica/ref/", s.replicaRef)
	mux.HandleFunc("/api/v1/replica/object/", s.replicaObject)
	mux.HandleFunc("/api/v1/search/vector", s.vectorSearch)
	// The security modules' routes, each registered from its own file
	// (modules.go) rather than written into this list.
	s.mountModules(mux)
	mux.HandleFunc("/api/v1/", s.notFound)
	// Everything else this handler is given is not found here either, and
	// says so in JSON. Left to the mux, /api/v1 was redirected to /api/v1/
	// with an HTML body, and /api/ and /api/v2/pages were a plain-text
	// "404 page not found", so a client parsing every answer as JSON failed
	// on exactly the ones meant to tell it it had the address wrong.
	mux.HandleFunc("/api/v1", s.notFound)
	mux.HandleFunc("/", s.notFound)
	inner := s.middleware(mux)
	// The description is the same for every server of a kind and says
	// nothing about the content behind it, so it needs no token; everything
	// it describes does.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/openapi.json" {
			s.openAPI(w, r)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// canonicalPath reports whether a path needs no cleaning, checked in both the
// escaped and the decoded form so that %2e%2e and .. are treated alike.
func canonicalPath(u *url.URL) bool {
	for _, p := range []string{u.EscapedPath(), u.Path} {
		if p == "" || p[0] != '/' {
			return false
		}
		if strings.ContainsAny(p, "\x00\r\n") {
			return false
		}
		c := path.Clean(p)
		if strings.HasSuffix(p, "/") && c != "/" {
			c += "/" // a trailing slash is a route here, not noise
		}
		if p != c {
			return false
		}
	}
	return true
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) ref() string {
	if s.Ref == "" {
		return site.RefLive
	}
	return s.Ref
}

// middleware authenticates, limits and sets the headers every response needs.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No cross-origin access. A content API that answers any origin is one
		// where a page on any website can spend a visitor's token, and "it is
		// only reads" stops being true the first time somebody enables writes.
		// There is deliberately no configuration for this yet: the safe version
		// is an allow-list of named origins, and shipping a wildcard switch in
		// the meantime is shipping the thing that gets set to *.
		w.Header().Set("Vary", "Authorization, If-None-Match")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if r.Method == http.MethodOptions {
			s.notAllowed(w, r, Error{
				Error: "cross-origin requests are not accepted",
				Detail: "this API has no CORS configuration, so a browser on " +
					"another origin cannot call it",
				Fix: "call it from a server, with a token that is not in a browser",
			})
			return
		}
		if s.Shield != nil {
			if until, off := s.Shield(); off {
				if secs := int(time.Until(until).Seconds()) + 1; secs > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(secs))
				}
				writeError(w, http.StatusServiceUnavailable, Error{
					Error: "the content API is turned off for a while",
					Fix:   "retry after the time in the Retry-After header",
				})
				return
			}
		}

		// Failed-authentication throttling, separate from the per-token rate
		// limit below. That one bounds what an authenticated client may do;
		// this one bounds how many times an unauthenticated one may guess,
		// and a rate limiter keyed on the token cannot do it because a failed
		// attempt has no token to key on.
		// The throttle blocks failures, not successes.
		//
		// The first version checked the throttle and refused before looking at
		// the credential, which is the obvious order and is wrong. Only the
		// source is known before authentication — a failed attempt carries no
		// identity to count against — so refusing on the source's history
		// means one attacker locks out every legitimate user sharing that
		// address. Behind a NAT or a corporate proxy that is the whole office,
		// and it is precisely the malicious-lockout property the soft delay
		// exists to preserve. Verified in a live run: five bad tokens, and a
		// valid one was then answered 429.
		//
		// So a throttled request is still authenticated, and a valid
		// credential is let through. That is safe because it gives an attacker
		// nothing: a wrong token is still refused, and they learn only what
		// they already knew. Verifying costs one constant-time comparison
		// against a stored hash — deliberately not a slow KDF, because a token
		// is 256 bits of entropy rather than a password — so the check itself
		// is not the expensive thing a throttle is protecting.
		// Re-read the credentials before deciding anything.
		//
		// The store is shared between processes — the admin, the public site and
		// the CLI all hold the same file — and each loaded it once at startup.
		// So a credential revoked through the admin kept working on the site
		// until that container restarted, which makes "revoked" a claim about a
		// file rather than a fact about a credential. Found by revoking a token
		// in one container and watching another keep accepting it.
		//
		// The hook stats the file and reloads only when it has changed, so this
		// is one stat per request rather than a parse.
		if s.ReloadTokens != nil {
			s.ReloadTokens()
		}
		// And the access rules, which are the same kind of shared file and
		// were read once: see ReloadPolicy.
		if s.ReloadPolicy != nil {
			s.ReloadPolicy()
		}

		authSub := throttle.Subject{Source: sourceOf(r)}
		throttled := false
		var tdec throttle.Decision
		if s.Throttle != nil {
			if tdec = s.Throttle.Check(authSub); !tdec.Allowed {
				throttled = true
			}
		}

		tok, err := s.authenticate(r)
		if err != nil {
			if throttled {
				retryAfter(w, tdec)
				writeError(w, http.StatusTooManyRequests, Error{
					Error:  "too many failed authentication attempts",
					Detail: tdec.Why,
					Fix:    "wait for the period in the Retry-After header",
				})
				return
			}
			// A real credential refused during a lockdown is not a guess.
			if s.Throttle != nil && !errors.Is(err, auth.ErrLockedDown) {
				d, alert := s.Throttle.Fail(authSub)
				if alert && s.OnAuthFailure != nil {
					s.OnAuthFailure(authSub.Source, d.Failures)
				}
				if !d.Allowed {
					retryAfter(w, d)
					writeError(w, http.StatusTooManyRequests, Error{
						Error:  "too many failed authentication attempts",
						Detail: d.Why,
					})
					return
				}
			}
			// 401 with no hint about whether the token exists. Distinguishing
			// "no such token" from "wrong password" is how an enumeration
			// oracle gets built by accident.
			w.Header().Set("WWW-Authenticate", `Bearer realm="quilzo"`)
			writeError(w, http.StatusUnauthorized, Error{
				Error: "not authenticated",
				Fix:   "send a token: Authorization: Bearer qz_...",
			})
			return
		}
		if s.Throttle != nil {
			// Keyed on the authenticated principal, not on the source. A
			// success clears that principal's history; the address keeps its
			// failures until they expire, because an address is shared and one
			// person signing in is not evidence that the guessing from it
			// stopped.
			s.Throttle.Succeed(throttle.Subject{Principal: tok.Principal})
		}
		// A sign-in session is the admin's, which keeps its idle clock and
		// mounts this server with it; anywhere else, `quilzo site --api`,
		// there is no clock, and such a session copied into a header
		// lasted the whole of session.max with nobody using it. A token,
		// and a session a program exchanged from one, are taken as before.
		if tok.SignedIn() && s.Idle == nil && !s.SessionAuth {
			w.Header().Set("WWW-Authenticate", `Bearer realm="quilzo"`)
			writeError(w, http.StatusUnauthorized, Error{
				Error: "a sign-in session is not taken here",
				Fix:   auth.SignInElsewhere,
			})
			return
		}
		if s.Idle != nil && s.Idle(r, tok) {
			writeError(w, http.StatusUnauthorized, Error{
				Error: "signed out after a while unused",
				Fix:   "sign in again, or send a token: Authorization: Bearer qz_...",
			})
			return
		}
		if s.OnTokenUsed != nil {
			s.OnTokenUsed(*tok)
		}

		// Checked after authentication, not before. A syntactic rejection is
		// cheap enough to do first, but doing it first means an unauthenticated
		// caller can tell one refusal from another, and a uniform 401 for
		// everything is the property worth keeping.
		//
		// A path that is not already canonical is refused here rather than
		// tidied up and served, because http.ServeMux tidies it up and
		// redirects, and everything about that is wrong for an API.
		//
		// It answers 301 with an HTML body, so a client parsing JSON gets
		// markup. It reflects the requested path into that body. And the
		// target is wherever the cleaning lands, which for
		// /api/v1/pages/x/../../../../admin is /admin — the content API
		// pointing a client at the admin interface.
		//
		// It also made the encoded and unencoded forms behave differently:
		// ..%2f gave 404 where ../ gave 301. Nothing was exploitable, but two
		// parsers disagreeing about what one path means is the shape of the
		// bug rather than an aesthetic complaint, and the disagreement is
		// cheaper to delete than to reason about every time a route is added.
		if !canonicalPath(r.URL) {
			writeError(w, http.StatusNotFound, Error{
				Error: "that path is not in canonical form",
				Detail: "this API does not normalise paths and redirect, " +
					"because a redirect changes which resource is served " +
					"after the request has been authorised",
				Fix: "request the path you mean, without . or .. segments",
			})
			return
		}

		// Limited per token rather than per address. Addresses are shared by
		// everybody behind one office, and limiting them together means one
		// busy client throttles their colleagues.
		//
		// Per token that lasts (RateKey): a session is counted with the
		// token it was exchanged from. Counted by its own id, every session
		// was a new caller with a whole burst, and a token can be exchanged
		// for another as often as its holder likes.
		now, key := s.now(), tok.RateKey()
		ok, remaining, reset := s.limiter.take(key, now)
		w.Header().Set("RateLimit-Limit",
			fmt.Sprintf("%d", s.Limits.withDefaults().PerMinute))
		w.Header().Set("RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("RateLimit-Reset", strconv.Itoa(secondsUntil(reset, now)))
		if !ok {
			// The same instant as RateLimit-Reset, which a refusal has to
			// wait for, and never less than a second.
			w.Header().Set("Retry-After", strconv.Itoa(max(1, secondsUntil(reset, now))))
			writeError(w, http.StatusTooManyRequests, Error{
				Error: "too many requests",
				Detail: "conditional requests that answer 304 are not counted, " +
					"so polling with If-None-Match is cheaper than polling " +
					"without it",
			})
			return
		}

		next.ServeHTTP(&uncounted304{ResponseWriter: w, give: func() {
			left, full := s.limiter.give(key, now)
			w.Header().Set("RateLimit-Remaining", strconv.Itoa(left))
			w.Header().Set("RateLimit-Reset", strconv.Itoa(secondsUntil(full, now)))
		}}, r.WithContext(withToken(r, tok)))
	})
}

// uncounted304 gives back the rate limit's token for an answer that is a 304,
// which the limiter does not count (limiter), and sets that answer's headers
// to say so. Asked at WriteHeader, which is the first moment the status is
// known and the last at which a header can still change.
type uncounted304 struct {
	http.ResponseWriter
	give    func()
	written bool
}

func (u *uncounted304) WriteHeader(code int) {
	if !u.written && code == http.StatusNotModified {
		u.give()
	}
	u.written = true
	u.ResponseWriter.WriteHeader(code)
}

func (u *uncounted304) Write(b []byte) (int, error) {
	u.written = true
	return u.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the connection's own writer.
func (u *uncounted304) Unwrap() http.ResponseWriter { return u.ResponseWriter }

type ctxKey struct{}

func withToken(r *http.Request, t *auth.Token) contextValue {
	return contextValue{r: r, t: t}
}

// contextValue carries the authenticated token without a context package
// dependency in the hot path.
type contextValue struct {
	r *http.Request
	t *auth.Token
}

func (c contextValue) Deadline() (time.Time, bool) { return c.r.Context().Deadline() }
func (c contextValue) Done() <-chan struct{}       { return c.r.Context().Done() }
func (c contextValue) Err() error                  { return c.r.Context().Err() }
func (c contextValue) Value(k any) any {
	if _, ok := k.(ctxKey); ok {
		return c.t
	}
	return c.r.Context().Value(k)
}

func tokenFrom(r *http.Request) *auth.Token {
	if t, ok := r.Context().Value(ctxKey{}).(*auth.Token); ok {
		return t
	}
	return nil
}

// retryAfter sets the header a well-behaved client obeys.
func retryAfter(w http.ResponseWriter, d throttle.Decision) {
	secs := int(d.RetryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}

// sourceOf is the address an attempt came from. RemoteAddr only: a forwarded
// header is set by whatever is in front, and a throttle keyed on a value the
// client controls is one the client switches off by varying it.
func sourceOf(r *http.Request) string { return clientip.SourceFrom(r) }

func (s *Server) authenticate(r *http.Request) (*auth.Token, error) {
	raw, scheme := auth.Presented(r.Header.Get("Authorization"))
	if scheme == "DPoP" {
		return s.authenticateProved(r, raw)
	}
	if scheme != "Bearer" {
		// The admin's session cookie, accepted only when this server is
		// mounted inside the admin and only for a same-origin request.
		//
		// Both conditions matter. The API is otherwise bearer-only, which is
		// what lets it have no CSRF defence at all: a header does not travel
		// automatically and a cookie does. Accepting a cookie without the
		// origin check would hand every API route the vulnerability the
		// bearer-only rule exists to avoid — any page on any site could make
		// a browser send a write with the visitor's session attached.
		//
		// This exists because the playground could not reach the API. Its
		// relative URLs resolve against the admin's origin, the API was on
		// another port, and there is deliberately no CORS — so the console
		// could render perfectly and could not make a single request. Found by
		// clicking Send in a screenshot; no test asserted that a request
		// arrived anywhere.
		if !s.SessionAuth || !s.sameOrigin(r) {
			return nil, fmt.Errorf("no bearer token")
		}
		c, err := r.Cookie("quilzo_token")
		if err != nil || c.Value == "" {
			return nil, fmt.Errorf("no bearer token")
		}
		raw = c.Value
	}
	if s.Tokens == nil {
		return nil, fmt.Errorf("no token store")
	}
	tok, err := s.Tokens.Authenticate(strings.TrimSpace(raw), s.now())
	if err != nil && s.OnBadToken != nil && !errors.Is(err, auth.ErrStepUp) {
		s.OnBadToken(r, strings.TrimSpace(raw), err)
	}
	return tok, err
}

// authenticateProved is a token bound to a key, presented with the
// request's one DPoP proof made by that key, at a route that takes one
// (moduleProved); every other route refuses it, as it always has. The
// proof is checked before the token is looked at, and spent only once the
// token is accepted, as the admin's exchange does (internal/admin's
// proofOf says why).
func (s *Server) authenticateProved(r *http.Request, raw string) (*auth.Token, error) {
	if !moduleProved(r.URL.Path) {
		return nil, auth.ErrKeyBound
	}
	if s.Tokens == nil {
		return nil, fmt.Errorf("no token store")
	}
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return nil, fmt.Errorf("%w: a request carries exactly one DPoP proof", dpop.ErrProof)
	}
	now := s.now()
	p, err := dpop.Verify(proofs[0], r.Method, s.requestURL(r), strings.TrimSpace(raw), now)
	if err != nil {
		return nil, err
	}
	tok, err := s.Tokens.AuthenticateProved(strings.TrimSpace(raw), "", p.Thumbprint, now)
	if err != nil {
		if s.OnBadToken != nil && !errors.Is(err, auth.ErrStepUp) {
			s.OnBadToken(r, strings.TrimSpace(raw), err)
		}
		return nil, err
	}
	if err := s.proofs.Spend(p, now); err != nil {
		return nil, err
	}
	return tok, nil
}

// requestURL is the address a request was made to, as a proof names it:
// this server's origin as its host works it out, and the path.
func (s *Server) requestURL(r *http.Request) string {
	if s.Origin != nil {
		return s.Origin(r) + r.URL.Path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// may checks a permission for the authenticated caller.
func (s *Server) may(r *http.Request, act auth.Action, resource string) error {
	tok := tokenFrom(r)
	if tok == nil {
		return fmt.Errorf("not authenticated")
	}
	// The credential's own limits, checked before the policy. They only ever
	// narrow — a scope is intersected with what the policy allows, never
	// unioned — so checking first is free and gives a better message: the
	// caller learns which dimension stopped them rather than a bare refusal
	// that could be any of them.
	//
	// Through the shared check rather than inline, which is what added the
	// missing one: this consulted the token's role and its scope and not its
	// resource path, so a token issued `--on /blog` reached every page in the
	// store through this API while the command line refused it.
	if err := auth.CheckCredential(tok.Role, tok.Resource, tok.Scope, act,
		resource); err != nil {
		return err
	}
	if s.Policy != nil {
		if d := s.Policy.Evaluate(tok.Principal, act, resource); !d.Allowed {
			return fmt.Errorf("%s", d.Reason)
		}
	}
	return nil
}

// mayInContent is may for a listing or a search, which then asks may of
// every page it answers: whether the caller may act somewhere in the site's
// content, through their credential.
//
// Both asked about "/", which a grant on /blog does not cover and a token
// issued `--on /blog` does not reach, so whoever held part of the site was
// refused the listing and the search of it. The content and not the areas
// (auth.Policy.Anywhere), and the credential asked about its own path
// rather than about "/". The refusal is the one may gives for "/".
func (s *Server) mayInContent(r *http.Request, act auth.Action) error {
	err := s.may(r, act, "/")
	if err == nil {
		return nil
	}
	tok := tokenFrom(r)
	if tok == nil {
		return err
	}
	within := strings.TrimSpace(tok.Resource)
	if within == "" {
		within = "/"
	}
	if auth.CheckCredential(tok.Role, tok.Resource, tok.Scope, act, within) != nil {
		return err
	}
	if s.Policy != nil && !s.Policy.Anywhere(tok.Principal, act) {
		return err
	}
	return nil
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, Error{
		Error: "no such endpoint",
		Fix:   "GET /api/v1/pages or GET /api/v1/pages/{name}",
	})
}

// allow is the methods a path answers on this server, for the Allow header
// RFC 9110 requires of every 405. Empty for a path that is not a route.
//
// One answer for every route, worked out from the path and this server's
// configuration, so a read-only server does not offer the write it refuses.
// Only a page's address set Allow, and it named PUT whether writes were on or
// not; every other 405, the read-only PUT's among them, had none.
func (s *Server) allow(p string) string {
	const reads = "GET, HEAD"
	records := s.Records != nil && s.Records.Tree != nil
	vectors := s.Vectors != nil && s.Tokenise != nil
	switch {
	case p == "/api/v1/openapi.json", p == "/api/v1/pages",
		strings.HasPrefix(p, "/api/v1/replica/ref/"), strings.HasPrefix(p, "/api/v1/replica/object/"),
		moduleRoute(p):
		return reads
	case p == "/api/v1/collections":
		if records {
			return reads
		}
	case p == "/api/v1/search/vector", strings.HasPrefix(p, "/api/v1/similar/"):
		if vectors {
			return reads
		}
	case strings.HasPrefix(p, "/api/v1/pages/"):
		if s.Writable {
			return reads + ", PUT"
		}
		return reads
	case strings.HasPrefix(p, "/api/v1/records/") && records:
		_, id, _ := strings.Cut(strings.TrimPrefix(p, "/api/v1/records/"), "/")
		switch {
		case !s.Records.Writable:
			return reads
		case id == "":
			return reads + ", POST"
		}
		return reads + ", PUT, DELETE"
	}
	// Not a route, or one this server was started without, which answers
	// 404 to every method.
	return ""
}

// notAllowed refuses a method with 405 and the Allow header that goes with it.
func (s *Server) notAllowed(w http.ResponseWriter, r *http.Request, e Error) {
	if a := s.allow(r.URL.Path); a != "" {
		w.Header().Set("Allow", a)
	}
	writeError(w, http.StatusMethodNotAllowed, e)
}

// readMethod reports whether a request reads: GET, or HEAD, which RFC 9110
// asks a server to answer wherever it answers GET. Seven reads took GET alone
// and answered the HEAD a monitor or a cache sends with 405.
func readMethod(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

// list returns a page of pages.
func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	if !readMethod(r) {
		s.notAllowed(w, r, Error{Error: "GET only"})
		return
	}
	if err := s.mayInContent(r, auth.ActView); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}

	offset, limit, err := parsePaging(r.URL.Query(), s.pageMax())
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Error: "bad paging", Detail: err.Error()})
		return
	}

	commit := s.Store.GetRef(s.ref())
	if commit == "" {
		writeError(w, http.StatusServiceUnavailable, Error{
			Error: "nothing is published",
			Fix:   "quilzo publish"})
		return
	}

	pages, tree, err := s.pagesAt(commit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the site could not be read", Detail: err.Error()})
		return
	}
	withheld := s.withhold(pages)

	// The listing's validator is the commit and the pages its publish
	// windows withhold now: if neither has changed, neither has any listing
	// of it. The commit alone was exact until the windows were asked, and
	// then it was not: a page whose embargo lifts at noon changes the
	// listing with the commit unchanged, and a client revalidating with the
	// morning's validator was told 304 and never saw it.
	etag := quote(commit + "-" + fmt.Sprintf("%d-%d", offset, limit) + withheldTag(withheld))
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	names := sortedNames(pages)

	// Total counts what this caller can see, not what exists. Reporting the
	// full count to a scoped token both leaks how much is being hidden and
	// makes paging incoherent: a client asked to fetch 400 items that it will
	// only ever be shown 12 of.
	//
	// And offset, limit and next walk the same pages the total counts. They
	// walked every page in the store, so a token limited to some types was
	// handed pages with nothing on them where the hidden pages fell and a
	// next link past the end of what it could see.
	var visible []string
	for _, n := range names {
		if err := s.may(r, auth.ActView, "/"+n); err != nil {
			// A page the caller cannot see is omitted rather than refused. A
			// listing that fails because one item is restricted tells the
			// caller that item exists.
			continue
		}
		if ok, _ := s.visibleTo(tokenFrom(r), n, pages[n]); !ok {
			// Out of the token's scope, and omitted for the same reason as
			// above: a listing that refuses because one item is out of scope
			// tells the caller that item exists.
			continue
		}
		visible = append(visible, n)
	}
	// Pages is [] when there are none on this page of the listing, as an
	// empty list is on the command line and the machine interface: a nil
	// slice was written "pages": null, and a client iterating it failed
	// where it had nothing to do.
	out := Listing{Pages: []Page{}, Total: len(visible), Offset: offset, Limit: limit,
		Commit: commit}
	for i := offset; i < len(visible) && i < offset+limit; i++ {
		name := visible[i]
		fields, _ := pages[name].(map[string]any)
		out.Pages = append(out.Pages, Page{
			Name: name, Fields: fields, ETag: tree[name],
		})
	}
	if offset+limit < len(visible) {
		out.Next = fmt.Sprintf("/api/v1/pages?offset=%d&limit=%d",
			offset+limit, limit)
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	writeJSON(w, http.StatusOK, out)
}

// page returns or replaces one page.
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/pages/")
	if name == "" || strings.Contains(name, "?") {
		s.notFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.get(w, r, name)
	case http.MethodPut:
		s.put(w, r, name)
	default:
		s.notAllowed(w, r, Error{Error: "method not allowed"})
	}
}

// visibleTo reports whether a scoped token may see a page, and why not.
//
// A page the caller cannot see is omitted from a listing rather than refused,
// for the same reason the resource check already does that: a listing that
// fails because one item is out of scope tells the caller that item exists.
func (s *Server) visibleTo(tok *auth.Token, name string, fields any) (bool, string) {
	if tok == nil || tok.Scope.Empty() {
		return true, ""
	}
	typeName, locale := s.describe(name, fields)
	if !tok.Scope.AllowsType(typeName) || !tok.Scope.AllowsLocale(locale) {
		return false, tok.Scope.Why(auth.ActView, typeName, locale)
	}
	return true, ""
}

// describe finds the content type and locale of a page.
//
// The type comes from the schema store's bindings, which is authoritative. The
// locale comes from the page's own field, because a locale is a property of
// the content rather than of its type — the same type exists in every
// language, which is the entire point of having locales.
func (s *Server) describe(name string, fields any) (typeName, locale string) {
	if s.Types != nil {
		if store, err := s.Types(); err == nil && store != nil {
			if bound, ok := store.Bound[name]; ok {
				typeName = bound
			}
		}
	}
	if m, ok := fields.(map[string]any); ok {
		for _, key := range []string{"locale", "lang", "language"} {
			if v, ok := m[key].(string); ok && v != "" {
				locale = v
				break
			}
		}
	}
	return typeName, locale
}

// readRef is the commit a read of one page is answered from, and whether it
// is the draft read for writing the page (?ref=draft), refusing what cannot
// be had.
//
// A write replaces the page as the draft holds it, and GET serves it as it
// is published. The two are one page until the first write, and after it
// they are not: a client that read the page to edit it a second time was
// given the published ETag, refused 412 by the write, told to read it again
// and given the same ETag, for as long as nobody published. ?ref=draft is
// the read that write is based on, and its ETag is what If-Match on the
// write is compared with.
//
// Asked for rather than given to anybody who may write, because what GET
// serves without it is what is published, and an integration that writes
// with its token may read with it for somebody who should see nothing
// else. On a server that takes writes, to a caller who may write the page
// (get): a read-only API has no write to base on it. ref=live is what is
// published, which is what a read without ref is unless the server was
// started on another ref.
func (s *Server) readRef(w http.ResponseWriter, r *http.Request) (commit string, editing, ok bool) {
	switch r.URL.Query().Get("ref") {
	case "":
		return s.Store.GetRef(s.ref()), false, true
	case site.RefLive:
		return s.Store.GetRef(site.RefLive), false, true
	case site.RefDraft:
		if !s.Writable {
			writeError(w, http.StatusForbidden, Error{
				Error: "the draft is read here to write a page, and this API is read-only",
				Fix:   writableFix,
			})
			return "", false, false
		}
		return s.draftHead(), true, true
	}
	writeError(w, http.StatusBadRequest, Error{
		Error:  "ref is live or draft",
		Detail: "without it a page is answered as it is published",
	})
	return "", false, false
}

// draftHead is the commit a write is made on: the draft, or what is live
// where nothing has been written since.
func (s *Server) draftHead() string {
	if draft := s.Store.GetRef(site.RefDraft); draft != "" {
		return draft
	}
	return s.Store.GetRef(site.RefLive)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, name string) {
	commit, editing, ok := s.readRef(w, r)
	if !ok {
		return
	}
	// The draft is read to write the page, so it takes what writing does.
	act := auth.ActView
	if editing {
		act = auth.ActEditDraft
	}
	if err := s.may(r, act, "/"+name); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}

	pages, tree, err := s.pagesAt(commit)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, Error{
			Error: "nothing is published"})
		return
	}
	oid, ok := tree[name]
	if !ok {
		writeError(w, http.StatusNotFound, Error{Error: "no such page"})
		return
	}
	// Out of scope answers exactly as not-found does, and deliberately so.
	// Answering 403 here would confirm the page exists to a token that was
	// issued precisely so it could not learn that, which turns every scoped
	// token into a way to enumerate the pages it cannot read.
	if visible, _ := s.visibleTo(tokenFrom(r), name, pages[name]); !visible {
		writeError(w, http.StatusNotFound, Error{Error: "no such page"})
		return
	}
	// Outside its publish window it is not published yet, or not any more,
	// and answers as a page that is not there, as the public site does. Not
	// for the draft read, which is the page somebody is writing, embargo and
	// all.
	if !editing && !inWindow(pages[name], s.now()) {
		writeError(w, http.StatusNotFound, Error{Error: "no such page"})
		return
	}

	// The object id is the hash of the content, so this answers exactly the
	// question the header asks: are these the bytes you already have.
	etag := quote(oid)
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	fields, _ := pages[name].(map[string]any)
	p := Page{Name: name, Fields: fields, ETag: oid}
	if s.Types != nil {
		if types, err := s.Types(); err == nil {
			p.Type = types.Bound[name]
		}
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	writeJSON(w, http.StatusOK, p)
}

// writableFix is the command line that turns page writes on, for a refusal
// of one on a read-only API to name. --api-writable alone serves no API: it
// takes --api with it. And --confine=false: the confined site cannot write
// the draft, so it refuses a writable API, and the line this named without
// it did not start. Records are written elsewhere (recordsWritableFix).
const writableFix = "quilzo site --api --api-writable --confine=false"

func (s *Server) put(w http.ResponseWriter, r *http.Request, name string) {
	if !s.Writable {
		s.notAllowed(w, r, Error{
			Error: "this API is read-only",
			Detail: "a read API and a write API are different products with " +
				"different blast radii, so writes are off unless turned on",
			// The site's flag, with the one that serves the API at all: this
			// said `quilzo serve --api-writable`, and serve has no such flag.
			Fix: writableFix,
		})
		return
	}
	if err := s.may(r, auth.ActEditDraft, "/"+name); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	// A name the store cannot hold is asked about here, by the store's own
	// rule, before the lock is taken. It was met only at the commit, and
	// answered 500 "the write failed" for Ürün, "a b" and -dash: a client
	// retries a 5xx, and this refusal is the same however often it is sent.
	if err := store.CheckPath(name); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Error: "that is not a page name the store can hold", Detail: err.Error(),
			Fix: "name the page with ASCII letters, digits, dot, dash and " +
				"underscore, such as about-us or tr/hakkimizda",
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.bodyMax())+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{Error: "cannot read the body"})
		return
	}
	if len(body) > s.bodyMax() {
		writeError(w, http.StatusRequestEntityTooLarge, Error{
			Error: "the body is too large"})
		return
	}

	fields, err := objectBody(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Error: "the body is not a JSON object", Detail: err.Error()})
		return
	}

	// A precondition is required, and If-None-Match: * is one: it is how a
	// page is created without overwriting one (precondition).
	ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
	if strings.TrimSpace(ifMatch) == "" && strings.TrimSpace(ifNone) != "*" {
		writeError(w, http.StatusPreconditionRequired, Error{
			Error: "If-Match is required",
			Detail: "a write without a validator overwrites whatever is there " +
				"now, including somebody else's edit made since you read it",
			Fix: "GET the page with ?ref=draft, then PUT with If-Match set to " +
				"its ETag. To create a page that does not exist yet, send " +
				"If-None-Match: * instead",
		})
		return
	}

	tok := tokenFrom(r)

	// Everything from here to the commit runs under the store's ref lock.
	//
	// Reading the current tree, comparing If-Match against it and then writing
	// are three steps, and without the lock another writer lands between them:
	// sixteen concurrent writes carrying the same ETag all compared equal and
	// all committed, and fifteen edits were lost. If-Match was doing nothing
	// that a comment could not have done.
	//
	// The response is written after the lock is released. Holding a
	// store-wide lock while writing to a socket hands any slow client the
	// ability to stop every writer.
	var (
		cid      string
		conflict *Error
		status   int
		created  bool
	)
	lockErr := s.Store.WithRefLock(func() error {
		draft := s.draftHead()
		pages := map[string]any{}
		if draft != "" {
			if existing, err := site.PagesAt(s.Store, draft); err == nil {
				pages = existing
			}
		}

		_, exists := pages[name]
		// A token limited to some content types or languages writes only
		// what it may read: the page as it stands, answered as get answers
		// it, and the page as it would be, whose language is the body's. A
		// read was asked this and a write was not, so a token issued
		// `--types policy` replaced the product page it was answered 404
		// for, and one issued `--locales fr` wrote a page as English.
		if visible, _ := s.visibleTo(tok, name, pages[name]); exists && !visible {
			status, conflict = http.StatusNotFound, &Error{Error: "no such page"}
			return nil
		}
		if visible, why := s.visibleTo(tok, name, fields); !visible {
			status, conflict = http.StatusForbidden, &Error{Error: "not permitted", Detail: why}
			return nil
		}
		current := ""
		if exists {
			tree, err := s.tree(draft)
			if err != nil {
				status, conflict = http.StatusInternalServerError, &Error{
					Error: "the draft could not be read"}
				return nil
			}
			current = tree[name]
		}
		if e := precondition(ifMatch, ifNone, exists, current, "page",
			"GET it again with ?ref=draft, re-apply your change, and PUT with "+
				"the ETag it answers"); e != nil {
			status, conflict = http.StatusPreconditionFailed, e
			return nil
		}
		created = !exists

		pages[name] = fields

		// The same content-type gate the CLI, the admin and the agent
		// interface go through. An API that could store content the other
		// surfaces refuse would be the fifth write path with a hole in it.
		if s.Types != nil {
			types, err := s.Types()
			if err == nil {
				if failures := types.Gate(pages); len(failures) > 0 {
					var detail []string
					for _, f := range failures {
						detail = append(detail, f.String())
					}
					status, conflict = http.StatusUnprocessableEntity, &Error{
						Error:  "the content does not satisfy its type",
						Detail: strings.Join(detail, "; "),
						Fix:    typeFix(types.Bound[name]),
					}
					return nil
				}
				// And the binding is recorded, which it was not.
				//
				// This gate refused invalid content and then wrote nothing
				// down, while every other write path — the CLI, the admin,
				// MCP, the importer, sections — goes through
				// gateWrite, which records. So a page written here was
				// permanently indistinguishable from one nobody ever checked.
				//
				// internal/admin's wiring states the invariant this breaks:
				// unrecorded reads as unvalidated, which is the safe way
				// round. Safe, and wrong — schema.Validated exists to answer
				// "did this exact content pass this exact type", and for
				// anything written through the API the honest answer was no
				// when the truth was yes.
				types.RecordAll(pages, time.Now())
				if serr := types.Save(); serr != nil {
					// Refused rather than stored with the record missing. A
					// write that cannot be attested is the case this whole
					// gate exists for, and storing it anyway would recreate
					// exactly the hole being closed.
					status, conflict = http.StatusInternalServerError, &Error{
						Error: "the content is valid and the validation " +
							"could not be recorded, so it has not been stored",
						Detail: serr.Error(),
					}
					return nil
				}
			}
		}

		var err error
		cid, err = site.SaveDraftLocked(s.Store, pages,
			"api: write "+name, tok.Principal, draft)
		return err
	})

	if conflict != nil {
		writeError(w, status, *conflict)
		return
	}
	if lockErr != nil {
		var c *site.Conflict
		if errors.As(lockErr, &c) {
			writeError(w, http.StatusConflict, Error{
				Error:  "the draft moved while this request was in flight",
				Detail: c.Error(),
			})
			return
		}
		// The same distinction the records path makes: content failing its
		// type is the caller's problem and answers 422, not 500. Both write
		// paths, because a status code that is right on one endpoint and
		// wrong on the other is the shape of bug this project keeps finding.
		if schema.IsInvalid(lockErr) {
			writeError(w, http.StatusUnprocessableEntity, Error{
				Error:  "this content does not satisfy its type",
				Detail: lockErr.Error(),
				Fix:    s.typeFixFor(func(st *schema.Store) string { return st.Bound[name] }),
			})
			return
		}
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the write failed", Detail: lockErr.Error()})
		return
	}

	if s.OnWrite != nil {
		s.OnWrite(tok.Principal, name, cid)
	}

	tree, _ := s.tree(cid)
	w.Header().Set("ETag", quote(tree[name]))
	// 201 for a page the write made, which RFC 9110 §9.3.4 requires of a
	// PUT that creates; both answered 200, so a client could not tell that
	// its write had made a page rather than changed one.
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, Page{
		Name: name, Fields: fields, ETag: tree[name],
	})
}

// objectBody reads a write's body as the JSON object it must be.
//
// null decodes into a map without an error, as a nil map, so it was taken:
// a page written with the body null was stored with its fields null, and a
// record with none, while every other body that is not an object was
// refused. It is refused with them.
func objectBody(body []byte) (map[string]any, error) {
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("the body is null; send {} for no fields")
	}
	return fields, nil
}

// precondition evaluates a write's If-Match and If-None-Match against what
// it would replace, in the order RFC 9110 §13.2.2 gives, and says why the
// write may not go ahead, or nil. exists is whether there is anything there,
// current its ETag; what names it, and reread is how to read it again.
//
// Both are evaluated, and * means what §13.1 says. If-Match: * is true only
// of something that exists, so it never creates: it created a page here,
// which is the one thing a client sending it asks not to happen, as one
// updating a page somebody has just deleted would. If-None-Match: * is true
// only where nothing exists, which is how a client creates without
// overwriting, and it was refused 428 as though no precondition had been
// sent; beside an If-Match it was not looked at, and a write it should have
// stopped went through.
func precondition(ifMatch, ifNone string, exists bool, current, what, reread string) *Error {
	ifMatch, ifNone = strings.TrimSpace(ifMatch), strings.TrimSpace(ifNone)
	switch {
	case ifMatch == "":
	case !exists:
		return &Error{
			Error:  "no such " + what + ", so nothing matches If-Match",
			Detail: "If-Match, * among them, is a condition that there is one",
			Fix:    "send If-None-Match: * to create it",
		}
	case !matches(ifMatch, quote(current)):
		return &Error{
			Error:  "the " + what + " has changed since you read it",
			Detail: fmt.Sprintf("it is now %s", current),
			Fix:    reread,
		}
	}
	switch {
	case ifNone == "" || !exists:
	case ifNone == "*":
		return &Error{
			Error: "there is such a " + what + " already, and If-None-Match: * " +
				"writes only where there is none",
			Detail: fmt.Sprintf("it is %s", current),
			Fix:    "to replace it, send If-Match with its ETag",
		}
	case matches(ifNone, quote(current)):
		return &Error{
			Error:  "the " + what + " is one that If-None-Match names",
			Detail: fmt.Sprintf("it is %s", current),
		}
	}
	return nil
}

// inWindow reports whether a page's publish window is open at now: its
// starts date passed, its expires date not reached (site.WindowOf).
//
// A window that cannot be read is closed, as on the public site. Open
// would mean a mistyped date lifting an embargo, which is the mistake
// nobody notices.
func inWindow(body any, now time.Time) bool {
	w, err := site.WindowOf(body)
	return err == nil && w.Public(now)
}

// withhold takes the pages whose publish windows are closed now out of a
// page set, and names them in order.
//
// Everything this API serves as published goes through this or inWindow.
// It went through neither: the public site asks every page's window when
// the page is asked for, so that an embargo cannot lift because a job was
// wedged, and this API served a page set to start at noon from the moment
// it was published, by name and in every listing, to any read token, and
// a page past its expires date for as long as it stayed in the tree.
func (s *Server) withhold(pages map[string]any) []string {
	now := s.now()
	var out []string
	for name, body := range pages {
		if !inWindow(body, now) {
			delete(pages, name)
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// withheldTag is what a listing's validator carries for the pages withheld
// from it: nothing when none are, so a site with no window closed keeps the
// validators it had, and otherwise a hash of their names, which changes
// whenever a window opens or closes.
func withheldTag(names []string) string {
	if len(names) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return "-" + hex.EncodeToString(h[:8])
}

func (s *Server) pagesAt(commit string) (map[string]any, map[string]string, error) {
	if commit == "" {
		return nil, nil, fmt.Errorf("nothing published")
	}
	pages, err := site.PagesAt(s.Store, commit)
	if err != nil {
		return nil, nil, err
	}
	tree, err := s.tree(commit)
	if err != nil {
		return nil, nil, err
	}
	return pages, tree, nil
}

func (s *Server) tree(commit string) (map[string]string, error) {
	c, err := s.Store.GetCommit(commit)
	if err != nil {
		return nil, err
	}
	return s.Store.GetTree(c.Tree)
}

// Sweep drops rate-limit state for callers that have gone away.
func (s *Server) Sweep(before time.Time) {
	if s.limiter != nil {
		s.limiter.forget(before)
	}
}

// -- similarity ---------------------------------------------------------------

// similar returns the pages nearest to a given one.
func (s *Server) similar(w http.ResponseWriter, r *http.Request) {
	if !readMethod(r) {
		s.notAllowed(w, r, Error{Error: "GET only"})
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/similar/")
	if name == "" {
		writeError(w, http.StatusNotFound, Error{
			Error: "name a page", Fix: "GET /api/v1/similar/{name}"})
		return
	}
	if err := s.may(r, auth.ActView, "/"+name); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	idx := s.index(w)
	if idx == nil {
		return
	}
	pages, closed, ok := s.closedAt(w, idx)
	if !ok {
		return
	}
	v, ok := idx.Vectors[name]
	visible, _ := s.visibleTo(tokenFrom(r), name, pages[name])
	if !ok || closed[name] || !visible {
		// Not indexed and not found answer alike, because distinguishing them
		// tells a caller which pages exist but hold no text — which is a
		// question about the store, not about similarity. A page outside its
		// publish window is not found either, as it is everywhere else, nor
		// one out of a token's types or languages, as get answers it.
		writeError(w, http.StatusNotFound, Error{
			Error: "no such page, or it has no text to compare"})
		return
	}
	s.answerNeighbours(w, r, idx, v, name, pages, closed)
}

// vectorSearch returns the pages nearest to a query.
func (s *Server) vectorSearch(w http.ResponseWriter, r *http.Request) {
	if !readMethod(r) {
		s.notAllowed(w, r, Error{Error: "GET only"})
		return
	}
	if err := s.mayInContent(r, auth.ActView); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	q := r.URL.Query().Get("q")
	if strings.TrimSpace(q) == "" {
		writeError(w, http.StatusBadRequest, Error{
			Error: "no query", Fix: "GET /api/v1/search/vector?q=..."})
		return
	}
	if len(q) > 2000 {
		// Bounded before tokenising. A very long query is not a query, and
		// the work of embedding it is work somebody else chose for this
		// machine to do.
		writeError(w, http.StatusRequestEntityTooLarge, Error{
			Error: "the query is too long"})
		return
	}
	idx := s.index(w)
	if idx == nil {
		return
	}
	pages, closed, ok := s.closedAt(w, idx)
	if !ok {
		return
	}
	s.answerNeighbours(w, r, idx, idx.Embed(q, s.Tokenise), "", pages, closed)
}

func (s *Server) index(w http.ResponseWriter) *vector.Index {
	if s.Vectors == nil || s.Tokenise == nil {
		writeError(w, http.StatusNotFound, Error{
			Error: "no vector index",
			Detail: "this server was started without one, so there is nothing " +
				"to compare against",
			// The site builds one whenever it serves the API; there is no
			// --vectors flag, which is what this used to name.
			Fix: "quilzo site --api",
		})
		return nil
	}
	idx := s.Vectors()
	if idx == nil {
		writeError(w, http.StatusServiceUnavailable, Error{
			Error: "nothing is published, so nothing is indexed"})
		return nil
	}
	return idx
}

// closedAt is the pages of the commit an index was built from that their
// publish windows withhold now, for leaving out of what it answers.
//
// The index holds every published page, the embargoed among them, so a
// search for a word only an embargoed press release used named it, with
// the words it shared, before its window opened. Asked here, at the time
// of asking, because the index is built once a commit and the windows
// open and close without one.
//
// And the pages whose windows are open, whose fields give each one's
// language (visibleTo).
func (s *Server) closedAt(w http.ResponseWriter, idx *vector.Index) (map[string]any, map[string]bool, bool) {
	pages, err := site.PagesAt(s.Store, idx.Commit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the index could not be queried", Detail: err.Error()})
		return nil, nil, false
	}
	closed := map[string]bool{}
	for _, name := range s.withhold(pages) {
		closed[name] = true
	}
	return pages, closed, true
}

// answerNeighbours writes a result set, filtered by what the caller may see.
func (s *Server) answerNeighbours(w http.ResponseWriter, r *http.Request,
	idx *vector.Index, q vector.Vector, exclude string, pages map[string]any, closed map[string]bool) {

	// Bounded by api.page.max, as every listing is. Similar pages and a
	// search by meaning answered up to the compiled-in hundred whatever it
	// was set to.
	limit := min(10, s.pageMax())
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > s.pageMax() {
			writeError(w, http.StatusBadRequest, Error{
				Error: fmt.Sprintf("limit must be 1 to %d", s.pageMax())})
			return
		}
		limit = n
	}

	// Over-fetched, then filtered, then trimmed. Filtering after the limit
	// would silently return fewer than asked for whenever a neighbour is out
	// of the caller's reach — and the caller cannot tell that from "there were
	// only three".
	found, err := idx.Nearest(q, limit*4, exclude)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the index could not be queried", Detail: err.Error()})
		return
	}
	tok := tokenFrom(r)
	out := make([]vector.Neighbour, 0, limit)
	for _, n := range found {
		if len(out) >= limit {
			break
		}
		if closed[n.Page] {
			continue
		}
		if err := s.may(r, auth.ActView, "/"+n.Page); err != nil {
			continue
		}
		// With its fields, which give its language. Asked of none, which
		// give no language, a token issued `--locales fr` was named the
		// English pages, with the words each shared with what it asked.
		if visible, _ := s.visibleTo(tok, n.Page, pages[n.Page]); !visible {
			continue
		}
		out = append(out, n)
	}

	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{
		"model":   idx.Model,
		"commit":  idx.Commit,
		"results": out,
	})
}

// sameOrigin reports whether a request came from this site's own pages,
// for taking the admin's session cookie (sameorigin.Check).
//
// Sec-Fetch-Site first, because a current browser states the relationship
// directly and cannot be talked out of it. Origin second, for clients that do
// not send it. A request with neither is not a browser and therefore not a
// cross-site request forgery — nothing attached a cookie to it automatically,
// so this door admits it, and a request a person started (none) too.
//
// Origin was asked only whether it ended in "//" and the host, so another
// scheme's pages and "http://evil.example//h" were this server's own. The
// origin is the admin's, as the admin works it out (Origin), since this
// server is mounted at it: taken from this connection alone, its scheme
// behind a proxy that ends TLS was http, so a page the admin's screens
// took as their own was another site's here, and the other way round.
func (s *Server) sameOrigin(r *http.Request) bool {
	own := ""
	if s.Origin != nil {
		own = s.Origin(r)
	} else {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		own = scheme + "://" + r.Host
	}
	return sameorigin.Check(r, own, sameorigin.Policy{None: true, Missing: true})
}
