package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rsh1k/scrivet/internal/throttle"
	"github.com/rsh1k/scrivet/internal/vector"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/collection"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
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
	// ReloadTokens re-reads the credential store when it has changed on disk.
	// Nil means never, which is only right for a test.
	ReloadTokens func()
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

	limiter *limiter
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
	mux.HandleFunc("/api/v1/search/vector", s.vectorSearch)
	mux.HandleFunc("/api/v1/", s.notFound)
	return s.middleware(mux)
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
			writeError(w, http.StatusMethodNotAllowed, Error{
				Error: "cross-origin requests are not accepted",
				Detail: "this API has no CORS configuration, so a browser on " +
					"another origin cannot call it",
				Fix: "call it from a server, with a token that is not in a browser",
			})
			return
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
			if s.Throttle != nil {
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
			w.Header().Set("WWW-Authenticate", `Bearer realm="scrivet"`)
			writeError(w, http.StatusUnauthorized, Error{
				Error: "not authenticated",
				Fix:   "send a token: Authorization: Bearer scv_...",
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
		ok, remaining, reset := s.limiter.take(tok.ID, s.now())
		w.Header().Set("RateLimit-Limit",
			fmt.Sprintf("%d", s.Limits.withDefaults().PerMinute))
		w.Header().Set("RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("RateLimit-Reset",
			fmt.Sprintf("%d", int(time.Until(reset).Seconds())))
		if !ok {
			w.Header().Set("Retry-After",
				fmt.Sprintf("%d", int(time.Until(reset).Seconds())+1))
			writeError(w, http.StatusTooManyRequests, Error{
				Error: "too many requests",
				Detail: "conditional requests that answer 304 are not counted, " +
					"so polling with If-None-Match is cheaper than polling " +
					"without it",
			})
			return
		}

		next.ServeHTTP(w, r.WithContext(withToken(r, tok)))
	})
}

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
func sourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) authenticate(r *http.Request) (*auth.Token, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
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
		if !s.SessionAuth || !sameOrigin(r) {
			return nil, fmt.Errorf("no bearer token")
		}
		c, err := r.Cookie("scrivet_token")
		if err != nil || c.Value == "" {
			return nil, fmt.Errorf("no bearer token")
		}
		raw = c.Value
	}
	if s.Tokens == nil {
		return nil, fmt.Errorf("no token store")
	}
	return s.Tokens.Authenticate(strings.TrimSpace(raw), s.now())
}

// may checks a permission for the authenticated caller.
func (s *Server) may(r *http.Request, act auth.Action, resource string) error {
	tok := tokenFrom(r)
	if tok == nil {
		return fmt.Errorf("not authenticated")
	}
	// The token's own role caps what this session may do, whatever the policy
	// grants the principal in general. Checking only the policy would make a
	// read-only token a full one the moment its owner was promoted.
	needed, ok := auth.Needs(act)
	if !ok {
		return fmt.Errorf("unknown action")
	}
	if !tok.Role.AtLeast(needed) {
		return fmt.Errorf("this token carries the %s role and %s needs %s",
			tok.Role, act, needed)
	}
	// The token's scope, checked before the policy. A scope only ever narrows
	// — it is intersected with what the policy allows, never unioned — so
	// checking it first is free and gives a better message: the caller learns
	// which of five dimensions stopped them rather than a bare refusal that
	// could be any of them.
	if !tok.Scope.AllowsAction(act) {
		return fmt.Errorf("%s", tok.Scope.Why(act, "", ""))
	}
	if s.Policy != nil {
		if d := s.Policy.Evaluate(tok.Principal, act, resource); !d.Allowed {
			return fmt.Errorf("%s", d.Reason)
		}
	}
	return nil
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, Error{
		Error: "no such endpoint",
		Fix:   "GET /api/v1/pages or GET /api/v1/pages/{name}",
	})
}

// list returns a page of pages.
func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, Error{Error: "GET only"})
		return
	}
	if err := s.may(r, auth.ActView, "/"); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}

	offset, limit, err := parsePaging(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Error: "bad paging", Detail: err.Error()})
		return
	}

	commit := s.Store.GetRef(s.ref())
	if commit == "" {
		writeError(w, http.StatusServiceUnavailable, Error{
			Error: "nothing is published",
			Fix:   "scrivet publish"})
		return
	}
	// The listing's validator is the commit: if the site has not changed,
	// neither has any listing of it. Exact rather than a hash of the response,
	// because the commit already commits to every page in it.
	etag := quote(commit + "-" + fmt.Sprintf("%d-%d", offset, limit))
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	pages, tree, err := s.pagesAt(commit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the site could not be read", Detail: err.Error()})
		return
	}
	names := sortedNames(pages)

	// Total counts what this caller can see, not what exists. Reporting the
	// full count to a scoped token both leaks how much is being hidden and
	// makes paging incoherent: a client asked to fetch 400 items that it will
	// only ever be shown 12 of.
	visible := 0
	for _, n := range names {
		if err := s.may(r, auth.ActView, "/"+n); err != nil {
			continue
		}
		if ok, _ := s.visibleTo(tokenFrom(r), n, pages[n]); ok {
			visible++
		}
	}
	out := Listing{Total: visible, Offset: offset, Limit: limit,
		Commit: commit}
	for i := offset; i < len(names) && i < offset+limit; i++ {
		name := names[i]
		if err := s.may(r, auth.ActView, "/"+name); err != nil {
			// A page the caller cannot see is omitted rather than refused. A
			// listing that fails because one item is restricted tells the
			// caller that item exists.
			continue
		}
		fields, _ := pages[name].(map[string]any)
		if ok, _ := s.visibleTo(tokenFrom(r), name, pages[name]); !ok {
			// Out of the token's scope, and omitted for the same reason as
			// above: a listing that refuses because one item is out of scope
			// tells the caller that item exists.
			continue
		}
		out.Pages = append(out.Pages, Page{
			Name: name, Fields: fields, ETag: tree[name],
		})
	}
	if offset+limit < len(names) {
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
		w.Header().Set("Allow", "GET, HEAD, PUT")
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error: "method not allowed"})
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

func (s *Server) get(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.may(r, auth.ActView, "/"+name); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}

	commit := s.Store.GetRef(s.ref())
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

func (s *Server) put(w http.ResponseWriter, r *http.Request, name string) {
	if !s.Writable {
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error: "this API is read-only",
			Detail: "a read API and a write API are different products with " +
				"different blast radii, so writes are off unless turned on",
			Fix: "scrivet serve --api-writable",
		})
		return
	}
	if err := s.may(r, auth.ActEditDraft, "/"+name); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{Error: "cannot read the body"})
		return
	}
	if len(body) > MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, Error{
			Error: "the body is too large"})
		return
	}

	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Error: "the body is not a JSON object", Detail: err.Error()})
		return
	}

	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		writeError(w, http.StatusPreconditionRequired, Error{
			Error: "If-Match is required",
			Detail: "a write without a validator overwrites whatever is there " +
				"now, including somebody else's edit made since you read it",
			Fix: "GET the page, then PUT with If-Match set to its ETag. For a " +
				"page that does not exist yet, use If-Match: *",
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
	)
	lockErr := s.Store.WithRefLock(func() error {
		draft := s.Store.GetRef(site.RefDraft)
		if draft == "" {
			draft = s.Store.GetRef(site.RefLive)
		}
		pages := map[string]any{}
		if draft != "" {
			if existing, err := site.PagesAt(s.Store, draft); err == nil {
				pages = existing
			}
		}

		if _, exists := pages[name]; exists {
			tree, err := s.tree(draft)
			if err != nil {
				status, conflict = http.StatusInternalServerError, &Error{
					Error: "the draft could not be read"}
				return nil
			}
			if !matches(ifMatch, quote(tree[name])) {
				status, conflict = http.StatusPreconditionFailed, &Error{
					Error:  "the page has changed since you read it",
					Detail: fmt.Sprintf("it is now %s", tree[name]),
					Fix:    "GET it again, re-apply your change, and PUT with the new ETag",
				}
				return nil
			}
		} else if ifMatch != "*" {
			// If-Match on a page that does not exist. RFC 9110 says this
			// fails, and saying so is better than creating it and leaving the
			// client believing it updated something.
			status, conflict = http.StatusPreconditionFailed, &Error{
				Error: "no such page, so nothing matches that validator",
				Fix:   "use If-Match: * to create a page",
			}
			return nil
		}

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
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the write failed", Detail: lockErr.Error()})
		return
	}

	if s.OnWrite != nil {
		s.OnWrite(tok.Principal, name, cid)
	}

	tree, _ := s.tree(cid)
	w.Header().Set("ETag", quote(tree[name]))
	writeJSON(w, http.StatusOK, Page{
		Name: name, Fields: fields, ETag: tree[name],
	})
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
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, Error{Error: "GET only"})
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
	v, ok := idx.Vectors[name]
	if !ok {
		// Not indexed and not found answer alike, because distinguishing them
		// tells a caller which pages exist but hold no text — which is a
		// question about the store, not about similarity.
		writeError(w, http.StatusNotFound, Error{
			Error: "no such page, or it has no text to compare"})
		return
	}
	s.answerNeighbours(w, r, idx, v, name)
}

// vectorSearch returns the pages nearest to a query.
func (s *Server) vectorSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, Error{Error: "GET only"})
		return
	}
	if err := s.may(r, auth.ActView, "/"); err != nil {
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
	s.answerNeighbours(w, r, idx, idx.Embed(q, s.Tokenise), "")
}

func (s *Server) index(w http.ResponseWriter) *vector.Index {
	if s.Vectors == nil || s.Tokenise == nil {
		writeError(w, http.StatusNotFound, Error{
			Error: "no vector index",
			Detail: "this server was started without one, so there is nothing " +
				"to compare against",
			Fix: "scrivet site --vectors",
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

// answerNeighbours writes a result set, filtered by what the caller may see.
func (s *Server) answerNeighbours(w http.ResponseWriter, r *http.Request,
	idx *vector.Index, q vector.Vector, exclude string) {

	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxPageSize {
			writeError(w, http.StatusBadRequest, Error{
				Error: fmt.Sprintf("limit must be 1 to %d", MaxPageSize)})
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
		if err := s.may(r, auth.ActView, "/"+n.Page); err != nil {
			continue
		}
		if visible, _ := s.visibleTo(tok, n.Page, nil); !visible {
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

// sameOrigin reports whether a request came from this site's own pages.
//
// Sec-Fetch-Site first, because a current browser states the relationship
// directly and cannot be talked out of it. Origin second, for clients that do
// not send it. A request with neither is not a browser and therefore not a
// cross-site request forgery — nothing attached a cookie to it automatically.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "cross-site", "same-site":
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		host := r.Host
		return strings.HasSuffix(o, "//"+host)
	}
	return true
}
