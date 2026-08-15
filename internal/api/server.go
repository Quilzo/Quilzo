package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
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
	mux.HandleFunc("/api/v1/", s.notFound)
	return s.middleware(mux)
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

		tok, err := s.authenticate(r)
		if err != nil {
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

func (s *Server) authenticate(r *http.Request) (*auth.Token, error) {
	h := r.Header.Get("Authorization")
	raw, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return nil, fmt.Errorf("no bearer token")
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

	out := Listing{Total: len(names), Offset: offset, Limit: limit,
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

	// If-Match is compare-and-swap, and it maps onto the store's own mechanism
	// rather than being a second one alongside it. A client that omits it is
	// writing blind and is told so, rather than being allowed to overwrite
	// whatever happens to be there.
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
	if _, exists := pages[name]; exists {
		tree, err := s.tree(draft)
		if err != nil {
			writeError(w, http.StatusInternalServerError, Error{
				Error: "the draft could not be read"})
			return
		}
		if !matches(ifMatch, quote(tree[name])) {
			writeError(w, http.StatusPreconditionFailed, Error{
				Error:  "the page has changed since you read it",
				Detail: fmt.Sprintf("it is now %s", tree[name]),
				Fix:    "GET it again, re-apply your change, and PUT with the new ETag",
			})
			return
		}
	}

	pages[name] = fields

	// The same content-type gate the CLI, the admin and the agent interface go
	// through. An API that could store content the other surfaces refuse would
	// be the fifth write path with a hole in it.
	if s.Types != nil {
		types, err := s.Types()
		if err == nil {
			if failures := types.Gate(pages); len(failures) > 0 {
				var detail []string
				for _, f := range failures {
					detail = append(detail, f.String())
				}
				writeError(w, http.StatusUnprocessableEntity, Error{
					Error:  "the content does not satisfy its type",
					Detail: strings.Join(detail, "; "),
				})
				return
			}
		}
	}

	tok := tokenFrom(r)
	cid, err := site.SaveDraftFrom(s.Store, pages,
		"api: write "+name, tok.Principal, draft)
	if err != nil {
		var c *site.Conflict
		if errors.As(err, &c) {
			writeError(w, http.StatusConflict, Error{
				Error:  "the draft moved while this request was in flight",
				Detail: c.Error(),
			})
			return
		}
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the write failed", Detail: err.Error()})
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
