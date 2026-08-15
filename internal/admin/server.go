// Package admin serves the editing interface.
//
// # Why this is server-rendered HTML
//
// ATAG 2.0 says the plain thing out loud: a web-based authoring tool "may rely
// on user agent features such as keyboard navigation, find functions, display
// preferences, and undo features" to meet its criteria. A form-and-links admin
// inherits all of that from the browser, correctly, for nothing. A single-page
// app reimplements each one and usually gets at least one wrong — focus after
// navigation, the back button, find-in-page across virtualised lists.
//
// The other reasons point the same way. scrivet is one static binary in a 4 MB
// scratch image with no dependencies; adding a JavaScript build would bring a
// node toolchain, several hundred transitive packages, and a bundle larger than
// the entire program. For a CMS whose argument is that nothing in it executes,
// shipping a framework to render a form would be an odd thing to do.
//
// So: HTML over HTTP, forms that work with scripting disabled, and no build
// step. Progressive enhancement, not degradation.
//
// # Accessibility is structural here
//
// ATAG has two halves and both apply. Part B — does the tool help you produce
// accessible content — is `internal/a11y`, wired into publish. Part A is this
// package: the editing interface must itself be usable by a disabled author,
// which is the half that gets skipped because the people who build CMS admin
// panels are rarely the people locked out of them.
//
// Concretely, and each of these is a thing that is normally wrong:
//
//   - Every control is a real button or link, so it is reachable and operable by
//     keyboard without a single line of script.
//   - Focus is always visible, at 3:1 contrast and a 2px perimeter (WCAG 2.2
//     2.4.13), and never hidden behind a sticky bar (2.4.11).
//   - No action requires dragging (2.5.7). Reordering is a number you type,
//     which is also faster.
//   - Targets are at least 24x24 CSS pixels (2.5.8).
//   - Authentication is pasting a token. No puzzle, no image recognition, no
//     transcription — those are cognitive function tests and 3.3.8 prohibits
//     them.
//   - Status messages announce themselves without stealing focus.
//   - Colour never carries meaning alone; every state has a word.
//
// # Preview
//
// A.3.7.1 wants a preview rendered by a real in-market user agent rather than an
// approximation. So preview serves the actual page to the actual browser instead
// of drawing a picture of it in a panel.
package admin

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/a11y"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/posture"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
	"github.com/rsh1k/scrivet/internal/tmpl"
)

//go:embed assets/*
var assets embed.FS

// Server holds everything a request needs.
type Server struct {
	Store    *store.Store
	Policy   *auth.Policy
	Tokens   *auth.TokenStore
	Template string // the site template, for preview and the a11y check
	tpl      *template.Template

	// Provenance is loaded and saved by the host, so the admin does not need to
	// know where the store keeps it.
	LoadProvenance func() (*provenance.Index, error)
	SaveProvenance func(*provenance.Index) error

	// CheckTypes validates a page set against the site's content types, and is
	// wired to the same schema.Store the CLI uses. Nil means no types are
	// configured, which is different from types that pass: a site with no types
	// is unconstrained, and saying so plainly is better than a silent success.
	CheckTypes func(map[string]any) []schema.Failure
	// TypeFor names the type a page must satisfy, so the editor can render the
	// declared fields rather than whatever keys the page happens to have.
	TypeFor func(page string) (schema.Type, bool)

	// Posture runs the continuous misconfiguration scan. Nil means the host did
	// not wire it, and the dashboard says so rather than rendering an empty
	// page that reads as "nothing is wrong".
	Posture func() posture.Report

	// Reload re-reads credentials and access rules from disk.
	//
	// Without it the server answers from whatever it read at startup, and a
	// revoked token keeps working until somebody restarts the process. That is
	// the same failure as a session outliving its parent: revocation that does
	// not revoke, with a window measured in however long the server has been
	// up. A newly granted role is invisible for just as long, which is the same
	// bug in the direction people notice.
	Reload func() (*auth.Policy, *auth.TokenStore, error)
}

// refresh pulls current credentials and rules before a decision.
//
// Called on every request that authenticates or authorises. Re-reading two small
// JSON files per request is not the bottleneck in a CMS, and the alternative is
// a cache whose staleness is a security property.
func (s *Server) refresh() {
	if s.Reload == nil {
		return
	}
	if pol, toks, err := s.Reload(); err == nil {
		if pol != nil {
			s.Policy = pol
		}
		if toks != nil {
			s.Tokens = toks
		}
	}
}

// New builds the server and parses the admin templates once.
//
// html/template rather than scrivet's own engine, and the distinction matters.
// scrivet's language is deliberately powerless because *users* write in it and
// user templates are an injection surface. These templates are ours, shipped in
// the binary, and never author-supplied — so the stdlib's contextual escaping is
// exactly right and there is no surface to remove.
func New(s *store.Store, p *auth.Policy, ts *auth.TokenStore, siteTemplate string) (*Server, error) {
	t, err := template.New("").Funcs(template.FuncMap{
		"short": func(id string) string {
			if len(id) > 12 {
				return id[:12]
			}
			return id
		},
		"ago": func(unix int64) string {
			if unix == 0 {
				return "never"
			}
			d := time.Since(time.Unix(unix, 0))
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
			case d < 24*time.Hour:
				return fmt.Sprintf("%d hours ago", int(d.Hours()))
			default:
				return fmt.Sprintf("%d days ago", int(d.Hours()/24))
			}
		},
	}).ParseFS(assets, "assets/*.html")
	if err != nil {
		return nil, fmt.Errorf("admin templates: %w", err)
	}
	return &Server{Store: s, Policy: p, Tokens: ts, Template: siteTemplate, tpl: t}, nil
}

// principal is who the current request is acting as.
type principal struct {
	Name string
	Role auth.Role
}

// authenticate resolves a request to a principal.
//
// Bearer token only. There is no password form, which removes password storage,
// reset flows, and credential stuffing in one go — and pasting a token is not a
// cognitive function test, which is what WCAG 2.2 3.3.8 is about.
func (s *Server) authenticate(r *http.Request) (principal, error) {
	s.refresh()
	header := r.Header.Get("Authorization")
	raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if raw == "" {
		if c, err := r.Cookie("scrivet_token"); err == nil {
			raw = c.Value
		}
	}
	if raw == "" {
		return principal{}, fmt.Errorf("no token")
	}
	tok, err := s.Tokens.Authenticate(raw, time.Now())
	if err != nil {
		return principal{}, err
	}
	return principal{Name: tok.Principal, Role: tok.Role}, nil
}

// can checks a permission and writes the refusal itself if there is one.
//
// The refusal says which role was needed. "Forbidden" with no explanation makes
// someone guess or ask an admin for more than they need, which is how access
// creeps upward.
func (s *Server) can(w http.ResponseWriter, p principal, act auth.Action, resource string) bool {
	d := s.Policy.Evaluate(p.Name, act, resource)
	if d.Allowed {
		return true
	}
	w.WriteHeader(http.StatusForbidden)
	s.render(w, "message.html", map[string]any{
		"Title": "Not permitted", "Principal": p,
		"Heading": "You cannot do that here",
		"Body":    d.Reason,
	})
	return false
}

// renderTypeFailures explains a refused save.
//
// The status is 422 rather than 400: the request was well formed and the person
// is allowed to make it, but the content does not satisfy the shape the site
// declared. A 400 would suggest they had done something wrong mechanically, and
// they have not.
func (s *Server) renderTypeFailures(w http.ResponseWriter, p principal,
	page string, failures []schema.Failure) {

	w.WriteHeader(http.StatusUnprocessableEntity)
	s.render(w, "message.html", map[string]any{
		"Title": "Not saved", "Principal": p,
		"Heading":  "This does not match its content type",
		"Page":     page,
		"Failures": failures,
	})
}

func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		// The status is already sent by now, so this can only be logged, not
		// turned into a clean error page.
		fmt.Fprintf(w, "\n<!-- render error: %v -->", err)
	}
}

// securityHeaders applies the same posture as the rest of the project.
//
// The CSP forbids inline script and every external origin. The admin needs no
// script at all, so this is not a restriction anyone has to work around — it is
// a statement that there is nothing to execute, enforced by the browser as well
// as by the architecture.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self' data:; "+
				"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// MaxRequestBody caps a POST. Without a limit a single request can make the
// process allocate until it dies, which needs no credential and no cleverness.
const MaxRequestBody = 2 << 20 // 2 MiB

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// sameSiteOnly refuses cross-origin state changes.
//
// The admin authenticates with a cookie, and a cookie is sent by the browser on
// any request to this origin — including a form on somebody else's page posting
// to /publish. That is CSRF, and it needs no vulnerability in this code beyond
// accepting the request.
//
// SameSite=Strict on the cookie is the primary defence and stops the browser
// sending it at all. This is the second line, because a defence that depends on
// one attribute being set correctly forever is one line too few: `Sec-Fetch-Site`
// is sent by current browsers and states the relationship directly, and `Origin`
// covers the rest. A request that says it came from elsewhere is refused for any
// method that changes something.
func sameSiteOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut &&
			r.Method != http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}

		switch r.Header.Get("Sec-Fetch-Site") {
		case "same-origin", "none", "":
			// same-origin is what we want; none is a direct navigation; empty
			// means a client that does not send it, handled by the Origin check.
		default:
			http.Error(w, "cross-site requests cannot change anything here",
				http.StatusForbidden)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				http.Error(w, "this request came from another origin",
					http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Handler returns the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePages)
	mux.HandleFunc("/page/", s.handlePage)
	mux.HandleFunc("/save", s.handleSave)
	mux.HandleFunc("/security", s.handleSecurity)
	mux.HandleFunc("/security/rules", s.handleRules)
	mux.HandleFunc("/security/rule/", s.handleRule)
	mux.HandleFunc("/review", s.handleReview)
	mux.HandleFunc("/publish", s.handlePublish)
	mux.HandleFunc("/access", s.handleAccess)
	mux.HandleFunc("/provenance", s.handleProvenance)
	mux.HandleFunc("/provenance/set", s.handleProvenanceSet)
	mux.HandleFunc("/history", s.handleHistory)
	mux.HandleFunc("/rollback", s.handleRollback)
	mux.HandleFunc("/preview/", s.handlePreview)
	mux.HandleFunc("/signin", s.handleSignIn)
	mux.HandleFunc("/signout", s.handleSignOut)
	mux.HandleFunc("/style.css", s.handleCSS)
	return securityHeaders(sameSiteOnly(limitBody(mux)))
}

// handleSignIn exchanges a pasted token for a session cookie.
//
// A POST, because the previous version was a GET form: submitting put the token
// in the URL, and from there into browser history, the server's access log, and
// the Referer header of every outbound link. A credential in a URL is a
// credential in several places nobody thinks to clear.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.render(w, "signin.html", map[string]any{"Title": "Sign in"})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.FormValue("token"))
	if _, err := s.Tokens.Authenticate(raw, time.Now()); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "signin.html", map[string]any{
			"Title": "Sign in", "Error": err.Error()})
		return
	}

	// Secure only over TLS, or the cookie is refused on a loopback deployment
	// and nobody can sign in at all — which is how a security attribute gets
	// removed permanently by whoever is trying to get their work done.
	http.SetCookie(w, &http.Cookie{
		Name: "scrivet_token", Value: raw, Path: "/",
		HttpOnly: true,                    // unreadable by script; there is none, but the header outlives that
		SameSite: http.SameSiteStrictMode, // the primary CSRF defence
		Secure:   r.TLS != nil,
		MaxAge:   8 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "scrivet_token", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		http.Error(w, "missing stylesheet", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, err := s.authenticate(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "signin.html", map[string]any{
			"Title": "Sign in", "Error": err.Error(),
		})
		return principal{}, false
	}
	return p, true
}

func (s *Server) handlePages(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActView, "/") {
		return
	}

	draft := s.Store.GetRef(site.RefDraft)
	live := s.Store.GetRef(site.RefLive)
	pages, _ := site.PagesAt(s.Store, site.RefDraft)

	names := make([]string, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Strings(names)

	changed := map[string]bool{}
	if draft != "" && live != "" && draft != live {
		if diffs, err := site.Diff(s.Store, live, draft); err == nil {
			for _, c := range diffs {
				changed[c.Path] = true
			}
		}
	}

	s.render(w, "pages.html", map[string]any{
		"Title": "Pages", "Principal": p, "Names": names,
		"Changed": changed, "Draft": draft, "Live": live,
		"Unpublished": draft != "" && draft != live,
		"CanEdit":     s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
		"CanPublish":  s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed,
	})
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/page/")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	if !s.can(w, p, auth.ActView, "/"+name) {
		return
	}

	pages, _ := site.PagesAt(s.Store, site.RefDraft)
	body, exists := pages[name]

	// A page with a type gets an editor built from the declaration: the right
	// control for each field, the author's own labels, and the fields that are
	// missing shown as empty rather than absent. Without one, fall back to
	// whatever keys the page happens to have — which is all the old editor
	// could ever do, and the reason it could not offer a date picker or say
	// what a field was for.
	var (
		fields   []field
		typeName string
	)
	if s.TypeFor != nil {
		if t, ok := s.TypeFor(name); ok {
			fields, typeName = typedFields(t, body), t.Name
		}
	}
	if fields == nil {
		fields = flatten(body)
	}

	s.render(w, "edit.html", map[string]any{
		"Title": "Edit " + name, "Principal": p, "Name": name,
		"Fields": fields, "Exists": exists, "Type": typeName,
		"CanEdit": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/"+name).Allowed,
	})
}

// field is one editable value.
type field struct {
	Key   string
	Value string
	Long  bool

	// The rest is filled in only when the page has a content type. A field
	// carrying its own label, help text and constraints is the difference
	// between an editor and a JSON form with nicer margins.
	Label    string
	Help     string
	Required bool
	Choices  []string
	Selected map[string]bool
	// Input is the HTML input type. It is chosen from the field kind rather
	// than guessed from the value, so an empty date field is still a date
	// picker and an empty number field still refuses letters.
	Input    string
	MaxLen   int
	Min      string
	Max      string
	Checkbox bool
	Checked  bool
	// AltFor names the field this one describes. Surfacing it in the editor is
	// ATAG 2.0 Part B: the tool helps the author produce accessible content
	// instead of checking afterwards whether they did.
	AltFor string
}

// typedFields builds the editor from a content type.
//
// Fields appear in the order the type declares, not alphabetically and not in
// whatever order the JSON happened to be written. The declaration is the
// author's sequence of thought, and reordering it makes the form read as a list
// of unrelated boxes.
func typedFields(t schema.Type, body any) []field {
	m, _ := body.(map[string]any)

	out := make([]field, 0, len(t.Fields)+4)
	declared := map[string]bool{}
	for _, f := range t.Fields {
		declared[f.Name] = true

		label := f.Label
		if label == "" {
			label = f.Name
		}
		e := field{
			Key: f.Name, Label: label, Help: f.Help, Required: f.Required,
			MaxLen: f.MaxLen, AltFor: f.AltFor, Input: "text",
		}
		switch f.Kind {
		case schema.LongText:
			e.Long = true
		case schema.Number:
			e.Input = "number"
			if f.Min != nil {
				e.Min = fmt.Sprintf("%g", *f.Min)
			}
			if f.Max != nil {
				e.Max = fmt.Sprintf("%g", *f.Max)
			}
		case schema.Date:
			e.Input = "date"
		case schema.URL:
			e.Input = "url"
		case schema.Email:
			e.Input = "email"
		case schema.Boolean:
			e.Checkbox = true
		case schema.Choice:
			e.Choices = f.Choices
		}

		switch v := m[f.Name].(type) {
		case string:
			e.Value = v
		case float64:
			e.Value = fmt.Sprintf("%v", v)
		case bool:
			e.Checked = v
			e.Value = fmt.Sprintf("%v", v)
		case []any:
			// Lists are edited as one value per line. A repeated-input widget
			// needs script to add and remove rows, and the admin has none: the
			// CSP forbids it and the absence is the security argument.
			parts := make([]string, 0, len(v))
			for _, item := range v {
				if str, ok := item.(string); ok {
					parts = append(parts, str)
				}
			}
			e.Value, e.Long = strings.Join(parts, "\n"), true
			e.Help = strings.TrimSpace(e.Help + " One per line.")
		}
		if len(e.Choices) > 0 {
			e.Selected = map[string]bool{e.Value: true}
		}
		out = append(out, e)
	}

	// Anything the page carries that the type does not declare is shown last
	// and marked. Hiding it would let a value the type rejects sit in the page
	// invisibly, blocking every save with an error about a field the editor
	// never displayed.
	extra := make([]string, 0)
	for k := range m {
		if !declared[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		v, _ := m[k].(string)
		out = append(out, field{
			Key: k, Label: k, Value: v, Input: "text",
			Help: "Not declared by " + t.Name + ". Clear this field to remove it.",
		})
	}
	return out
}

// flatten turns a page into a flat list of editable fields.
//
// Only the top level, and only scalars. A generic tree editor for arbitrary JSON
// is where CMS admin panels become unusable — and unusable-with-a-screen-reader
// long before that. Structured content is edited through the CLI or the API
// until there is a design worth defending.
func flatten(body any) []field {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]field, 0, len(keys))
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			out = append(out, field{Key: k, Label: k, Value: v, Long: len(v) > 80,
				Input: "text"})
		case float64:
			out = append(out, field{Key: k, Label: k, Value: fmt.Sprintf("%v", v),
				Input: "text"})
		case bool:
			out = append(out, field{Key: k, Label: k, Value: fmt.Sprintf("%v", v),
				Input: "text"})
		}
	}
	return out
}

// coerceForm turns submitted strings into the shapes the type declares.
//
// An unparseable number is left as the string the person typed rather than
// silently dropped or zeroed. Validation then reports "must be a number", which
// is what happened, instead of the field quietly becoming 0 or vanishing — both
// of which lose work without saying so.
func coerceForm(t schema.Type, form url.Values, body map[string]any) {
	declared := map[string]bool{}

	for _, f := range t.Fields {
		declared[f.Name] = true
		values, present := form[f.Name]

		if f.Kind == schema.Boolean {
			// An unchecked box submits nothing at all, so absence is false
			// here — the one place where a missing key is a real value rather
			// than an omission.
			body[f.Name] = present && len(values) > 0 && values[0] == "true"
			continue
		}
		if !present || len(values) == 0 {
			continue
		}
		raw := values[0]

		switch f.Kind {
		case schema.Number:
			if n, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil {
				body[f.Name] = n
			} else if strings.TrimSpace(raw) == "" {
				delete(body, f.Name)
			} else {
				body[f.Name] = raw
			}
		case schema.List:
			items := []any{}
			for _, line := range strings.Split(raw, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					items = append(items, line)
				}
			}
			body[f.Name] = items
		default:
			// An optional field left blank is removed rather than stored as an
			// empty string. "" is a value, and a URL field holding it would be
			// a page with a link to nowhere.
			if raw == "" && !f.Required {
				delete(body, f.Name)
			} else {
				body[f.Name] = raw
			}
		}
	}

	// Undeclared keys the editor showed: an empty one is a deletion, which is
	// the only way to remove a field the type does not know about.
	for key, values := range form {
		if strings.HasPrefix(key, "__") || declared[key] {
			continue
		}
		if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
			delete(body, key)
			continue
		}
		body[key] = values[0]
	}
}

// handleSecurity is the posture dashboard.
//
// Server-rendered, with no script at all: the CSP on every admin response
// forbids it, and a security dashboard that needs a client-side framework to
// tell you a token is world-readable has the dependency the wrong way round.
func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Reading the posture means reading the access policy, the token store and
	// the audit log. That is administrator information, and gating it on
	// ActManageAccess rather than ActView is the least-privilege reading: a
	// list of exactly where the defences are thin is a target list.
	if !s.can(w, p, auth.ActGrant, "/") {
		return
	}
	if s.Posture == nil {
		s.render(w, "message.html", map[string]any{
			"Title": "Security", "Principal": p,
			"Heading": "The posture scanner is not wired up",
			"Body": "This build serves the admin without a posture scanner, so " +
				"nothing has been checked. An empty dashboard would read as a " +
				"clean one, which is why this says so instead.",
		})
		return
	}

	rep := s.Posture()
	var controls []string
	for c := range rep.Controls {
		controls = append(controls, c)
	}
	sort.Strings(controls)

	s.render(w, "security.html", map[string]any{
		"Title": "Security posture", "Principal": p,
		"Report": rep, "Controls": controls, "Band": band(rep.Score),
	})
}

// band turns the score into a class name, so the colour is decided once.
func band(score int) string {
	switch {
	case score >= 90:
		return "ok"
	case score >= 60:
		return "warn"
	default:
		return "bad"
	}
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActGrant, "/") {
		return
	}
	s.render(w, "rules.html", map[string]any{
		"Title": "What is checked", "Principal": p, "Rules": posture.Rules(),
	})
}

// handleRule answers "why does this matter" for one rule.
//
// The reasoning is a first-class page rather than a tooltip because a finding
// somebody does not understand is a finding they argue with, and the argument
// costs more than the fix.
func (s *Server) handleRule(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActGrant, "/") {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/security/rule/")
	rule, found := posture.Explain(id)
	if !found {
		http.NotFound(w, r)
		return
	}
	s.render(w, "rules.html", map[string]any{
		"Title": rule.Title, "Principal": p, "Rules": []posture.Rule{rule},
	})
}

func (s *Server) handleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("__name")
	if name == "" {
		http.Error(w, "no page name", http.StatusBadRequest)
		return
	}
	if !s.can(w, p, auth.ActEditDraft, "/"+name) {
		return
	}

	pages, _ := site.PagesAt(s.Store, site.RefDraft)
	body := map[string]any{}
	if existing, ok := pages[name].(map[string]any); ok {
		for k, v := range existing {
			body[k] = v
		}
	}
	// A form submits strings and nothing else. A number field arrives as "4"
	// and a checkbox arrives as "true" or not at all, so the type is what says
	// which of those is a number, a boolean or a list. Without this step every
	// typed page would fail its own validation on the first save from the
	// browser, and the fix people would reach for is turning validation off.
	var typ schema.Type
	typed := false
	if s.TypeFor != nil {
		typ, typed = s.TypeFor(name)
	}
	if typed {
		coerceForm(typ, r.Form, body)
	} else {
		for key, values := range r.Form {
			if strings.HasPrefix(key, "__") || len(values) == 0 {
				continue
			}
			body[key] = values[0]
		}
	}
	pages[name] = body

	msg := r.FormValue("__message")
	if strings.TrimSpace(msg) == "" {
		msg = "edit " + name
	}
	// Content types are enforced here as well as in the CLI. This project has
	// twice shipped a rule the terminal honoured and the browser did not, and
	// the browser is where most editing happens.
	if s.CheckTypes != nil {
		if failures := s.CheckTypes(pages); len(failures) > 0 {
			s.renderTypeFailures(w, p, name, failures)
			return
		}
	}

	if _, err := site.SaveDraft(s.Store, pages, msg, p.Name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Redirect after post so a refresh does not re-submit, and so the browser's
	// back button behaves the way the person expects.
	http.Redirect(w, r, "/review?saved="+name, http.StatusSeeOther)
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActView, "/") {
		return
	}

	draft := s.Store.GetRef(site.RefDraft)
	live := s.Store.GetRef(site.RefLive)
	var changes []site.Change
	if draft != "" {
		changes, _ = site.Diff(s.Store, live, draft)
	}

	reports := s.checkAll(draft)
	s.render(w, "review.html", map[string]any{
		"Title": "Review", "Principal": p, "Changes": changes,
		"Reports": reports, "Blocking": a11y.BlockingCount(reports),
		"Saved":      r.URL.Query().Get("saved"),
		"CanPublish": s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed,
		"Nothing":    draft == "" || draft == live,
	})
}

// checkAll renders every page and runs the accessibility checks.
func (s *Server) checkAll(commitID string) []*a11y.Report {
	if commitID == "" || s.Template == "" {
		return nil
	}
	pages, err := site.PagesAt(s.Store, commitID)
	if err != nil {
		return nil
	}
	rendered := map[string]string{}
	for name, body := range pages {
		out, err := tmpl.Render(s.Template, map[string]any{"page": body})
		if err != nil {
			continue
		}
		rendered[name] = out
	}
	return a11y.CheckAll(rendered)
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActPublish, "/") {
		return
	}

	draft := s.Store.GetRef(site.RefDraft)
	reports := s.checkAll(draft)
	blocking := a11y.BlockingCount(reports)
	reason := strings.TrimSpace(r.FormValue("reason"))

	// Provenance is gated here for the same reason accessibility is: a control
	// present on the command line and absent from the interface is a control
	// with a hole in whichever one people actually use — and the interface is
	// the one an editor uses, which is exactly the person likely to be
	// publishing what an assistant wrote.
	unmarked := s.unmarkedPages(draft)
	if len(unmarked) > 0 && reason == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "review.html", map[string]any{
			"Title": "Review", "Principal": p, "Reports": reports,
			"Blocking": blocking, "Unmarked": unmarked, "CanPublish": true,
			"Error": fmt.Sprintf(
				"%d page%s without provenance. EU AI Act Article 50 requires "+
					"AI-generated content to carry a machine-readable mark, and "+
					"unrecorded is not the same as human-written.",
				len(unmarked), plural(len(unmarked))),
		})
		return
	}

	// The same gate as the CLI, for the same reason. An override that is
	// available in the interface but not on the command line, or the reverse, is
	// a control with a hole in whichever one people actually use.
	if blocking > 0 && reason == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "review.html", map[string]any{
			"Title": "Review", "Principal": p, "Reports": reports,
			"Blocking":   blocking,
			"CanPublish": true,
			"Error": fmt.Sprintf(
				"%d blocking accessibility failure%s. Fix them, or give a reason "+
					"to publish anyway — it will be recorded.",
				blocking, plural(blocking)),
		})
		return
	}

	pub, err := site.Publish(s.Store, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "message.html", map[string]any{
		"Title": "Published", "Principal": p,
		"Heading": "Published",
		"Body": fmt.Sprintf("%d change%s are now live. The previous version is "+
			"still stored, so rolling back moves a pointer.",
			len(pub.Changes), plural(len(pub.Changes))),
		"Override": reason,
	})
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActGrant, "/") {
		return
	}

	type row struct {
		Principal string
		Actions   []struct {
			Name    string
			Allowed bool
			Reason  string
		}
	}
	var rows []row
	for _, who := range s.Policy.Principals() {
		rr := row{Principal: who}
		for _, a := range auth.Actions() {
			d := s.Policy.Evaluate(who, a, "/")
			rr.Actions = append(rr.Actions, struct {
				Name    string
				Allowed bool
				Reason  string
			}{string(a), d.Allowed, d.Reason})
		}
		rows = append(rows, rr)
	}

	s.render(w, "access.html", map[string]any{
		"Title": "Access", "Principal": p,
		"Rows": rows, "Bindings": s.Policy.Bindings,
	})
}

// unmarkedPages lists pages with no usable provenance at a commit.
func (s *Server) unmarkedPages(commitID string) []string {
	if commitID == "" || s.LoadProvenance == nil {
		return nil
	}
	idx, err := s.LoadProvenance()
	if err != nil {
		return nil
	}
	c, err := s.Store.GetCommit(commitID)
	if err != nil {
		return nil
	}
	tree, err := s.Store.GetTree(c.Tree)
	if err != nil {
		return nil
	}
	var out []string
	for _, st := range provenance.Unmarked(provenance.Check(idx, tree)) {
		out = append(out, st.Page)
	}
	return out
}

func (s *Server) handleProvenance(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActView, "/") {
		return
	}
	if s.LoadProvenance == nil {
		http.Error(w, "provenance is not configured", http.StatusServiceUnavailable)
		return
	}

	idx, err := s.LoadProvenance()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	draft := s.Store.GetRef(site.RefDraft)
	c, err := s.Store.GetCommit(draft)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tree, _ := s.Store.GetTree(c.Tree)

	type row struct {
		Page, State, SourceType, Model, Disclosure string
		NeedsMark                                  bool
	}
	var rows []row
	for _, st := range provenance.Check(idx, tree) {
		rr := row{Page: st.Page, Disclosure: st.Disclosure, NeedsMark: st.NeedsMark}
		switch {
		case !st.Have:
			rr.State = "unrecorded"
		case st.Stale:
			rr.State = "stale"
		default:
			rr.State = "recorded"
			rr.SourceType = string(st.Record.SourceType)
			rr.Model = st.Record.Model
		}
		rows = append(rows, rr)
	}

	s.render(w, "provenance.html", map[string]any{
		"Title": "Provenance", "Principal": p, "Rows": rows,
		"Saved":   r.URL.Query().Get("saved"),
		"CanEdit": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	})
}

func (s *Server) handleProvenanceSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	page := r.FormValue("page")
	if !s.can(w, p, auth.ActEditDraft, "/"+page) {
		return
	}

	draft := s.Store.GetRef(site.RefDraft)
	c, err := s.Store.GetCommit(draft)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tree, _ := s.Store.GetTree(c.Tree)
	hash, exists := tree[page]
	if !exists {
		http.NotFound(w, r)
		return
	}

	idx, err := s.LoadProvenance()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rec := provenance.Record{
		ContentHash: hash,
		SourceType:  provenance.SourceType(r.FormValue("source")),
		Model:       strings.TrimSpace(r.FormValue("model")),
		// The person signed in is accountable. Article 50 binds a provider or
		// deployer, and a form field inviting someone to type a different name
		// would be an invitation to write down the wrong one.
		Author:     p.Name,
		ReviewedBy: strings.TrimSpace(r.FormValue("reviewed_by")),
	}
	if err := idx.Set(page, rec); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, "message.html", map[string]any{
			"Title": "Not recorded", "Principal": p,
			"Heading": "That provenance could not be recorded", "Body": err.Error(),
		})
		return
	}
	if err := s.SaveProvenance(idx); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/provenance?saved="+page, http.StatusSeeOther)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActView, "/") {
		return
	}
	live := s.Store.GetRef(site.RefLive)
	head := s.Store.GetRef(site.RefDraft)
	if head == "" {
		head = live
	}

	type entry struct {
		ID, Short, Message, Author string
		Live                       bool
	}
	var entries []entry
	hist, err := s.Store.History(head, 30)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, h := range hist {
		entries = append(entries, entry{
			ID: h.ID, Short: h.ID[:12], Message: h.Commit.Message,
			Author: h.Commit.Author, Live: h.ID == live,
		})
	}
	s.render(w, "history.html", map[string]any{
		"Title": "History", "Principal": p, "Entries": entries,
		"CanRollback": s.Policy.Evaluate(p.Name, auth.ActRollback, "/").Allowed,
	})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, p, auth.ActRollback, "/") {
		return
	}
	target := r.FormValue("commit")
	if target == "" {
		http.Error(w, "no commit given", http.StatusBadRequest)
		return
	}
	pub, err := site.Publish(s.Store, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "message.html", map[string]any{
		"Title": "Rolled back", "Principal": p, "Heading": "Rolled back",
		"Body": fmt.Sprintf("live is now %s. %d page%s changed. The version you "+
			"moved away from is still stored, so this is reversible too.",
			target[:12], len(pub.Changes), plural(len(pub.Changes))),
	})
}

// handlePreview serves the real page to the real browser.
//
// ATAG A.3.7.1 asks that a preview either render in an in-market user agent or
// meet UAAG Level A itself. Serving the actual HTML satisfies the first and is
// also simply more honest: a preview panel that approximates the page is a
// second renderer that can disagree with the one readers get.
func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/preview/")
	if !s.can(w, p, auth.ActView, "/"+name) {
		return
	}
	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	body, exists := pages[name]
	if !exists {
		http.NotFound(w, r)
		return
	}
	out, err := tmpl.Render(s.Template, map[string]any{"page": body})
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
