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
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/a11y"
	"github.com/rsh1k/scrivet/internal/auth"
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

// Handler returns the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handlePages)
	mux.HandleFunc("/page/", s.handlePage)
	mux.HandleFunc("/save", s.handleSave)
	mux.HandleFunc("/review", s.handleReview)
	mux.HandleFunc("/publish", s.handlePublish)
	mux.HandleFunc("/access", s.handleAccess)
	mux.HandleFunc("/preview/", s.handlePreview)
	mux.HandleFunc("/style.css", s.handleCSS)
	return securityHeaders(mux)
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
	fields := flatten(body)

	s.render(w, "edit.html", map[string]any{
		"Title": "Edit " + name, "Principal": p, "Name": name,
		"Fields": fields, "Exists": exists,
		"CanEdit": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/"+name).Allowed,
	})
}

// field is one editable value.
type field struct {
	Key   string
	Value string
	Long  bool
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
			out = append(out, field{Key: k, Value: v, Long: len(v) > 80})
		case float64:
			out = append(out, field{Key: k, Value: fmt.Sprintf("%v", v)})
		case bool:
			out = append(out, field{Key: k, Value: fmt.Sprintf("%v", v)})
		}
	}
	return out
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
	for key, values := range r.Form {
		if strings.HasPrefix(key, "__") || len(values) == 0 {
			continue
		}
		body[key] = values[0]
	}
	pages[name] = body

	msg := r.FormValue("__message")
	if strings.TrimSpace(msg) == "" {
		msg = "edit " + name
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
