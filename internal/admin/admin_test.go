package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/a11y"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/posture"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
)

// The admin is checked by the same engine it uses on your content.
//
// ATAG has two halves: Part B is whether the tool helps you produce accessible
// content, and Part A is whether the tool is itself usable by a disabled author.
// Part A is the half that gets skipped, because the people who build admin
// panels are rarely the people locked out of them. Running our own checker over
// our own output is the cheapest way to stop that being true here, and it means
// a regression in the interface fails the build rather than waiting for someone
// to complain.

const siteTemplate = `<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head>
<body><h1>{{ page.title }}</h1><p>{{ page.body }}</p></body></html>`

func setup(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Home", "body": "Welcome."},
		"about": map[string]any{"title": "About", "body": "Who we are."},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}

	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "editor", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.Issue("test", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(s, pol, ts, siteTemplate)
	if err != nil {
		t.Fatal(err)
	}
	idx := provenance.NewIndex()
	srv.LoadProvenance = func() (*provenance.Index, error) { return idx, nil }
	srv.SaveProvenance = func(i *provenance.Index) error { idx = i; return nil }
	return srv, secret
}

func get(t *testing.T, srv *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// The dogfooding test. Every admin page must pass the checks we enforce on
// content before publishing.
func TestAdminPagesPassOurOwnAccessibilityChecks(t *testing.T) {
	srv, token := setup(t)

	for _, path := range []string{
		"/", "/page/index", "/review", "/access", "/provenance", "/history",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, srv, path, token)
			if w.Code != http.StatusOK {
				t.Fatalf("%s returned %d", path, w.Code)
			}
			r := a11y.Check(path, w.Body.String())
			if r.Blocks() {
				for _, f := range r.Findings {
					if f.Severity == a11y.Blocking {
						t.Errorf("%s: %s (%s) — %s", path, f.Rule, f.Criterion, f.Detail)
					}
				}
				t.Fatal("the authoring interface fails the checks it enforces on content")
			}
		})
	}
}

// The sign-in page is reached without a token, so it is checked unauthenticated.
func TestSignInPageIsAccessible(t *testing.T) {
	srv, _ := setup(t)
	w := get(t, srv, "/", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a token, got %d", w.Code)
	}
	r := a11y.Check("signin", w.Body.String())
	for _, f := range r.Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("sign-in: %s (%s) — %s", f.Rule, f.Criterion, f.Detail)
		}
	}
}

func TestEveryPageHasASkipLinkAndLandmarks(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/", token).Body.String()

	for _, want := range []string{
		`class="skip"`,             // 2.4.1 Bypass Blocks
		`id="main"`,                // the skip target
		"<nav", "<main", "<header", // landmarks to navigate by
		`aria-label="Sections"`, // a named nav, since there is more than one region
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %s", want)
		}
	}
}

// WCAG 2.2 3.3.8: authentication must not be a cognitive function test. Pasting
// a token is not; a puzzle or a transcription would be.
func TestSignInHasNoPuzzle(t *testing.T) {
	srv, _ := setup(t)
	body := strings.ToLower(get(t, srv, "/", "").Body.String())

	// Look for the mechanism, not the word. The first version of this grepped
	// for "solve" and flagged the sentence "no puzzle to solve" — copy that
	// exists to say the thing is absent. A test that fails on an accurate
	// description of compliance is a test that gets deleted.
	for _, bad := range []string{
		"captcha",         // any of the usual widgets
		"<img",            // image recognition in the auth form
		"data-sitekey",    // recaptcha/hcaptcha/turnstile hook
		"type=\"number\"", // a code to transcribe
	} {
		if strings.Contains(body, bad) {
			t.Errorf("the sign-in form contains %q, which suggests a cognitive "+
				"function test", bad)
		}
	}
	// And the thing that should be there.
	if !strings.Contains(body, "type=\"password\"") {
		t.Error("sign-in should accept a pasted token")
	}
}

func TestNoScriptAnywhere(t *testing.T) {
	srv, token := setup(t)
	for _, path := range []string{
		"/", "/page/index", "/review", "/access", "/provenance", "/history",
	} {
		body := get(t, srv, path, token).Body.String()
		if strings.Contains(strings.ToLower(body), "<script") {
			t.Errorf("%s contains a script tag; the admin works without scripting", path)
		}
		if strings.Contains(body, "onclick=") || strings.Contains(body, "onload=") {
			t.Errorf("%s uses an inline event handler", path)
		}
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	srv, token := setup(t)
	h := get(t, srv, "/", token).Header()
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP should deny by default, got %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("CSP must not permit inline script")
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

// Authorisation is enforced server-side. Hiding a button is presentation; the
// handler refusing is the control.
func TestPermissionsAreEnforcedNotJustHidden(t *testing.T) {
	srv, _ := setup(t)

	// An author may edit drafts but not publish.
	if err := srv.Policy.Grant(auth.Binding{
		Principal: "writer", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/publish", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("an author posting to /publish should get 403, got %d", w.Code)
	}
	// The refusal has to say what was missing, or people ask for more access
	// than they need just to make the error go away.
	if !strings.Contains(w.Body.String(), "publisher") {
		t.Error("the refusal should name the role required")
	}
}

func TestBadTokenIsRefused(t *testing.T) {
	srv, _ := setup(t)
	if w := get(t, srv, "/", "scv_not_a_real_token"); w.Code != http.StatusUnauthorized {
		t.Errorf("a bad token should give 401, got %d", w.Code)
	}
}

// A.3.7.1: a preview should render in a real user agent rather than an
// approximation, so it serves the actual page.
func TestPreviewServesTheRealPage(t *testing.T) {
	srv, token := setup(t)
	w := get(t, srv, "/preview/index", token)
	if w.Code != http.StatusOK {
		t.Fatalf("preview returned %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<h1>Home</h1>") {
		t.Errorf("preview should be the rendered page, got %q", body[:min(120, len(body))])
	}
	if strings.Contains(body, "class=\"bar\"") {
		t.Error("preview must not wrap the page in admin chrome")
	}
}

func TestStylesheetIsServedAndSelfContained(t *testing.T) {
	srv, _ := setup(t)
	w := get(t, srv, "/style.css", "")
	if w.Code != http.StatusOK {
		t.Fatalf("stylesheet returned %d", w.Code)
	}
	css := stripCSSComments(w.Body.String())

	// Declarations only. Checking the raw text flagged two comments that exist
	// to say outlines are never removed — the same mistake as grepping the
	// sign-in page for "solve" and finding "no puzzle to solve". Prose about the
	// absence of a thing is not the thing.
	if strings.Contains(css, "outline: none") || strings.Contains(css, "outline:none") {
		t.Error("the stylesheet removes a focus outline somewhere")
	}
	if strings.Contains(css, "http://") || strings.Contains(css, "https://") {
		t.Error("the stylesheet fetches something external; it should be self-contained")
	}
	if !strings.Contains(css, "prefers-reduced-motion") {
		t.Error("the stylesheet should honour prefers-reduced-motion")
	}
}

// stripCSSComments removes /* ... */ so assertions apply to declarations.
func stripCSSComments(css string) string {
	var b strings.Builder
	for {
		i := strings.Index(css, "/*")
		if i < 0 {
			b.WriteString(css)
			return b.String()
		}
		b.WriteString(css[:i])
		j := strings.Index(css[i:], "*/")
		if j < 0 {
			return b.String()
		}
		css = css[i+j+2:]
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// A server that answers from what it read at startup lets a revoked credential
// keep working until somebody restarts the process — revocation that does not
// revoke, with a window as long as the server's uptime.
func TestRevokedTokensStopWorkingWithoutARestart(t *testing.T) {
	srv, token := setup(t)
	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		return srv.Policy, srv.Tokens, nil
	}

	if w := get(t, srv, "/", token); w.Code != http.StatusOK {
		t.Fatalf("the token should work first: %d", w.Code)
	}

	// Revoke it in the store the server reads from.
	if _, err := srv.Tokens.Revoke(srv.Tokens.Tokens[0].ID); err != nil {
		t.Fatal(err)
	}

	if w := get(t, srv, "/", token); w.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token still worked: %d", w.Code)
	}
}

// The same staleness in the other direction: a newly granted role should apply
// without a restart, which is the half people notice and report.
func TestNewlyIssuedTokensWorkWithoutARestart(t *testing.T) {
	srv, _ := setup(t)
	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		return srv.Policy, srv.Tokens, nil
	}

	if err := srv.Policy.Grant(auth.Binding{
		Principal: "newcomer", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("late", "newcomer", auth.RoleReader, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/", secret); w.Code != http.StatusOK {
		t.Errorf("a token issued after startup did not work: %d", w.Code)
	}
}

// -- vulnerabilities found by audit, kept fixed by these ---------------------

// The sign-in form was a GET, so submitting put the token in the URL — and from
// there into browser history, the access log, and the Referer of every outbound
// link. A credential in a URL is a credential in several places nobody clears.
func TestSignInIsAPostAndNeverPutsTheTokenInAURL(t *testing.T) {
	srv, _ := setup(t)
	body := get(t, srv, "/signin", "").Body.String()

	if strings.Contains(body, `method="get"`) {
		t.Error("the sign-in form is a GET; the token would land in the URL")
	}
	if !strings.Contains(body, `method="post"`) {
		t.Fatal("the sign-in form should POST")
	}
}

func TestSignInSetsAHardenedCookie(t *testing.T) {
	srv, token := setup(t)

	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect after sign-in, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie was set; the form did not actually sign anyone in")
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("the session cookie should be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("SameSite=Strict is the primary CSRF defence and is missing")
	}
}

func TestSignInRefusesABadToken(t *testing.T) {
	srv, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token=scv_nonsense"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("a bad token should be refused, got %d", w.Code)
	}
	if len(w.Result().Cookies()) > 0 {
		t.Error("a rejected sign-in must not set a session cookie")
	}
}

// Cookie authentication means the browser attaches credentials to any request
// to this origin, including a form on someone else's page posting to /publish.
func TestCrossSitePostsCannotChangeAnything(t *testing.T) {
	srv, token := setup(t)

	for _, path := range []string{"/publish", "/save", "/rollback", "/provenance/set"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			// What a browser sends when another site submits a form here.
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			req.Header.Set("Origin", "https://evil.example")

			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("a cross-site POST reached %s: %d", path, w.Code)
			}
		})
	}
}

func TestSameOriginPostsStillWork(t *testing.T) {
	srv, token := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/publish", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", "http://"+req.Host)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Error("the CSRF check is refusing legitimate same-origin requests")
	}
}

func TestAnOriginFromAnotherHostIsRefused(t *testing.T) {
	srv, token := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/publish", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// No Sec-Fetch-Site, as an older client would send. Origin has to catch it.
	req.Header.Set("Origin", "https://evil.example")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("an Origin from another host reached the handler: %d", w.Code)
	}
}

// An unbounded body lets one request make the process allocate until it dies,
// which needs no credential and no cleverness.
func TestOversizedRequestsAreRefused(t *testing.T) {
	srv, token := setup(t)
	huge := strings.Repeat("a", MaxRequestBody+1024)

	req := httptest.NewRequest(http.MethodPost, "/save",
		strings.NewReader("__name=index&body="+huge))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusSeeOther || w.Code == http.StatusOK {
		t.Errorf("a body past the limit was accepted: %d", w.Code)
	}
}

// -- content types -----------------------------------------------------------

// withTypes wires the same schema.Store the CLI uses, the way serve.go does.
func withTypes(t *testing.T, srv *Server) *schema.Store {
	t.Helper()
	st, err := schema.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Registry.Add(schema.Type{
		Name: "article",
		Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true, MaxLen: 40,
				Label: "Headline"},
			{Name: "body", Kind: schema.LongText, Required: true},
			{Name: "canonical", Kind: schema.URL},
			{Name: "minutes", Kind: schema.Number, Min: fp(1), Max: fp(120)},
			{Name: "featured", Kind: schema.Boolean},
			{Name: "tags", Kind: schema.List},
			{Name: "status", Kind: schema.Choice,
				Choices: []string{"draft", "final"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Bind("index", "article"); err != nil {
		t.Fatal(err)
	}
	srv.CheckTypes = st.Gate
	srv.TypeFor = func(page string) (schema.Type, bool) {
		name, bound := st.Bound[page]
		if !bound {
			return schema.Type{}, false
		}
		return st.Registry.Get(name)
	}
	return st
}

func fp(v float64) *float64 { return &v }

func save(t *testing.T, srv *Server, token string, form url.Values,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/save",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// The gate has to hold in the browser, not only in the terminal. Twice before,
// a rule this project enforced in the CLI was absent from the web UI, and the
// web UI is where most editing happens.
func TestTheWebEditorRefusesContentThatFailsItsType(t *testing.T) {
	srv, token := setup(t)
	withTypes(t, srv)

	form := url.Values{
		"__name":    {"index"},
		"title":     {strings.Repeat("x", 60)}, // past MaxLen
		"body":      {"Prose."},
		"canonical": {"javascript:alert(1)"},
		"minutes":   {"999"},
		"status":    {"FINAL"},
		"is_admin":  {"true"}, // undeclared
	}
	w := save(t, srv, token, form)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("the web editor saved content that fails its type: %d", w.Code)
	}
	body := w.Body.String()
	// Each refusal has to name its field, or the person is told "invalid" and
	// left to guess which of seven inputs is wrong.
	for _, want := range []string{"title", "canonical", "minutes", "status", "is_admin"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not mention %s: %s", want, body)
		}
	}

	// Nothing may have been written. A partial save into an immutable store
	// leaves the broken version addressable forever.
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if got := pages["index"].(map[string]any)["title"]; got != "Home" {
		t.Errorf("the draft changed despite the refusal: title is now %v", got)
	}
}

// A form submits strings and nothing else. Without coercion every typed page
// would fail its own validation on the first save from the browser, and the fix
// people reach for is turning validation off.
func TestTheWebEditorSubmitsValuesInTheShapeTheTypeDeclares(t *testing.T) {
	srv, token := setup(t)
	withTypes(t, srv)

	w := save(t, srv, token, url.Values{
		"__name":   {"index"},
		"title":    {"Home"},
		"body":     {"Prose."},
		"minutes":  {"4"},
		"featured": {"true"},
		"tags":     {"one\ntwo\n\n three "},
		"status":   {"final"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("a valid save was refused: %d — %s", w.Code, w.Body.String())
	}

	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body := pages["index"].(map[string]any)

	if n, ok := body["minutes"].(float64); !ok || n != 4 {
		t.Errorf("a number field stored %#v, not a number", body["minutes"])
	}
	if b, ok := body["featured"].(bool); !ok || !b {
		t.Errorf("a boolean field stored %#v, not a bool", body["featured"])
	}
	tags, ok := body["tags"].([]any)
	if !ok || len(tags) != 3 {
		t.Fatalf("a list field stored %#v", body["tags"])
	}
	if tags[2] != "three" {
		t.Errorf("list items should be trimmed, got %q", tags[2])
	}
}

// An unchecked box submits nothing at all. If absence were treated as "leave it
// alone", a boolean could be turned on and never off again through the UI.
func TestUncheckingABoxTurnsItOff(t *testing.T) {
	srv, token := setup(t)
	withTypes(t, srv)

	base := url.Values{"__name": {"index"}, "title": {"Home"}, "body": {"Prose."}}
	on := url.Values{}
	for k, v := range base {
		on[k] = v
	}
	on["featured"] = []string{"true"}
	if w := save(t, srv, token, on); w.Code != http.StatusSeeOther {
		t.Fatalf("setting the box failed: %d", w.Code)
	}

	// Submit the same form with the checkbox absent, as a browser does.
	if w := save(t, srv, token, base); w.Code != http.StatusSeeOther {
		t.Fatalf("clearing the box failed: %d", w.Code)
	}
	pages, _ := site.PagesAt(srv.Store, site.RefDraft)
	if v := pages["index"].(map[string]any)["featured"]; v != false {
		t.Errorf("featured is %#v after unchecking; a boolean that cannot be "+
			"turned off is a one-way switch", v)
	}
}

// The editor is built from the declaration, so an empty date field is still a
// date picker and a choice is still a list of the allowed values.
func TestTheEditorRendersTheDeclaredFieldsNotWhateverThePageHas(t *testing.T) {
	srv, token := setup(t)
	withTypes(t, srv)

	w := get(t, srv, "/page/index", token)
	if w.Code != http.StatusOK {
		t.Fatalf("the editor returned %d", w.Code)
	}
	html := w.Body.String()

	// Declared but absent from the page: it must still appear, or a required
	// field nobody can see blocks every save.
	if !strings.Contains(html, `name="minutes"`) {
		t.Error("a declared field missing from the page was not rendered")
	}
	if !strings.Contains(html, `type="number"`) {
		t.Error("a number field is not a number input")
	}
	if !strings.Contains(html, `type="url"`) {
		t.Error("a URL field is not a url input")
	}
	if !strings.Contains(html, "<select") {
		t.Error("a choice field is not a select, so the allowed values are a " +
			"secret the editor keeps")
	}
	// The label is followed by a required marker, so match the text and the
	// association rather than an exact closing bracket.
	if !strings.Contains(html, `<label for="f-title">Headline`) {
		t.Error("the author's own label was not used, or is not bound to its input")
	}
	if !strings.Contains(html, `maxlength="40"`) {
		t.Error("a length limit the type declares should reach the browser too")
	}

	// And it must still pass the accessibility checks the tool enforces on
	// content — a richer form is the easiest place to lose a label.
	if r := a11y.Check("/page/index", html); r.Blocks() {
		for _, f := range r.Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("typed editor: %s (%s) — %s", f.Rule, f.Criterion, f.Detail)
			}
		}
		t.Fatal("the typed editor fails our own accessibility checks")
	}
}

// -- security posture --------------------------------------------------------

func withPosture(srv *Server, rep posture.Report) {
	srv.Posture = func() posture.Report { return rep }
}

func brokenPosture() posture.Report {
	return posture.Scan(posture.State{
		Policy: &auth.Policy{},
		Server: posture.ServerFacts{AdminAddr: "0.0.0.0:8080"},
		Files: []posture.FileFact{{
			Path: "tokens.json", Mode: 0o644, Exists: true,
			Description: "token hashes"}},
		Now: time.Now(),
	}, nil)
}

// The dashboard lists exactly where the defences are thin, which is a target
// list. Least privilege says the people who can read it are the people who
// could already change it.
func TestThePostureDashboardNeedsAdministrator(t *testing.T) {
	srv, _ := setup(t)
	withPosture(srv, brokenPosture())

	ts := &auth.TokenStore{}
	secret, _, err := ts.Issue("reader", "kit", auth.RoleReader, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.Tokens = ts
	if err := srv.Policy.Grant(auth.Binding{
		Principal: "kit", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/security", "/security/rules"} {
		w := get(t, srv, path, secret)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s returned %d to a reader; a map of the weak spots is "+
				"not view-level information", path, w.Code)
		}
	}
}

// An unwired scanner rendering an empty dashboard would read as a clean one.
// That is the single most misleading thing this page could do.
func TestAnUnwiredScannerSaysSoRatherThanLookingClean(t *testing.T) {
	srv, token := setup(t)
	srv.Posture = nil

	w := get(t, srv, "/security", token)
	body := w.Body.String()
	if strings.Contains(body, "100") && !strings.Contains(body, "not wired") {
		t.Error("a build with no scanner showed a score")
	}
	if !strings.Contains(strings.ToLower(body), "nothing has been checked") {
		t.Errorf("the page does not say it checked nothing: %s", body)
	}
}

func TestTheDashboardShowsFindingsWithTheirFixAndControls(t *testing.T) {
	srv, token := setup(t)
	withPosture(srv, brokenPosture())

	w := get(t, srv, "/security", token)
	if w.Code != http.StatusOK {
		t.Fatalf("the dashboard returned %d", w.Code)
	}
	body := w.Body.String()

	for _, want := range []string{
		"critical",            // the severity
		"0.0.0.0:8080",        // the specific resource
		"chmod 600",           // the remedy
		"SC-7",                // the NIST control
		"A02:2025",            // the OWASP category
		"expose.admin-public", // the rule id, linked to its reasoning
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the dashboard omits %q", want)
		}
	}

	// And it must say what it could not check, or the findings read as the
	// complete picture.
	if !strings.Contains(body, "Not checked") {
		t.Error("the dashboard does not admit what it skipped")
	}
}

// The reasoning is a page, not a tooltip: a finding somebody does not
// understand is a finding they argue with, and the argument costs more than
// the fix.
func TestEveryRuleCanBeExplainedFromTheDashboard(t *testing.T) {
	srv, token := setup(t)
	withPosture(srv, brokenPosture())

	for _, r := range posture.Rules() {
		w := get(t, srv, "/security/rule/"+r.ID, token)
		if w.Code != http.StatusOK {
			t.Errorf("%s has no explanation page: %d", r.ID, w.Code)
			continue
		}
		// Compared with apostrophes stripped from both sides. The template
		// escapes them to &#39;, which is the correct output and would
		// otherwise make this assertion a test of HTML escaping.
		got := strings.ReplaceAll(w.Body.String(), "&#39;", "'")
		if !strings.Contains(got, r.Why[:30]) {
			t.Errorf("%s renders without its reasoning", r.ID)
		}
	}
}

// The dogfooding rule applies here too, and a table of severities is the
// easiest place to signal meaning with colour alone.
func TestTheSecurityPagesPassOurOwnAccessibilityChecks(t *testing.T) {
	srv, token := setup(t)
	withPosture(srv, brokenPosture())

	for _, path := range []string{"/security", "/security/rules"} {
		w := get(t, srv, path, token)
		if w.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, w.Code)
		}
		r := a11y.Check(path, w.Body.String())
		if r.Blocks() {
			for _, f := range r.Findings {
				if f.Severity == a11y.Blocking {
					t.Errorf("%s: %s (%s) — %s", path, f.Rule, f.Criterion, f.Detail)
				}
			}
		}
	}
}
