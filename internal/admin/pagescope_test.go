// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/checked"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/note"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// scoped builds a server whose policy is whatever the test says, with a token
// for each principal named.
func scoped(t *testing.T, bindings ...auth.Binding) (*Server, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index":       map[string]any{"title": "Home", "body": "Welcome."},
		"about":       map[string]any{"title": "About", "body": "Who we are."},
		"blog/first":  map[string]any{"title": "First", "body": "Hello."},
		"legal/terms": map[string]any{"title": "Terms", "body": "The terms."},
	}
	if _, err := site.SaveDraft(st, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}

	pol := &auth.Policy{}
	for _, b := range bindings {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	ts := &auth.TokenStore{}
	tokens := map[string]string{}
	seen := map[string]bool{}
	for _, b := range bindings {
		if seen[b.Principal] {
			continue
		}
		seen[b.Principal] = true
		secret, _, err := ts.IssueSession("test-"+b.Principal, b.Principal,
			auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		tokens[b.Principal] = secret
	}

	srv, err := New(st, pol, ts, render.OneLayout(siteTemplate))
	if err != nil {
		t.Fatal(err)
	}
	// No content gates in a test that is not about them. cmd/quilzo wires
	// the real set; a nil one is refused by handlePublish, because a build
	// that cannot run the checks must not report that they passed.
	srv.ContentGates = noGates
	idx := provenance.NewIndex()
	srv.LoadProvenance = func() (*provenance.Index, error) { return idx, nil }
	srv.SaveProvenance = func(i *provenance.Index) error { idx = i; return nil }
	ns, err := note.Open(filepath.Join(dir, "notes"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Notes = &Notes{Store: ns}
	srv.Transfer = &Transfer{
		Pages: func() (map[string]any, error) { return pages, nil },
		Save: func(map[string]any, string, string, string) error {
			t.Error("a page was written although the caller may not edit it")
			return nil
		},
	}
	locks := &collab.Locks{}
	locks.Claim("about", "someone", "", time.Now())
	srv.Publishing = &Publishing{
		Envs:           func() (*site.Envs, error) { return &site.Envs{}, nil },
		SaveEnvs:       func(*site.Envs) error { return nil },
		Schedule:       func() (*schedule.Schedule, error) { return &schedule.Schedule{}, nil },
		UpdateSchedule: func(func(*schedule.Schedule) error) error { return nil },
	}
	srv.Locks = func() (*collab.Locks, error) { return locks, nil }
	srv.SaveLocks = func(*collab.Locks) error {
		t.Error("a lock was released although the caller may not edit the page")
		return nil
	}
	cs, err := checked.Open(filepath.Join(dir, "checked"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Checked = &Checked{Store: cs}
	return srv, tokens
}

// A deny scoped to a path binds here, the same as it does on the command line.
//
// It did not. Every handler that read a page name out of the form asked
// whether the caller could act on "/", and an admin denied author on /about
// still holds admin on "/", so the deny never matched:
//
//	quilzo note add about "…"             denied author on /about
//	POST /notes/add page=about text=…     200, and the note was written
//
// The browser is where the deny is displayed, on the people screen, as a rule.
// Somebody reads it there and believes it.
func TestADenyOnAPathBindsInTheBrowser(t *testing.T) {
	srv, tok := scoped(t,
		auth.Binding{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"},
		auth.Binding{Principal: "editor", Role: auth.RoleAuthor,
			Resource: "/about", Deny: true},
	)

	for _, tc := range []struct{ path, body string }{
		{"/notes/add", "page=about&text=a remark"},
		{"/checked/set", "page=about&back=/"},
		{"/checked/own", "page=about&owner=finance&back=/"},
		{"/transfer/starter", "name=blog&page=about&overwrite=1"},
		{"/publishing/lock/release", "page=about&holder=someone"},
	} {
		w := postForm(t, srv, tc.path, tok["editor"], tc.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s (%s) answered %d; the deny on /about did not "+
				"bind, so the command line refuses this and the browser does "+
				"not", tc.path, tc.body, w.Code)
		}
	}
}

// The assistant writes whatever the proposal names, so every name is checked.
func TestAcceptingAProposalChecksEveryPageItNames(t *testing.T) {
	srv, tok := scoped(t,
		auth.Binding{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"},
		auth.Binding{Principal: "editor", Role: auth.RoleAuthor,
			Resource: "/about", Deny: true},
	)
	srv.Assist = &Assist{
		Pages: func() (map[string]any, error) { return map[string]any{}, nil },
		Save: func(map[string]any, string, string, string) error {
			t.Error("the proposal was written although it named a denied page")
			return nil
		},
	}
	proposal := `{"pages":{"about":{"title":"T","body":"B"}}}`
	w := postForm(t, srv, "/assist/accept", tok["editor"],
		"overwrite=1&model=m&proposal="+url.QueryEscape(proposal)+
			"&seal="+srv.sealProposal("editor", "m", proposal))
	if w.Code != http.StatusForbidden {
		t.Errorf("accepting a proposal naming a denied page answered %d", w.Code)
	}
}

// And the other direction: a grant scoped to a path is usable.
//
// covers("/blog", "/") is false, so asking whether a /blog author may act on
// "/" refused them everything — the pages list, their own page's notes, a
// review date inside their own scope. The editor rendered and every control in
// it answered 403.
func TestAnAuthorScopedToAPathCanUseTheBrowser(t *testing.T) {
	srv, tok := scoped(t, auth.Binding{
		Principal: "bea", Role: auth.RoleAuthor, Resource: "/blog"})

	if w := get(t, srv, "/", tok["bea"]); w.Code != http.StatusOK {
		t.Fatalf("the pages screen answered %d for an author scoped to /blog; "+
			"the front door of the interface was shut to anybody narrowed to "+
			"part of the site", w.Code)
	}
	for _, tc := range []struct {
		path, body string
		want       int
	}{
		{"/notes/add", "page=blog/first&text=inside my scope", http.StatusSeeOther},
		{"/notes/add", "page=legal/terms&text=outside it", http.StatusForbidden},
		{"/checked/set", "page=blog/first&back=/", http.StatusSeeOther},
		{"/checked/set", "page=legal/terms&back=/", http.StatusForbidden},
		{"/checked/own", "page=blog/first&owner=bea&back=/", http.StatusSeeOther},
		{"/checked/own", "page=legal/terms&owner=bea&back=/", http.StatusForbidden},
	} {
		w := postForm(t, srv, tc.path, tok["bea"], tc.body)
		if w.Code != tc.want {
			t.Errorf("POST %s (%s) answered %d, want %d",
				tc.path, tc.body, w.Code, tc.want)
		}
	}
}

// The listing is what they may read, not everything that exists.
//
// A list naming pages somebody cannot open is a worse answer than a refusal:
// it tells them the pages exist and what they are called, which is most of
// what a scope was drawn to withhold.
func TestTheListingIsWhatTheReaderMayRead(t *testing.T) {
	srv, tok := scoped(t, auth.Binding{
		Principal: "bea", Role: auth.RoleAuthor, Resource: "/blog"})

	body := get(t, srv, "/", tok["bea"]).Body.String()
	if !strings.Contains(body, "blog/first") {
		t.Error("the pages screen does not list blog/first, which is the one " +
			"page this author is scoped to")
	}
	for _, hidden := range []string{"legal/terms", "about"} {
		if strings.Contains(body, hidden) {
			t.Errorf("the pages screen names %s to an author scoped to /blog", hidden)
		}
	}
}

// A handler that knows a page name does not ask about the site.
//
// A source walk rather than a list, because this is a convention and the
// convention is exactly what did not hold: eight handlers read a page name and
// then authorised "/", and nothing said so. A list would need updating by the
// same person who forgot.
func TestNoHandlerReadsAPageNameAndAuthorisesTheWholeSite(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	var bad []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), file, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if !namesAPage(fd) {
				continue
			}
			checked++
			if where := authorisesTheSite(fd); where != "" {
				bad = append(bad, file+": "+fd.Name.Name+" reads a page name "+
					"and then "+where)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("only %d handlers look like they name a page; the walk is "+
			"wrong and a test that inspects nothing passes", checked)
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s. Use canPage with that name — a check against \"/\" is "+
			"covered only by a binding on the whole site, so a grant scoped "+
			"to a path refuses the person and a deny scoped to a path does "+
			"not bind at all", b)
	}
}

// namesAPage reports whether a function reads a page name out of the request.
func namesAPage(fd *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fd, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "FormValue" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if ok && lit.Value == `"page"` {
			found = true
		}
		return true
	})
	return found
}

// authorisesTheSite reports a can() call whose resource is the literal "/".
func authorisesTheSite(fd *ast.FuncDecl) string {
	out := ""
	ast.Inspect(fd, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "can", "mayUse":
		default:
			return true
		}
		last, ok := call.Args[len(call.Args)-1].(*ast.BasicLit)
		if ok && last.Value == `"/"` {
			out = "authorises \"/\" with " + sel.Sel.Name
		}
		return true
	})
	return out
}

// Publishing asks about every page the publish would change, and an export
// about every page it holds, so a deny on one page is not passed over by
// the check on the whole site.
func TestPublishAndExportAskAboutEachPage(t *testing.T) {
	srv, token := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "editor", Role: auth.RolePublisher,
		Resource: "/about", Deny: true}); err != nil {
		t.Fatal(err)
	}
	w := postForm(t, srv, "/publish", token, "reason=go")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "about") {
		t.Errorf("a publish changing a page the editor may not publish answered %d", w.Code)
	}
	if srv.Store.GetRef(site.RefLive) != "" {
		t.Fatal("it was published")
	}

	if err := srv.Policy.Grant(auth.Binding{Principal: "editor", Role: auth.RoleReader,
		Resource: "/about", Deny: true}); err != nil {
		t.Fatal(err)
	}
	srv.Transfer = &Transfer{Pages: func() (map[string]any, error) {
		return map[string]any{"index": map[string]any{"title": "Home"}, "about": map[string]any{"title": "About"}}, nil
	}}
	w = postForm(t, srv, "/transfer/export", token, "format=json")
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "not+yours") && !strings.Contains(loc, "not%20yours") {
		t.Errorf("an export went round a deny: %d %s", w.Code, loc)
	}
}

// blogSession signs a whole-site administrator in through a credential issued
// `--on /blog`, which is narrower than the person.
func blogSession(t *testing.T, srv *Server, who string) string {
	t.Helper()
	secret, _, err := srv.Tokens.IssueSession("blog-only", who, auth.RoleAdmin,
		"/blog", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// A bulk action asks about the credential as well as the person.
//
// Both bulk loops asked the policy alone, which is a question about the
// person. An administrator signing in with a credential issued `--on /blog`
// was refused POST /page/delete for about, and could remove about and index
// through /pages/bulk, or record legal/terms as reviewed, because the person
// may and nobody asked whether this session could.
func TestABulkActionIsCappedByTheCredentialsPath(t *testing.T) {
	srv, _ := scoped(t, auth.Binding{
		Principal: "ada", Role: auth.RoleAdmin, Resource: "/"})
	blog := blogSession(t, srv, "ada")

	if w := postForm(t, srv, "/page/delete", blog, "name=about"); w.Code != http.StatusForbidden {
		t.Fatalf("control: the single removal answered %d for a /blog session", w.Code)
	}

	w := postForm(t, srv, "/pages/bulk", blog,
		"page=about&page=index&confirm-remove=1")
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "e=") {
		t.Errorf("a bulk removal outside the credential's path was not refused: "+
			"%d %s", w.Code, loc)
	}
	pages := mustPages(t, srv)
	for _, name := range []string{"about", "index"} {
		if _, ok := pages[name]; !ok {
			t.Errorf("a session scoped to /blog removed %s through /pages/bulk", name)
		}
	}

	w = postForm(t, srv, "/pages/bulk", blog, "page=legal/terms&checked=1")
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "e=") {
		t.Errorf("a bulk check outside the credential's path was not refused: "+
			"%d %s", w.Code, loc)
	}
	if recs, err := srv.Checked.Store.All(); err == nil && len(recs) > 0 {
		t.Errorf("a session scoped to /blog recorded a check outside it: %+v", recs)
	}

	// And inside the path it still works, so the fix is not a refusal of
	// everything.
	w = postForm(t, srv, "/pages/bulk", blog, "page=blog/first&checked=1")
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "m=") {
		t.Errorf("a bulk check inside the credential's path was refused: %d %s",
			w.Code, loc)
	}
}

// The screens that list pages one at a time ask about the credential too.
//
// The same question as the bulk loops, asked the same wrong way: the pages
// list, the notes screen and a link followed inside a preview filtered each
// page by the policy alone. A credential issued `--on /blog` to a whole-site
// administrator was shown every page's name and every page's remarks, which
// quote the content, past the path it was issued for.
func TestAListingIsCappedByTheCredentialsPath(t *testing.T) {
	srv, _ := scoped(t, auth.Binding{
		Principal: "ada", Role: auth.RoleAdmin, Resource: "/"})
	blog := blogSession(t, srv, "ada")
	for _, page := range []string{"blog/first", "legal/terms"} {
		if _, err := srv.Notes.Store.Add(note.Note{Page: page, Author: "ada",
			Text: "remark on " + page}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	body := get(t, srv, "/", blog).Body.String()
	if !strings.Contains(body, "blog/first") {
		t.Error("the pages screen does not list blog/first, which is inside " +
			"the credential's path")
	}
	if strings.Contains(body, "legal/terms") {
		t.Error("the pages screen names legal/terms to a session scoped to /blog")
	}

	body = get(t, srv, "/notes", blog).Body.String()
	if !strings.Contains(body, "remark on blog/first") {
		t.Error("the notes screen does not show the note inside the " +
			"credential's path")
	}
	if strings.Contains(body, "remark on legal/terms") {
		t.Error("the notes screen shows a note on legal/terms to a session " +
			"scoped to /blog")
	}

	if w := get(t, srv, "/about", blog); w.Code != http.StatusNotFound {
		t.Errorf("a preview link to about answered %d for a session scoped to "+
			"/blog, which says the page exists", w.Code)
	}
}

// And the figures on Today count what the pages screen lists.
//
// Both counts asked the policy alone. A credential issued `--on /blog` to a
// whole-site administrator was listed one page on the pages screen and told
// on Today that the draft held four, and that four were waiting to be
// published: the size of what the path was drawn to withhold, which the
// listing had stopped giving away.
func TestTodaysFiguresAreCappedByTheCredentialsPath(t *testing.T) {
	srv, _ := scoped(t, auth.Binding{
		Principal: "ada", Role: auth.RoleAdmin, Resource: "/"})
	req := httptest.NewRequest(http.MethodGet, "/today", nil)
	req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: blogSession(t, srv, "ada")})
	p, err := srv.authenticate(req)
	if err != nil {
		t.Fatal(err)
	}

	pages := -1
	for _, it := range srv.glance(p, map[string]bool{"pages": true}, time.Now()).Items {
		if it.Href == "/" {
			pages = it.N
		}
	}
	if pages != 1 {
		t.Errorf("Today counted %d pages for a session scoped to /blog, which "+
			"may read only blog/first", pages)
	}
	if n := srv.unpublishedFor(p); n != 1 {
		t.Errorf("Today counted %d unpublished pages for a session scoped to "+
			"/blog, which may read only blog/first", n)
	}
}
