package admin

import (
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/agentwatch"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/compliance"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/csp"
	"github.com/quilzo/quilzo/internal/ext"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/taxonomy"
	"github.com/quilzo/quilzo/internal/webhook"
)

// Every screen is opened, by a test that finds them rather than by a list.
//
// The old version of this named six paths. It passed for as long as those six
// worked, which is why a footer link to a page nothing served survived every
// pass anybody made over this product, and why twenty-six capabilities could be
// missing from the interface without a single test noticing.
//
// So this walks the mux, opens everything that answers a GET, and requires each
// one to render and to pass the accessibility checks this project enforces on
// other people's content. A screen added later is covered the moment it is
// registered, with nobody remembering to add it here.
//
// It also catches the class of bug that unit tests structurally cannot: a
// template that references a field the handler does not set renders as a
// half-page with an HTML comment at the bottom, and every package's own tests
// stay green.
func TestEveryScreenRendersAndIsAccessible(t *testing.T) {
	srv, token := fullyWired(t)

	served := servedRoutes(t)
	// A skip has to be written down, or it is indistinguishable from a screen
	// nobody thought to check — which is the failure this whole test exists to
	// stop being possible. Every entry is asserted to be a real route below, so
	// one that becomes stale fails rather than quietly excusing nothing.
	for path := range notAScreen {
		if !served[path] {
			t.Errorf("%q is excused from this test and is not a route; the "+
				"exemption is stale", path)
		}
	}

	routes := make([]string, 0)
	for r := range served {
		// A path pattern ending in "/" is a subtree, and the parent screen is
		// what a person opens. /page/ and /preview/ need a name after them, and
		// /api/ is not a screen at all.
		if strings.HasSuffix(r, "/") && r != "/" {
			continue
		}
		if _, excused := notAScreen[r]; excused {
			continue
		}
		routes = append(routes, r)
	}
	sort.Strings(routes)
	if len(routes) < 25 {
		t.Fatalf("found %d screens; the parse is wrong and a test that opens "+
			"nothing passes", len(routes))
	}

	rendered := 0
	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			w := get(t, srv, path, token)
			switch w.Code {
			case http.StatusMethodNotAllowed:
				// A write-only route. Correct, and not a screen.
				return
			case http.StatusOK:
			default:
				t.Fatalf("%s answered %d\n%s", path, w.Code,
					firstLines(w.Body.String(), 6))
			}
			rendered++

			body := w.Body.String()
			// A template that referenced something the handler did not supply
			// renders most of a page and appends this. The status is already
			// 200 by then, so nothing else can catch it.
			if strings.Contains(body, "<!-- render error:") {
				t.Fatalf("%s rendered with a template error:\n%s", path,
					body[strings.Index(body, "<!-- render error:"):])
			}
			if !strings.Contains(body, "</html>") {
				t.Fatalf("%s stopped rendering part-way through", path)
			}

			rep := a11y.Check(path, body)
			for _, f := range rep.Findings {
				if f.Severity == a11y.Blocking {
					t.Errorf("%s: %s (%s) — %s", path, f.Rule, f.Criterion, f.Detail)
				}
			}
		})
	}
	if rendered < 20 {
		t.Errorf("only %d screens rendered; the rest answered 405, which "+
			"means this test is checking almost nothing", rendered)
	}
}

// Every screen has to say something when its capability was not wired in.
//
// A server built without the hooks must not render an empty table: "you have
// none of these" and "this build cannot tell you" look identical on a page and
// mean opposite things. This opens every screen against a bare server and
// requires each to answer — 200 with an explanation, or 503 with one — rather
// than a 500 or a half-rendered page.
func TestEveryScreenSurvivesWithNothingWiredIn(t *testing.T) {
	srv, token := setup(t)

	for r := range servedRoutes(t) {
		if strings.HasSuffix(r, "/") && r != "/" {
			continue
		}
		if _, excused := notAScreen[r]; excused {
			continue
		}
		path := r
		t.Run(path, func(t *testing.T) {
			w := get(t, srv, path, token)
			switch w.Code {
			case http.StatusOK, http.StatusMethodNotAllowed,
				http.StatusServiceUnavailable:
			default:
				t.Fatalf("%s answered %d with nothing wired in; it should "+
					"explain itself rather than fail\n%s",
					path, w.Code, firstLines(w.Body.String(), 6))
			}
			if strings.Contains(w.Body.String(), "<!-- render error:") {
				t.Fatalf("%s rendered with a template error", path)
			}
		})
	}
}

// notAScreen is every registered route that a person cannot open, and why.
//
// Four of them, each for a different reason, and each written out rather than
// filtered by a pattern — a pattern would also excuse the next thing that
// happens to match it.
var notAScreen = map[string]string{
	"/signin/oidc": "starts an authorisation redirect, and answers 404 when " +
		"no identity provider is configured",
	"/auth/callback": "receives one, and is never opened directly",
	"/signout":       "clears the cookie and redirects; there is nothing to render",
	"/style.css":     "is a stylesheet",
	"/decentralised/bundle": "sends a tar.gz of the rendered site, not a page; " +
		"it redirects with an explanation when there is nothing published",
}

// fullyWired builds a server with every capability connected, the way the
// command line connects it.
//
// Fixtures rather than real subsystems where a real one would need a network
// or a subprocess. The point is to render every screen with plausible data in
// it, which is what exercises the templates.
func fullyWired(t *testing.T) (*Server, string) {
	t.Helper()
	srv, token := setup(t)

	types := &schema.Store{
		Registry: schema.NewRegistry(),
		Bound:    map[string]string{"index": "article"},
	}
	min := 1.0
	if err := types.Registry.Add(schema.Type{
		Name: "article", Description: "A single piece of writing.",
		Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true, MaxLen: 80},
			{Name: "body", Kind: schema.LongText},
			{Name: "rank", Kind: schema.Number, Min: &min},
			{Name: "section", Kind: schema.Choice,
				Choices: []string{"news", "opinion"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	srv.Types = &Types{
		Load:  func() (*schema.Store, error) { return types, nil },
		Save:  func(*schema.Store) error { return nil },
		Pages: func() (map[string]any, error) { return srv.draftPages() },
	}

	envs := site.DefaultEnvs()
	sched := &schedule.Schedule{}
	if err := sched.Add(srv.Store.GetRef(site.RefDraft),
		time.Now().Add(48*time.Hour), "editor", "launch", time.Now()); err != nil {
		t.Fatal(err)
	}
	srv.Publishing = &Publishing{
		Envs:         func() (*site.Envs, error) { return envs, nil },
		SaveEnvs:     func(*site.Envs) error { return nil },
		Schedule:     func() (*schedule.Schedule, error) { return sched, nil },
		SaveSchedule: func(*schedule.Schedule) error { return nil },
	}

	locks := &collab.Locks{}
	locks.Claim("index", "editor", "rewriting the intro", time.Now())
	srv.Locks = func() (*collab.Locks, error) { return locks, nil }
	srv.SaveLocks = func(*collab.Locks) error { return nil }

	lib, err := medialib.Open(filepath.Join(t.TempDir(), "media"))
	if err != nil {
		t.Fatal(err)
	}
	if f, body := onePNG(t); true {
		f.Alt = "a single grey pixel"
		if err := lib.Put(f, body); err != nil {
			t.Fatal(err)
		}
	}
	srv.Media = &Media{
		Library: func() (*medialib.Library, error) { return lib, nil },
		Options: func() media.Options { return media.Options{} },
	}

	locales := i18n.NewConfig("en")
	if err := locales.Add("fr"); err != nil {
		t.Fatal(err)
	}
	srv.Languages = &Languages{
		Load: func() (*i18n.Config, error) { return locales, nil },
		Save: func(*i18n.Config) error { return nil },
		Hashes: func() (map[string]string, error) {
			return map[string]string{"index": "abc123", "fr/index": "def456"}, nil
		},
	}

	srv.Integrations = &Integrations{
		Webhooks: func() ([]webhook.Endpoint, []webhook.Delivery, error) {
			return []webhook.Endpoint{{
					URL: "https://example.org/hook", Secret: "0123456789abcdef",
					Types: []string{"publish"}, Note: "the deploy trigger",
				}}, []webhook.Delivery{{
					ID: "d1", URL: "https://example.org/hook", Type: "publish",
					Attempt: 1, Status: 200, At: "2026-08-16T09:00:00Z",
					Succeeded: true,
				}}, nil
		},
		SaveWebhooks: func([]webhook.Endpoint) error { return nil },
		Extensions: func() ([]ext.Manifest, error) {
			return []ext.Manifest{{
				Name: "house-style", Version: "1.0.0",
				Description: "checks the style guide",
				Command:     []string{"/usr/local/bin/house-style"},
				Hooks:       []ext.Hook{ext.OnValidate},
				Fields:      []string{"title", "body"},
				SHA256:      strings.Repeat("a", 64),
			}}, nil
		},
		SaveExtensions: func([]ext.Manifest) error { return nil },
		Pin:            func(string) (string, error) { return strings.Repeat("b", 64), nil },
		Events:         func() ([]audit.Event, error) { return nil, nil },
		Provider: func() (string, string, string, string, bool, bool) {
			return "https://id.example.org", "quilzo",
				"https://cms.example.org/auth/callback", "email", true, true
		},
	}

	srv.Assurance = &Assurance{
		Scan: func() (int, []codescan.Finding, error) {
			return 12, []codescan.Finding{{
				Rule: "inline-event-handler", Severity: codescan.High,
				Where: "templates/page.html", Line: 4,
				Detail: "an inline event handler in a template",
				Fix:    "move it out, or remove it",
				OWASP:  "A03:2021",
			}}, nil
		},
		CSP: func() (string, string, csp.Sources, int, error) {
			return "Content-Security-Policy",
				"default-src 'none'; img-src 'self' cdn.example.org",
				csp.Sources{Img: []string{"cdn.example.org"}}, 2, nil
		},
		SBOM:   func() (*compliance.SBOM, error) { return compliance.Generate(time.Now()) },
		Verify: func() (int, error) { return 41, nil },
		Vault: func() (bool, string, []string) {
			return true, "k1", []string{"k1", "k0"}
		},
		Agents: func() ([]agentwatch.Report, error) {
			return []agentwatch.Report{{
				Principal: "assistant", Model: "a-model", Actions: 40,
				Counts: map[string]int{"repeated-refusal": 2}, Flagged: false,
				Summary: "two refusals in forty actions",
			}}, nil
		},
		Evidence: func() ([]Evidence, error) {
			return []Evidence{{
				Kind: "timestamp", Subject: strings.Repeat("c", 64),
				Authority: "freetsa.org", State: "issued",
				At: "2026-08-16T09:00:00Z",
			}}, nil
		},
	}

	fstore, err := form.Open(filepath.Join(t.TempDir(), "submissions"))
	if err != nil {
		t.Fatal(err)
	}
	forms := &form.Set{Forms: []form.Form{{
		Name: "contact", Label: "Contact us",
		Notice: "Kept for 90 days and used only to reply.",
		Fields: []form.Field{
			{Name: "name", Label: "Name", Kind: form.Line, Required: true},
			{Name: "email", Label: "Email", Kind: form.Email},
		},
	}}}
	srv.Forms = &Forms{
		Load:  func() (*form.Set, error) { return forms, nil },
		Save:  func(*form.Set) error { return nil },
		Store: fstore,
	}

	lists := &listing.Set{}
	if err := lists.Add(listing.Listing{
		Name: "recent", Label: "Recently updated", Collection: "notes",
		Fields: []string{"title"}, Sort: "updated", Descending: true, Rows: 5,
	}); err != nil {
		t.Fatal(err)
	}
	srv.Listings = &Listings{
		Load: func() (*listing.Set, error) { return lists, nil },
		Save: func(*listing.Set) error { return nil },
	}

	vocabs := &taxonomy.Set{}
	if err := vocabs.Add(taxonomy.Vocabulary{
		Name: "topics", Label: "Topics", Terms: []taxonomy.Term{
			{ID: "reports", Label: "Reports", Description: "Anything periodic."},
			{ID: "quarterly", Label: "Quarterly", Parent: "reports"},
			{ID: "marketing", Label: "Marketing", Synonyms: []string{"mktg"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	menus := &menu.Set{}
	if err := menus.Add(menu.Menu{Name: "main", Label: "Main", Items: []menu.Item{
		{ID: "i1", Label: "Home", Kind: menu.Page, Target: "index", Order: 1},
		{ID: "i2", Label: "Elsewhere", Kind: menu.External,
			Target: "https://example.org", Order: 2},
	}}); err != nil {
		t.Fatal(err)
	}
	srv.Structure = &Structure{
		Vocabularies:     func() (*taxonomy.Set, error) { return vocabs, nil },
		SaveVocabularies: func(*taxonomy.Set) error { return nil },
		Menus:            func() (*menu.Set, error) { return menus, nil },
		SaveMenus:        func(*menu.Set) error { return nil },
	}
	srv.Decentralised = &Decentralised{
		Pages:      func() (map[string]any, error) { return srv.draftPages() },
		Stylesheet: func() string { return "body{font-family:system-ui}" },
	}
	srv.Transfer = &Transfer{
		Pages:    func() (map[string]any, error) { return srv.draftPages() },
		Save:     func(map[string]any, string, string, string) error { return nil },
		SiteName: "Example", BaseURL: "https://example.org",
	}

	// No model. That is the configuration most stores are in, and the screen
	// has to render something in it — which is the state a hosted fixture
	// would never exercise.
	srv.Assist = &Assist{
		Model: func() (assist.Model, error) { return nil, nil },
		Pages: func() (map[string]any, error) { return srv.draftPages() },
		Save:  func(map[string]any, string, string, string) error { return nil },
	}

	cfg := config.New()
	srv.Settings = &Settings{
		Load: func() (*config.Config, error) { return cfg, nil },
		Save: func(*config.Config) error { return nil },
	}
	srv.Data = &Data{
		Tree: func() (string, error) {
			c, err := srv.Store.GetCommit(srv.Store.GetRef(site.RefDraft))
			if err != nil {
				return "", err
			}
			return c.Tree, nil
		},
		Commit: func(string, string, string) error { return nil },
	}
	return srv, token
}

// onePNG is the smallest valid image the media package accepts.
func onePNG(t *testing.T) (media.File, []byte) {
	t.Helper()
	// A 1x1 greyscale PNG, written out rather than base64 so the bytes are
	// visible in the source and a change to them is a change somebody made on
	// purpose.
	body := []byte{
		0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
		0, 0, 0, 0x0d, 'I', 'H', 'D', 'R',
		0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0,
		0x3a, 0x7e, 0x9b, 0x55,
		0, 0, 0, 0x0a, 'I', 'D', 'A', 'T',
		0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
		0x0d, 0x0a, 0x2d, 0xb4,
		0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
	}
	f, err := media.Accept("pixel.png", body, time.Now())
	if err != nil {
		t.Fatalf("the fixture image is not accepted by the media package: %v", err)
	}
	return f, body
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// draftPages is what the screens read. A method so the fixtures above can share
// it without each one re-deriving the draft.
func (s *Server) draftPages() (map[string]any, error) {
	return site.PagesAt(s.Store, site.RefDraft)
}
