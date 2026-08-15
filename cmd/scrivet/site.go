package main

import (
	"flag"
	"fmt"
	"github.com/rsh1k/scrivet/internal/throttle"
	"github.com/rsh1k/scrivet/internal/vector"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/api"
	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/public"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/search"
	"github.com/rsh1k/scrivet/internal/seo"
	"github.com/rsh1k/scrivet/internal/site"
)

// cmdSite serves the published site.
//
// Separate from `serve`, which is the admin, and separate on purpose. They have
// different audiences, different auth, and different exposure: the admin belongs
// on loopback behind whatever you already trust, and this is the thing you point
// the internet at. Running both on one port would mean one misconfiguration
// exposes the editing interface.
func cmdSite(root string, args []string) error {
	fs := flag.NewFlagSet("site", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8081", "listen address")
	tplDir := fs.String("templates", "templates", "where page.html lives")
	apiEnable := fs.Bool("api", false,
		"serve the content API at /api/v1")
	apiWritable := fs.Bool("api-writable", false,
		"allow PUT; a read API and a write API are different products")
	baseURL := fs.String("base-url", "",
		"absolute origin, e.g. https://example.com — required for the sitemap")
	redirectFile := fs.String("redirects", "",
		"a redirect map, as written by scrivet import")
	name := fs.String("name", "", "site name, shown when installing")
	desc := fs.String("description", "", "site description")
	index := fs.String("index", "index",
		"the page served at / — no need to rename yours")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	tplPath := filepath.Join(*tplDir, "page.html")
	raw, err := os.ReadFile(tplPath)
	if err != nil {
		return fmt.Errorf("no template at %s: %w", tplPath, err)
	}

	st := public.New(s, string(raw))
	// The stylesheet beside the template, if there is one. A starter writes
	// both into the same directory, so this is the file `template use` just
	// produced — and it is read once here rather than resolved per request.
	if css, err := os.ReadFile(filepath.Join(*tplDir, "site.css")); err == nil {
		st.Stylesheet = string(css)
	}
	st.BaseURL = strings.TrimSpace(*baseURL)

	// The policy is generated once, at startup, from what is live — the same
	// moment and the same content the search index is built from. Regenerating
	// per request would read every page to set a header.
	if cfg, cerr := loadConfig(root); cerr == nil {
		st.HSTS = cfg.Dur("site.hsts")
		if live := s.GetRef(site.RefLive); live != "" {
			if pages, perr := site.PagesAt(s, live); perr == nil {
				policy := buildCSP(cfg, pages)
				value := policy.Build()
				st.CSP = policy.Header
				st.CSPValue = func() string { return value }
				if n := len(policy.Sources.Img) + len(policy.Sources.Media) +
					len(policy.Sources.Frame); n > 0 {
					fmt.Fprintf(os.Stderr, "  %scsp: %s, %d external host(s) "+
						"named%s\n", dim, policy.Mode, n, reset)
				} else {
					fmt.Fprintf(os.Stderr, "  %scsp: %s, nothing external%s\n",
						dim, policy.Mode, reset)
				}
			}
		}
	}
	// Set before anything reads it. It used to be assigned forty lines below
	// the startup check that consults it, so --index was applied to the server
	// and not to the warning: passing --index home still reported that / would
	// 404, correctly serving the page it had just said was missing.
	st.Index = *index

	// Languages, if configured. A single-language site never sees this: the
	// sitemap is byte-identical to what it was before the feature existed.
	if locales, lerr := loadLocales(root); lerr == nil && locales != nil &&
		len(locales.Locales) > 1 {
		st.Locales = locales
	}

	// The index is built from what is live, at startup. Building it from the
	// draft would make the search box return pages nobody has published, which
	// is a content leak however it is labelled.
	// The vector index is built once, from what is live, at the same moment
	// the search index is. Rebuilding per request would embed every page to
	// answer one query.
	var vecIndex *vector.Index

	live := s.GetRef(site.RefLive)
	if live == "" {
		fmt.Fprintf(os.Stderr, "  %s%snothing is published, so every page will "+
			"404%s\n", yellow, "", reset)
		fmt.Fprintf(os.Stderr, "  %sscrivet publish%s\n", dim, reset)
	}
	if live != "" {
		if pages, perr := site.PagesAt(s, live); perr == nil {
			st.Search = search.Build(live, pages)
			fmt.Fprintf(os.Stderr, "  %ssearch: %d terms over %d pages%s\n",
				dim, st.Search.Size(), len(pages), reset)

			vecIndex = vector.Build(live, pages, search.Tokenise)
			vp, vt := vecIndex.Size()
			fmt.Fprintf(os.Stderr, "  %svectors: %d page(s), %d term(s), "+
				"model %s%s\n", dim, vp, vt, vecIndex.Model, reset)

			// The home page is the one URL every visitor tries and the one
			// this server cannot infer. It serves whatever page is named
			// "index"; a site whose pages are called home, main or landing
			// starts cleanly, reports how many pages it indexed, and answers
			// / with a 404 — and nothing says why.
			if _, ok := pages[st.Index]; !ok {
				fmt.Fprintf(os.Stderr, "  %sno page named %q, so / will 404%s\n",
					yellow, st.Index, reset)
				names := make([]string, 0, len(pages))
				for n := range pages {
					names = append(names, n)
				}
				sort.Strings(names)
				if len(names) > 6 {
					names = names[:6]
				}
				fmt.Fprintf(os.Stderr, "  %spublished: %s%s\n",
					dim, strings.Join(names, ", "), reset)
				fmt.Fprintf(os.Stderr, "  %srename one to index, or pass "+
					"--index NAME%s\n", dim, reset)
			}
		}
	}

	// lastmod is computed per request rather than cached, because it is derived
	// from history and history only grows. A cached value would go stale
	// exactly when a page changed, which is the one moment it matters.
	st.LastChanged = func() (map[string]time.Time, error) {
		return seo.LastChanged(s, s.GetRef(site.RefLive), 5000)
	}

	if *redirectFile != "" {
		var file struct {
			Redirects []seo.Redirect `json:"redirects"`
		}
		if err := loadJSON(*redirectFile, &file); err != nil {
			return err
		}
		m, err := seo.NewMap(file.Redirects)
		if err != nil {
			// Refused at startup rather than at request time. A redirect map
			// with a loop in it should stop the server coming up, not send
			// visitors round in circles.
			return fmt.Errorf("%s: %w", *redirectFile, err)
		}
		st.Redirects = m
	}
	if *name != "" {
		st.Name = *name
	}
	st.Description = *desc
	st.LoadProvenance = func() (*provenance.Index, error) { return loadProvenance(root) }

	handler := st.Handler()

	// The API shares the listener but not the routing. Mounted here rather than
	// inside the public site because it is a different product with different
	// authentication, and interleaving them would mean one mistake in the
	// public handler reaching authenticated endpoints.
	if *apiEnable {
		pol, perr := loadPolicy(root)
		toks, terr := loadTokens(root)
		if perr != nil || terr != nil {
			return fmt.Errorf("the API needs an access policy and a token store")
		}
		cfg, cerr := loadConfig(root)
		if cerr != nil {
			return cerr
		}
		apiSrv := &api.Server{
			Store: s, Policy: pol, Tokens: toks,
			Writable: *apiWritable,
			Limits: api.Limits{
				PerMinute: cfg.Int("api.rate.per_minute"),
				Burst:     cfg.Int("api.rate.burst"),
			},
			Throttle: throttle.New(throttlePolicy(cfg)),
			Tokenise: search.Tokenise,
			Vectors:  func() *vector.Index { return vecIndex },
			OnAuthFailure: func(source string, failures int) {
				// The reaction ASVS 5.0 asks for above five failures an hour.
				// An audit record rather than an email, because this program
				// does not send email and a control that claims to notify
				// somebody and does not is worse than one that does not claim.
				record(root, audit.Record{
					Action: "auth.failures", Resource: "/api",
					Outcome: audit.Denied, Principal: source,
					// Unknown, not service: nobody proved who they were, which is
					// what failing to authenticate means. The identifier is the
					// address the attempts came from.
					Kind: audit.KindUnknown,
					Detail: map[string]string{
						"failures": fmt.Sprintf("%d", failures),
						"surface":  "api",
					},
				})
			},
			Types: func() (*schema.Store, error) { return schema.Load(root) },
			OnWrite: func(principal, page, commit string) {
				record(root, audit.Record{
					Action: "api.write", Resource: "/" + page,
					Outcome: audit.Success, Principal: principal,
					// Verified: the caller presented a token that
					// authenticated. This is the one place that word is fully
					// earned outside a sign-in.
					Kind: audit.KindService, Verified: true,
					Detail: map[string]string{"commit": commit},
				})
			},
		}
		apiHandler := apiSrv.Handler()
		public := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				apiHandler.ServeHTTP(w, r)
				return
			}
			public.ServeHTTP(w, r)
		})

		mode := "read-only"
		if *apiWritable {
			mode = "writable"
		}
		fmt.Fprintf(os.Stderr, "  %sapi: /api/v1, %s%s\n", dim, mode, reset)
		if *apiWritable {
			fmt.Fprintf(os.Stderr, "  %severy write needs If-Match, and goes "+
				"through the same content-type gate as the CLI%s\n", dim, reset)
		}
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("site on http://%s\n", *addr)
	fmt.Printf("  %sserving the live ref; drafts are not public%s\n", dim, reset)
	fmt.Printf("  %sinstallable: /manifest.webmanifest · offline: /sw.js%s\n", dim, reset)
	if fp := st.Fingerprint(); fp != "" {
		fmt.Printf("  %spublished fingerprint %s%s\n", dim, fp, reset)
	} else {
		fmt.Printf("  %snothing is published yet; run scrivet publish%s\n", yellow, reset)
	}
	return srv.ListenAndServe()
}
