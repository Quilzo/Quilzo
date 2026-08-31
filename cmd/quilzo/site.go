package main

import (
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/throttle"
	"github.com/quilzo/quilzo/internal/vector"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
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
		"a redirect map, as written by quilzo import")
	name := fs.String("name", "", "site name, shown when installing")
	desc := fs.String("description", "", "site description")
	envName := fs.String("env", "",
		"which environment to serve; production by default")
	index := fs.String("index", "index",
		"the page served at / — no need to rename yours")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	// One loader for the layouts, the theme, the fonts and the stylesheet, so
	// this server, the preview, the publish gate and every export render the
	// same page against the same design.
	design, err := loadDesign(*tplDir)
	if err != nil {
		return err
	}
	for _, note := range design.Notes {
		w.Human("%s%s%s\n", dim, note, reset)
	}

	// One builder, shared with the static bundle. See sitebuild.go: the server
	// and `ipfs write` used to assemble their own idea of what this site is,
	// and the bundle's was missing the sitemap, the licence, the manifest, the
	// structured data and the provenance marking.
	st, serr := siteFor(root, design, siteOpts{
		BaseURL: *baseURL,
		Note: func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, format, a...)
		},
	})
	if serr != nil {
		return serr
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

	// Which environment this server is serving. Production unless told
	// otherwise, so a store that has never configured environments behaves
	// exactly as it always did.
	envSet, eerr := loadEnvs(root)
	if eerr != nil {
		return eerr
	}
	serving := envSet.Production()
	if *envName != "" {
		env, ok := envSet.Lookup(*envName)
		if !ok {
			return fmt.Errorf("there is no environment called %q", *envName)
		}
		serving = env
	}
	st.Ref = serving.Ref
	if !serving.Production {
		// Said loudly. A non-production environment served on a public
		// address is content somebody believed was not published yet, and the
		// mistake is silent otherwise.
		fmt.Fprintf(os.Stderr, "  %sserving the %s environment, which is not "+
			"production%s\n", yellow, serving.Name, reset)
	}

	live := s.GetRef(serving.Ref)
	if live == "" {
		fmt.Fprintf(os.Stderr, "  %s%snothing is published, so every page will "+
			"404%s\n", yellow, "", reset)
		fmt.Fprintf(os.Stderr, "  %squilzo publish%s\n", dim, reset)
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
			// The same class of silence as the index warning below: without a
			// base URL the sitemap answers 404 and robots.txt no longer
			// advertises one, so a site starts cleanly and is invisible to
			// every crawler. Said at startup, because nobody checks
			// /sitemap.xml on a site they have just brought up.
			if st.BaseURL == "" {
				fmt.Fprintf(os.Stderr, "  %sno --base-url, so there is no "+
					"sitemap and robots.txt does not advertise one%s\n",
					yellow, reset)
			}
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
		// Strictly, because a field this does not know is a redirect that does
		// something other than what the file says. `"status": 301` is what
		// every other tool's redirect file looks like, and it was accepted and
		// ignored: the entry served a 307 while the file said permanent, so
		// nothing updated a bookmark or a search index. Found by writing one.
		if err := loadRedirectFile(*redirectFile, &file); err != nil {
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
	if d := strings.TrimSpace(*desc); d != "" {
		st.Description = d
	}

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
			Throttle:     throttle.New(throttlePolicy(cfg)),
			ReloadTokens: tokenReloader(root, toks),
			Tokenise:     search.Tokenise,
			Vectors:      func() *vector.Index { return vecIndex },
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
	fmt.Printf("  %sserving the %s environment; drafts are not public%s\n", dim, serving.Name, reset)
	fmt.Printf("  %sinstallable: /manifest.webmanifest · offline: /sw.js%s\n", dim, reset)
	if fp := st.Fingerprint(); fp != "" {
		fmt.Printf("  %spublished fingerprint %s%s\n", dim, fp, reset)
	} else {
		fmt.Printf("  %snothing is published yet; run quilzo publish%s\n", yellow, reset)
	}
	return srv.ListenAndServe()
}

// licenceFrom builds the crawl terms from configuration, or nil for none.
//
// nil rather than an empty Licence when nothing is configured. An RSL document
// with no grants in it is not "no terms" — it reads as terms that permit
// nothing, and a crawler honouring it would stop indexing a site whose
// operator never made that decision.
func licenceFrom(cfg *config.Config) (*public.Licence, error) {
	permits := splitTerms(cfg.Raw("licence.permits"))
	prohibits := splitTerms(cfg.Raw("licence.prohibits"))
	attribution := strings.TrimSpace(cfg.Raw("licence.attribution"))
	contact := strings.TrimSpace(cfg.Raw("licence.contact"))
	standard := strings.TrimSpace(cfg.Raw("licence.standard"))

	if len(permits) == 0 && len(prohibits) == 0 {
		// Attribution or a contact with nothing to attach them to is a
		// half-configured licence, and publishing it would assert terms the
		// operator did not finish choosing.
		if attribution != "" || contact != "" || standard != "" {
			return nil, fmt.Errorf(
				"licence.attribution, licence.contact and licence.standard " +
					"describe terms, and no terms are set. Add " +
					"licence.permits or licence.prohibits, or unset these — " +
					"publishing a licence nobody finished choosing is worse " +
					"than publishing none")
		}
		return nil, nil
	}

	for _, t := range append(append([]string{}, permits...), prohibits...) {
		if !validCrawlUse(t) {
			return nil, fmt.Errorf(
				"%q is not an automated use this can express; the vocabulary "+
					"is search, train, ai-summarize and none", t)
		}
	}

	// A use in both lists is a contradiction, and a reader resolving it either
	// way is guessing at what the operator meant. Refused at startup, where
	// somebody is watching, rather than served to a crawler that will act on
	// whichever half it read first.
	for _, p := range permits {
		for _, q := range prohibits {
			if p == q {
				return nil, fmt.Errorf(
					"licence.permits and licence.prohibits both name %q, so "+
						"the terms contradict themselves. A crawler would "+
						"act on whichever it read first", p)
			}
		}
	}

	return &public.Licence{
		Permits: permits, Prohibits: prohibits,
		Attribution: attribution, Contact: contact, Standard: standard,
	}, nil
}

// validCrawlUse reports whether a term is one this can express.
//
// A closed list, because the value is published to third parties who act on
// it: a typo in an open list becomes a grant nobody notices, and "trian" in
// the prohibits list is a site that thinks it refused training and did not.
func validCrawlUse(s string) bool {
	switch s {
	case "search", "train", "ai-summarize", "none":
		return true
	}
	return false
}

func splitTerms(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
