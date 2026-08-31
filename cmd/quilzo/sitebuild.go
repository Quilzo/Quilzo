package main

import (
	"strings"

	"github.com/quilzo/quilzo/internal/a2a"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/throttle"
)

// One place that knows what this store publishes.
//
// # Why this is a function and not two hundred lines in the server
//
// The server built a site out of the store — the design, the listings, the
// menus, the asset library, the crawl terms, the share target, the agent card,
// the content policy — and the static bundle built its own, much smaller idea
// of the same thing. So `ipfs write` produced a copy of the site with no
// sitemap, no robots.txt, no licence, no manifest, no service worker, no
// structured data on any page and, worse, none of the provenance marking: the
// disclosure that internal/provenance exists to attach and that the copy people
// archive is exactly where it needs to be.
//
// Two builders of the same thing is how that happens, and adding the missing
// pieces to the second one would leave two builders. So there is one, and the
// bundle is rendered by asking this site for its own pages.
type siteOpts struct {
	// BaseURL is where the site will be served from. Absolute URLs — the
	// sitemap, og:url — are built from it, and without one there is no
	// sitemap at all.
	BaseURL string
	// Ref is the environment being served. Empty means production.
	Ref string
	// Note receives the diagnostics a person watching a server start wants to
	// see. Nil for callers that are not starting a server.
	Note func(format string, a ...any)
}

func siteFor(root string, design *Design, opt siteOpts) (*public.Site, error) {
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	note := opt.Note
	if note == nil {
		note = func(string, ...any) {}
	}
	st := public.New(s, design.Layouts)
	st.Fonts = design.Fonts
	st.Stylesheet = design.Stylesheet
	// The installed app's splash and chrome, from the same tokens the
	// stylesheet is generated from — so a themed site does not open on a white
	// screen under somebody else's accent colour.
	if design.Theme != nil {
		if v, ok := design.Theme.Value("surface", false); ok {
			st.Background = v
		}
		if v, ok := design.Theme.Value("primary", false); ok {
			st.ThemeColour = v
		}
	}
	// The configured name, which the flag overrides for one run. Keeping it in
	// configuration is what lets the accessibility gate, the preview and the
	// exports render the same page this serves.
	if n := siteName(root); n != "" {
		st.Name = n
	}
	// The flag when there is one, the configured value otherwise. A base URL
	// belongs to the site — see the setting's own note — and a bundle is built
	// long after anybody typed a flag.
	st.BaseURL = strings.TrimSpace(opt.BaseURL)
	if st.BaseURL == "" {
		if cfg, cerr := loadConfig(root); cerr == nil {
			st.BaseURL = strings.TrimSpace(cfg.Raw("site.base_url"))
		}
	}
	// The one write capability this process gets: append a submission to a
	// store that is not the content store. It cannot read one back — that is
	// the admin's job, behind authentication, in a different process.
	if fs, ferr := openSubmissions(root); ferr == nil {
		st.Forms = &public.Forms{
			Set:   func() (*form.Set, error) { return loadForms(root) },
			Store: fs,
			Limit: throttle.New(throttlePolicy(mustConfig(root))),
			Audit: func(name, source string, accepted bool) {
				outcome := audit.Success
				if !accepted {
					outcome = audit.Denied
				}
				// The form and the source, never the content. A log outliving
				// the retention period must not be where the deleted data
				// survives.
				record(root, audit.Record{
					Action: "form.submit", Resource: "/" + name,
					Outcome: outcome, Principal: source,
					Kind: audit.KindUnknown,
				})
			},
		}
	}
	// The declared listings, and one index cache for the process. Without
	// these a page that shows a query renders without it — which is what
	// happened the first time, and is invisible because an absent section
	// looks exactly like an empty one.
	if set, lerr := loadListings(root); lerr == nil {
		commit := s.GetRef(site.RefLive)
		tree := ""
		if commit != "" {
			if c, cerr := s.GetCommit(commit); cerr == nil {
				tree = c.Tree
			}
		}
		st.Listings = &listing.Resolver{
			Store: s, Index: collection.NewCache(), Tree: tree, Set: set,
		}
	}
	// The asset library. Opened once and looked up per request: the files are
	// immutable and named by their own hash, so there is nothing to reload and
	// a cached handle cannot go stale.
	//
	// Without this an uploaded image could be stored, described and listed and
	// never appear on a page, which is what every deployment did until now.
	if lib, lerr := openMedia(root); lerr == nil {
		st.Media = func(id string) (media.File, []byte, error) {
			return lib.Get(id)
		}
	}

	// Navigation. Re-read per request rather than captured, because a menu
	// edited while the site is running should take effect the way a published
	// page does, and because the file is small.
	//
	// Without this a site could have menus defined, validated and gating its
	// publishes, and serve every page without any navigation at all.
	st.Menus = func() (*menu.Set, error) { return loadMenus(root) }

	// The policy is generated once, at startup, from what is live — the same
	// moment and the same content the search index is built from. Regenerating
	// per request would read every page to set a header.
	if cfg, cerr := loadConfig(root); cerr == nil {
		st.HSTS = cfg.Dur("site.hsts")
		// The catalogue feed, when one is named. Validated against the
		// declared listings here rather than at request time, so a name that
		// matches nothing is reported once at startup instead of as a 404
		// nobody can explain.
		if name := cfg.Raw("site.catalogue"); name != "" {
			st.Catalogue = name
		}
		// The A2A discovery document, when the operator publishes one.
		//
		// Built per request rather than once, because the manifests it
		// describes can be edited without restarting the server — and a card
		// that goes stale is a card that lies about what is enforced, which is
		// the one thing it must never do.
		// The crawl terms, when an operator has published any.
		//
		// This was the last mile of a feature that was otherwise finished:
		// RSL and TDMRep were implemented and tested, and nothing ever set
		// st.Licence, so /license.xml and /.well-known/tdmrep.json returned
		// 404 on every deployment there has ever been. Code reachable from
		// its tests and from nowhere else.
		if lic, lerr := licenceFrom(cfg); lerr != nil {
			return nil, lerr
		} else if lic != nil {
			st.Licence = lic
		}

		// The share sheet, when an operator has pointed it at a form.
		//
		// Validated here rather than at the first share: a target whose form
		// has an unreachable required field refuses every share, weeks later,
		// from somebody's phone, with no error anybody sees.
		if fname := cfg.Raw("share.form"); fname != "" {
			sh := &public.ShareTarget{
				Form:       fname,
				TitleField: cfg.Raw("share.title_field"),
				TextField:  cfg.Raw("share.text_field"),
				URLField:   cfg.Raw("share.url_field"),
			}
			var required []string
			if set, ferr := loadForms(root); ferr == nil {
				if f, ok := set.Get(fname); ok {
					for _, fl := range f.Fields {
						if fl.Required {
							required = append(required, fl.Name)
						}
					}
				} else {
					note("  %sshare target names %q, which is not a "+
						"declared form%s\n", yellow, fname, reset)
				}
			}
			if verr := sh.Validate(required); verr != nil {
				note("  %sshare sheet off: %v%s\n", yellow, verr, reset)
			} else {
				st.Share = sh
				note("  %sshare sheet: shares land in the %s form%s\n",
					dim, fname, reset)
			}
		}
		if cfg.Bool("site.agent_card") {
			st.AgentCard = func() (a2a.Card, error) {
				set, err := loadAgents(root)
				if err != nil {
					return a2a.Card{}, err
				}
				card := a2a.From(set.Agents, knownCapabilities(root), a2a.Options{
					SiteName:         cfg.Raw("site.name"),
					BaseURL:          st.BaseURL,
					Version:          version,
					DocumentationURL: cfg.Raw("site.docs_url"),
					Provider:         cfg.Raw("site.provider"),
					ProviderURL:      cfg.Raw("site.provider_url"),
				})
				// Validated on the way out. A deployment that would publish an
				// invalid card serves nothing instead: no card is a site that
				// is not discoverable, which is true and harmless; an invalid
				// one is a site that looks discoverable and breaks whatever
				// tried to use it.
				if verr := card.Validate(); verr != nil {
					return a2a.Card{}, verr
				}
				return card, nil
			}
		}
		if live := s.GetRef(site.RefLive); live != "" {
			if pages, perr := site.PagesAt(s, live); perr == nil {
				policy := buildCSP(cfg, pages)
				value := policy.Build()
				st.CSP = policy.Header
				st.CSPValue = func() string { return value }
				if n := len(policy.Sources.Img) + len(policy.Sources.Media) +
					len(policy.Sources.Frame); n > 0 {
					note("  %scsp: %s, %d external host(s) "+
						"named%s\n", dim, policy.Mode, n, reset)
				} else {
					note("  %scsp: %s, nothing external%s\n",
						dim, policy.Mode, reset)
				}
			}
		}
	}

	// The provenance records, which decide whether a page carries its
	// disclosure marking.
	//
	// This was assigned by the server and by nothing else, so a static copy —
	// the one somebody archives, the one a regulator would be shown — went out
	// with no marking on any page while the served site carried it. Article 50
	// is about what readers receive, and a copy is received by readers.
	st.LoadProvenance = func() (*provenance.Index, error) {
		return loadProvenance(root)
	}
	if strings.TrimSpace(opt.Ref) != "" {
		st.Ref = opt.Ref
	}
	// Languages, if configured. A single-language site never sees this: the
	// sitemap is byte-identical to what it was before the feature existed.
	if locales, lerr := loadLocales(root); lerr == nil && locales != nil &&
		len(locales.Locales) > 1 {
		st.Locales = locales
	}
	return st, nil
}
