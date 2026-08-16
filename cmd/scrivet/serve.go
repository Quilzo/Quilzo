package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/rsh1k/scrivet/internal/api"
	"github.com/rsh1k/scrivet/internal/config"
	"github.com/rsh1k/scrivet/internal/logd"
	"github.com/rsh1k/scrivet/internal/throttle"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rsh1k/scrivet/internal/admin"
	"github.com/rsh1k/scrivet/internal/agentwatch"
	"github.com/rsh1k/scrivet/internal/assist"
	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/codescan"
	"github.com/rsh1k/scrivet/internal/collab"
	"github.com/rsh1k/scrivet/internal/compliance"
	"github.com/rsh1k/scrivet/internal/csp"
	"github.com/rsh1k/scrivet/internal/ext"
	"github.com/rsh1k/scrivet/internal/fetch"
	"github.com/rsh1k/scrivet/internal/i18n"
	"github.com/rsh1k/scrivet/internal/listing"
	"github.com/rsh1k/scrivet/internal/media"
	"github.com/rsh1k/scrivet/internal/medialib"
	"github.com/rsh1k/scrivet/internal/menu"
	"github.com/rsh1k/scrivet/internal/oidc"
	"github.com/rsh1k/scrivet/internal/posture"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/schedule"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/taxonomy"
	"github.com/rsh1k/scrivet/internal/webhook"
)

func cmdServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	tplDir := fs.String("templates", "templates", "where page.html lives")
	// Declared so the posture scan can tell interception from exposure. An
	// operator who terminates TLS at a proxy should not be told they serve
	// cleartext — a rule a correct deployment cannot satisfy is a rule people
	// learn to ignore.
	behindProxy := fs.Bool("behind-proxy", false,
		"a reverse proxy terminates TLS in front of this")
	publicAddr := fs.String("public-addr", "",
		"where the public site is served, for the posture scan")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	toks, err := loadTokens(root)
	if err != nil {
		return err
	}

	siteTpl := ""
	if b, err := os.ReadFile(filepath.Join(*tplDir, "page.html")); err == nil {
		siteTpl = string(b)
	} else {
		fmt.Fprintf(os.Stderr, "  %sno %s; preview and the accessibility check "+
			"are unavailable%s\n", dim, filepath.Join(*tplDir, "page.html"), reset)
	}

	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	srv, err := admin.New(s, pol, toks, siteTpl)
	if err != nil {
		return err
	}
	// Persistence and auditing for the changes the admin can now make.
	// Without these an access change lives until the process restarts, and the
	// administrator has already been told it worked.
	srv.SavePolicy = func(p *auth.Policy) error {
		return saveJSON(policyPath(root), p)
	}
	srv.SaveTokens = func(t *auth.TokenStore) error {
		return saveJSON(tokensPath(root), t)
	}
	srv.Audit = func(action, resource string, detail map[string]string) {
		by := detail["by"]
		record(root, audit.Record{
			Action: action, Resource: resource, Outcome: audit.Success,
			Principal: by, Kind: audit.KindHuman, Verified: true,
			Detail: detail,
		})
	}

	srv.Settings = &admin.Settings{
		Load: func() (*config.Config, error) { return loadConfig(root) },
		Save: func(c *config.Config) error { return saveConfig(root, c) },
	}
	// Content types, re-read per call for the same reason CheckTypes is: a type
	// added from the CLI while this is running must take effect immediately.
	srv.Types = &admin.Types{
		Load:  func() (*schema.Store, error) { return schema.Load(root) },
		Save:  func(st *schema.Store) error { return st.Save() },
		Pages: func() (map[string]any, error) { return draftPages(root) },
	}
	srv.Data = &admin.Data{
		Tree: func() (string, error) { return draftTree(s) },
		Commit: func(tree, message, author string) error {
			return commitTreeNoLock(s, tree, message, author)
		},
	}
	// Everything below is the same wiring pattern: the admin package holds no
	// knowledge of where this store keeps its files, so the host hands it
	// functions. Each one may be left nil, and each screen says "this build has
	// no access to X" rather than rendering an empty list — because empty and
	// absent look identical on a page and mean opposite things.
	srv.Publishing = &admin.Publishing{
		Envs:         func() (*site.Envs, error) { return loadEnvs(root) },
		SaveEnvs:     func(e *site.Envs) error { return saveEnvs(root, e) },
		Schedule:     func() (*schedule.Schedule, error) { return loadSchedule(root) },
		SaveSchedule: func(sc *schedule.Schedule) error { return saveJSON(schedulePath(root), sc) },
	}
	srv.Media = &admin.Media{
		Library: func() (*medialib.Library, error) { return openMedia(root) },
		Options: func() media.Options {
			c, err := loadConfig(root)
			if err != nil {
				return media.Options{}
			}
			return media.Options{
				MaxWidth:    c.Int("media.max_width"),
				MaxHeight:   c.Int("media.max_height"),
				JPEGQuality: c.Int("media.jpeg_quality"),
				WebP:        c.Bool("media.webp"),
			}
		},
	}
	srv.Languages = &admin.Languages{
		Load: func() (*i18n.Config, error) { return loadLocales(root) },
		Save: func(c *i18n.Config) error { return saveJSON(localesPath(root), c) },
		Hashes: func() (map[string]string, error) {
			ref := site.RefDraft
			if s.GetRef(ref) == "" {
				ref = site.RefLive
			}
			return pageHashes(s, ref)
		},
	}
	srv.Integrations = &admin.Integrations{
		Webhooks: func() ([]webhook.Endpoint, []webhook.Delivery, error) {
			f, err := loadHooks(root)
			if err != nil {
				return nil, nil, err
			}
			return f.Endpoints, f.Deliveries, nil
		},
		SaveWebhooks: func(e []webhook.Endpoint) error {
			f, err := loadHooks(root)
			if err != nil {
				return err
			}
			f.Endpoints = e
			return saveJSON(hooksPath(root), f)
		},
		Extensions: func() ([]ext.Manifest, error) {
			f, err := loadExts(root)
			if err != nil {
				return nil, err
			}
			return f.Extensions, nil
		},
		SaveExtensions: func(m []ext.Manifest) error {
			return saveExts(root, &extFile{Extensions: m})
		},
		Pin:    ext.Pin,
		Events: func() ([]audit.Event, error) { return audit.Read(auditPath(root)) },
		Provider: func() (string, string, string, string, bool, bool) {
			c, err := loadOIDC(root)
			if err != nil || c == nil {
				return "", "", "", "", false, false
			}
			return c.Issuer, c.ClientID, c.RedirectURI, c.Claim,
				c.RequireVerifiedEmail, true
		},
	}
	srv.Assurance = &admin.Assurance{
		Scan: func() (int, []codescan.Finding, error) {
			inputs, err := collectInputs(root, *tplDir, site.RefDraft)
			if err != nil {
				return 0, nil, err
			}
			return len(inputs), codescan.Scan(inputs), nil
		},
		CSP: func() (string, string, csp.Sources, int, error) {
			c, err := loadConfig(root)
			if err != nil {
				return "", "", csp.Sources{}, 0, err
			}
			commit := s.GetRef(site.RefLive)
			if commit == "" {
				return "", "", csp.Sources{}, 0, fmt.Errorf(
					"nothing is published, so there is no content to derive a " +
						"policy from. One generated from an empty site would " +
						"permit nothing, which is correct and useless")
			}
			pages, err := site.PagesAt(s, commit)
			if err != nil {
				return "", "", csp.Sources{}, 0, err
			}
			pol := buildCSP(c, pages)
			name, _ := pol.Header()
			return name, pol.Build(), pol.Sources, len(pages), nil
		},
		SBOM:   func() (*compliance.SBOM, error) { return compliance.Generate(time.Now()) },
		Verify: func() (int, error) { return s.Verify() },
		Vault: func() (bool, string, []string) {
			kr, err := loadKeyring(root)
			if err != nil || kr == nil {
				return false, "", nil
			}
			return true, kr.Active, kr.IDs()
		},
		Agents: func() ([]agentwatch.Report, error) {
			events, err := audit.Read(auditPath(root))
			if err != nil {
				return nil, err
			}
			return agentwatch.Look(events, time.Now()), nil
		},
		Evidence: func() ([]admin.Evidence, error) { return evidenceRows(root) },
	}
	// Dual authorisation. The same files and the same engine the command line
	// uses — a second implementation of an approval rule would be a second
	// answer to "may this be published".
	srv.Approvals = &admin.Approvals{
		Policy: func() (collab.Policy, error) { return loadApprovalPolicy(root) },
		Current: func() (*collab.Proposal, error) {
			prop, _, err := currentProposal(root, s)
			return prop, err
		},
		Save: func(prop *collab.Proposal) error {
			return saveProposal(root, s, prop)
		},
		KindOf: func(principal string) string {
			return principalKind(root, principal)
		},
	}
	srv.Listings = &admin.Listings{
		Load: func() (*listing.Set, error) { return loadListings(root) },
		Save: func(set *listing.Set) error { return saveJSON(listingPath(root), set) },
	}
	srv.Structure = &admin.Structure{
		Vocabularies: func() (*taxonomy.Set, error) { return loadVocabularies(root) },
		SaveVocabularies: func(set *taxonomy.Set) error {
			return saveJSON(vocabPath(root), set)
		},
		Menus: func() (*menu.Set, error) { return loadMenus(root) },
		SaveMenus: func(set *menu.Set) error {
			return saveJSON(menuPath(root), set)
		},
	}
	srv.Decentralised = &admin.Decentralised{
		Pages: func() (map[string]any, error) { return site.PagesAt(s, site.RefLive) },
		Stylesheet: func() string {
			b, err := os.ReadFile(filepath.Join(*tplDir, "site.css"))
			if err != nil {
				return ""
			}
			return string(b)
		},
		Media: func() (map[string][]byte, error) {
			lib, err := openMedia(root)
			if err != nil {
				return nil, err
			}
			all, err := lib.List()
			if err != nil {
				return nil, err
			}
			out := map[string][]byte{}
			for _, f := range all {
				_, body, gerr := lib.Get(f.ID)
				if gerr != nil {
					continue
				}
				// The same path the public server uses, so an image reference
				// in a page resolves identically on IPFS.
				out["media/"+f.ID] = body
			}
			return out, nil
		},
	}
	srv.Transfer = &admin.Transfer{
		Pages: func() (map[string]any, error) { return draftPages(root) },
		Save: func(p map[string]any, msg, by, base string) error {
			return saveDraft(root, s, p, msg, by, base)
		},
		SiteName: cfg.Raw("site.name"), BaseURL: cfg.Raw("site.base_url"),
	}
	srv.Assist = &admin.Assist{
		Model: func() (assist.Model, error) {
			m, err := assist.NewHTTPModel()
			if err != nil {
				// No model configured is not an error condition, it is a
				// configuration. The screen says so and offers nothing rather
				// than offering a box that cannot answer.
				return nil, nil
			}
			return m, nil
		},
		Pages: func() (map[string]any, error) { return draftPages(root) },
		Save: func(p map[string]any, msg, by, base string) error {
			return saveDraft(root, s, p, msg, by, base)
		},
		Record: func(pages []string, model, author string) error {
			return recordAssisted(root, s, pages, model, author)
		},
	}
	// What people say about themselves. A display name and a way to reach
	// them, and deliberately nothing else — every field here is data this
	// system did not need before and now holds about a person.
	srv.Profile = &admin.Profile{
		Load: func() (map[string]admin.PersonDetails, error) { return loadProfiles(root) },
		Save: func(m map[string]admin.PersonDetails) error {
			return saveJSON(profilesPath(root), m)
		},
	}
	srv.NavPosition = cfg.Raw("admin.nav")
	srv.ReloadTokens = tokenReloader(root, toks)

	// The audit log, read-only. This process cannot write it where the writer
	// has been separated out, so there is no edit path to withhold.
	srv.LoadAudit = func() ([]audit.Event, error) {
		return audit.Read(auditPath(root))
	}
	srv.LogSeparated = func() bool {
		ok, _ := logd.CheckOwnership(auditPath(root), os.Geteuid())
		return ok
	}()
	// Forward matching only. The HMAC cannot be reversed; this computes the
	// pseudonym for each principal the store knows and compares, so somebody
	// the policy has never heard of stays opaque — which is itself worth
	// seeing on the page.
	srv.ResolvePrincipal = func(pseudonym string) string {
		l, err := openAudit(root)
		if err != nil {
			return ""
		}
		for _, name := range pol.Principals() {
			if l.Matches(pseudonym, name) {
				return name
			}
		}
		for _, t := range toks.Snapshot() {
			if l.Matches(pseudonym, t.Principal) {
				return t.Principal
			}
		}
		return ""
	}
	srv.Throttle = throttle.New(throttlePolicy(cfg))

	// The content API, same-origin with the playground. Read-only here: this
	// is the console, and a console that can rewrite production by accident
	// is a different product. `scrivet site --api-writable` is where writes
	// are turned on deliberately.
	apiSrv := &api.Server{
		Store: s, Policy: pol, Tokens: toks,
		// The same cache the admin uses. One process, one decoded copy of a
		// collection — two would be the same memory spent twice and two
		// chances for one of them to be built wrong.
		Index:       srv.Records,
		SessionAuth: true,
		Limits: api.Limits{
			PerMinute: cfg.Int("api.rate.per_minute"),
			Burst:     cfg.Int("api.rate.burst"),
		},
		Types: func() (*schema.Store, error) { return schema.Load(root) },
		Records: &api.Records{
			// Writable from the admin, because the admin is where somebody
			// edits things and a console that can only read is a console
			// people stop opening.
			Writable: true,
			Tree:     func() (string, error) { return draftTree(s) },
			Commit: func(tree, message, author string) error {
				return commitTreeNoLock(s, tree, message, author)
			},
		},
	}
	srv.API = apiSrv.Handler()
	srv.OnAuthFailure = func(source string, failures int) {
		// ASVS 5.0 asks for a reaction above five failures an hour. An audit
		// record is the reaction: a SIEM rule can match it, and this program
		// does not send email.
		record(root, audit.Record{
			Action: "auth.failures", Resource: "/admin",
			// Unknown, not service: nobody proved who they were.
			Outcome: audit.Denied, Principal: source,
			Kind: audit.KindUnknown,
			Detail: map[string]string{
				"failures": fmt.Sprintf("%d", failures),
				"surface":  "admin",
			},
		})
	}
	// The admin does not need to know where provenance lives, so the host
	// supplies the two functions and keeps the file layout in one place.
	srv.LoadProvenance = func() (*provenance.Index, error) { return loadProvenance(root) }
	srv.SaveProvenance = func(i *provenance.Index) error { return saveJSON(provPath(root), i) }
	// Types are re-read per request rather than captured once. A type added
	// from the CLI while the server is running must take effect immediately,
	// for the same reason revoked tokens do: a control that needs a restart is
	// a control that is off for as long as nobody restarts.
	srv.CheckTypes = func(pages map[string]any) []schema.Failure {
		st, err := schema.Load(root)
		if err != nil {
			// Fail closed. An unreadable types file is not the same as a site
			// with no types, and treating it as one would make corrupting the
			// file a way to switch validation off.
			return []schema.Failure{{Page: "(all)", Type: "?", Problems: []schema.Problem{
				{Field: "types.json", Reason: "cannot be read: " + err.Error()}}}}
		}
		return st.Gate(pages)
	}
	srv.TypeFor = func(page string) (schema.Type, bool) {
		st, err := schema.Load(root)
		if err != nil {
			return schema.Type{}, false
		}
		name, bound := st.Bound[page]
		if !bound {
			return schema.Type{}, false
		}
		return st.Registry.Get(name)
	}
	// The scan runs per request rather than on a timer here, because the
	// dashboard is the thing being looked at: a cached posture is a posture
	// from before whatever the person just changed.
	srv.Posture = func() posture.Report {
		state := Observe(root, *tplDir, posture.ServerFacts{
			AdminAddr: *addr, PublicAddr: *publicAddr, BehindProxy: *behindProxy,
		})
		sup, _ := loadSuppressions(root)
		return posture.Scan(state, sup)
	}
	// Locks live on disk so two server processes, or a server and the CLI, see
	// the same claims. Re-read per request rather than held in memory for the
	// same reason tokens are: a claim made in another process has to be visible
	// in this one or the courtesy is only a courtesy to whoever restarted last.
	// An identity provider, if one is configured. Discovery happens at startup
	// rather than on the first sign-in, so a misconfiguration is a failure to
	// start rather than a person who cannot log in and no information about why.
	if cfg, cerr := loadOIDC(root); cerr == nil && cfg != nil {
		secret := os.Getenv(oidcSecretEnv)
		if secret == "" {
			return fmt.Errorf(
				"%s is configured as the identity provider but %s is not set.\n"+
					"  Refusing to start rather than offering a sign-in button "+
					"that cannot work", cfg.Issuer, oidcSecretEnv)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		provider, derr := oidc.Discover(ctx, cfg.Issuer, fetch.New())
		cancel()
		if derr != nil {
			return fmt.Errorf("cannot reach the identity provider: %w", derr)
		}
		if err := provider.Warm(context.Background()); err != nil {
			return fmt.Errorf("cannot read the provider's signing keys: %w", err)
		}
		srv.OIDC = &admin.OIDC{
			Provider: provider, ClientID: cfg.ClientID, Secret: secret,
			RedirectURI: cfg.RedirectURI, Claim: cfg.Claim,
			RequireVerifiedEmail: cfg.RequireVerifiedEmail,
		}
		srv.SaveTokens = func(ts *auth.TokenStore) error {
			return saveJSON(tokensPath(root), ts)
		}
		srv.OnSignIn = func(principal, tokenID string) {
			record(root, audit.Record{
				Action: "signin.oidc", Resource: "/", Outcome: audit.Success,
				// Verified, and this is the one place that word is fully
				// earned: the provider proved the identity cryptographically
				// rather than it being taken from an environment variable.
				Principal: principal, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{
					"issuer": cfg.Issuer, "session": tokenID,
				},
			})
		}
		fmt.Fprintf(os.Stderr, "  %ssign-in via %s%s\n", dim, cfg.Issuer, reset)
	}

	srv.Locks = func() (*collab.Locks, error) { return loadLocks(root) }
	srv.SaveLocks = func(l *collab.Locks) error { return saveJSON(locksPath(root), l) }

	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		pol, err := loadPolicy(root)
		if err != nil {
			return nil, nil, err
		}
		toks, err := loadTokens(root)
		if err != nil {
			return nil, nil, err
		}
		return pol, toks, nil
	}

	// Loopback by default. An editing interface that binds every interface the
	// moment someone runs it is how a development server ends up on the
	// internet, and the fix has to be a decision rather than a default.
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("admin on http://%s\n", *addr)
	fmt.Printf("  %ssign in with a token: scrivet token issue you --principal you "+
		"--role admin%s\n", dim, reset)
	if len(toks.Tokens) == 0 {
		fmt.Printf("  %sno tokens exist yet, so nobody can sign in%s\n", yellow, reset)
	}
	return httpSrv.ListenAndServe()
}
