package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/httpsig"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
			// Told to whoever asked to be told. See webhookcmd.go: the
			// endpoints, the signing and the retries were all here and no
			// event ever named a form, so a booking sat in a store until
			// somebody opened the admin.
			//
			// In its own goroutine: a receiver that is slow must not be a form
			// that is slow, and the person who filled it in is owed their
			// answer whatever the receiver does. Delivery is bounded by the
			// sender's own timeout and retry count.
			Notify: func(name string) {
				go notify(root, "submitted", "", nil, name)
			},
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
		// Images go out carrying a signed manifest: what this site says about
		// where the picture came from, bound to the picture's own bytes.
		//
		// Attached on the way out rather than in the library, because the
		// library files everything under the hash of its own bytes and a
		// manifest changes them.
		get, _ := mediaLookup(root)
		if get == nil {
			get = lib.Get
		}
		st.Media = get
		// And the record on its own, for the pages that ask which narrower
		// copies a picture has: reading the bytes to answer that would read
		// every image on the page, on every request.
		st.MediaStat = func(id string) (media.File, error) {
			return lib.Stat(id)
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
		// Where somebody reports a problem with this site. Published only when
		// an operator has said, because a security.txt with nothing in it
		// answers the scanner that went looking and tells the person nothing.
		if contact := strings.TrimSpace(cfg.Raw("security.contact")); contact != "" {
			expires := time.Now().Add(365 * 24 * time.Hour)
			if raw := strings.TrimSpace(cfg.Raw("security.expires")); raw != "" {
				when, perr := time.Parse("2006-01-02", raw)
				if perr != nil {
					return nil, fmt.Errorf(
						"security.expires is %q; it wants a date like "+
							"2027-01-31", raw)
				}
				expires = when
			}
			st.Security = &public.SecurityContact{
				Contact: splitList(contact),
				Expires: expires,
				Policy:  strings.TrimSpace(cfg.Raw("security.policy")),
				Acknowledgments: strings.TrimSpace(
					cfg.Raw("security.acknowledgments")),
				Encryption: strings.TrimSpace(cfg.Raw("security.encryption")),
			}
		}
		// How eagerly a browser may fetch the next page. Refused rather than
		// ignored when it is not one of the three: a typo here is a
		// performance feature that silently does nothing, which is
		// indistinguishable from it not working.
		if spec := strings.TrimSpace(cfg.Raw("site.speculation")); spec != "" {
			if !public.Speculation(spec).Valid() {
				return nil, fmt.Errorf(
					"site.speculation is %q; it is off, prefetch or prerender",
					spec)
			}
			st.Speculate = public.Speculation(spec)
		}
		// The catalogue feed, when one is named. Validated against the
		// declared listings here rather than at request time, so a name that
		// matches nothing is reported once at startup instead of as a 404
		// nobody can explain.
		if name := cfg.Raw("site.catalogue"); name != "" {
			st.Catalogue = name
		}
		// The feed, when a listing is named for it.
		if name := cfg.Raw("site.feed"); name != "" {
			st.Feed = name
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

		// Federation, when an operator has published an actor.
		//
		// A commitment rather than a setting: remote servers store the actor
		// id and keep fetching it, so turning this on is a decision and
		// turning it off later strands whoever followed.
		if fed, ferr := federationFrom(root, cfg, st.BaseURL); ferr != nil {
			return nil, ferr
		} else if fed != nil {
			st.Federation = fed
		}

		// The crawl gate, when an operator has configured one.
		//
		// Only alongside terms: enforcing a licence nobody published would
		// refuse crawlers under rules they cannot read.
		if gate, gerr := crawlGate(cfg); gerr != nil {
			return nil, gerr
		} else if gate != nil {
			if st.Licence == nil {
				return nil, fmt.Errorf(
					"crawl.price or crawl.keys is set and no licence is " +
						"published, so crawlers would be refused under terms " +
						"they cannot read. Set licence.permits and " +
						"licence.prohibits, or unset the crawl settings")
			}
			st.Crawl = gate
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

// federationFrom builds the fediverse actor, or nil when the site does not
// federate.
//
// # Why so much is refused here
//
// An actor id is permanent in a way little else is: remote servers store it,
// and every follower's copy points at it. A misconfiguration discovered later
// cannot be corrected by editing a setting, because the servers that already
// have it will not re-read it. So the checks are at startup and they refuse
// rather than warn.
func federationFrom(root string, cfg *config.Config, baseURL string) (
	*public.Federation, error) {

	handle := strings.TrimSpace(cfg.Raw("fediverse.handle"))
	if handle == "" {
		return nil, nil
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf(
			"fediverse.handle is set and no --base-url is given. Every " +
				"federated id is absolute and is stored permanently by remote " +
				"servers, so one built from a guessed hostname is a mistake " +
				"that cannot be withdrawn")
	}
	for _, r := range handle {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return nil, fmt.Errorf(
				"fediverse.handle is %q; it may hold lower-case letters, "+
					"digits and underscores only, because it becomes the "+
					"local part of an address people type", handle)
		}
	}

	pemBytes, err := os.ReadFile(fediverseKeyPath(root))
	if err != nil {
		return nil, fmt.Errorf(
			"fediverse.handle is set and there is no signing key at %s. "+
				"Create one with `quilzo fediverse init` — remote servers "+
				"verify everything this site sends against it, and a site "+
				"that federates without one is a site nothing will accept",
			fediverseKeyPath(root))
	}

	pub, signer, err := keysFrom(pemBytes)
	if err != nil {
		return nil, err
	}

	base := strings.TrimSuffix(baseURL, "/")
	followers := activitypub.NewFollowers()
	queue := activitypub.NewQueue()
	path := fediverseFollowersPath(root)
	announcedPath := fediverseAnnouncedPath(root)
	if err := loadJSON(path, followers); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("cannot read the follower list: %w", err)
	}

	return &public.Federation{
		Actor: activitypub.Actor{
			ID: base + "/@", Handle: handle,
			Name:         siteName(root),
			Summary:      strings.TrimSpace(cfg.Raw("fediverse.summary")),
			PublicKeyPEM: pub,
			Published:    time.Now(),
		},
		Followers: followers,
		Save:      func() error { return saveJSON(path, followers) },

		// The announcement marker: the last commit whose changed pages were
		// delivered. Persisted so a restart resumes from where it left off
		// rather than treating every page as newly published — which, on a
		// site with followers, would repost the whole catalogue on every
		// deploy.
		Announced: func() string {
			var m struct {
				Commit string `json:"commit"`
			}
			_ = loadJSON(announcedPath, &m)
			return m.Commit
		},
		RecordAnnounced: func(commit string) error {
			return saveJSON(announcedPath, struct {
				Commit string `json:"commit"`
			}{commit})
		},

		// The queue, and the sender that empties it.
		//
		// Without these the site is followable and silent: a Follow is
		// recorded and never confirmed, so the remote server shows it pending
		// for ever, and a published page reaches nobody. Both were built and
		// neither was wired, which is the failure this project has a
		// source-walking test for — and the test only walked public.Site's own
		// fields, so a nested struct's were invisible to it.
		Queue: queue,
		Deliver: func(inbox string, activity map[string]any) {
			if err := queue.Enqueue([]string{inbox}, activity); err != nil {
				// Logged rather than returned: this runs while a remote server
				// waits on a Follow, and refusing the follow because the queue
				// is full would be the wrong answer to a full queue.
				fmt.Fprintf(os.Stderr,
					"could not queue a reply to %s: %v\n", inbox, err)
			}
		},

		// Fetching a remote actor is the one request this protocol cannot
		// avoid making to a URL a stranger named: the signature on an inbound
		// activity can only be checked against the key of whoever sent it, and
		// that key lives on their server.
		//
		// So it goes through the same client every other outbound request
		// uses, with its connect-time address check. A federation package that
		// built its own HTTP client would be a second place for that check to
		// be forgotten, and the first place anybody would forget it.
		Fetch: fediverseFetcher(base+"/@#main-key", signer),

		// The sender that empties the queue: it signs each delivery over a
		// body digest and POSTs it through the same address-checked client as
		// every other outbound request. Built here, where the signing key
		// already is, rather than in the serve path where it would have to be
		// re-derived.
		Sender: &public.Signer{
			KeyID: base + "/@#main-key",
			Key:   signer,
			Post: func(req *http.Request) (int, error) {
				return fetch.New().DoChecked(req)
			},
		},
	}, nil
}

func fediverseKeyPath(root string) string {
	return filepath.Join(root, "fediverse-key.pem")
}

func fediverseFollowersPath(root string) string {
	return filepath.Join(root, "followers.json")
}

func fediverseAnnouncedPath(root string) string {
	return filepath.Join(root, "announced.json")
}

// publicPEMFrom derives the published half of the signing key.
//
// Derived rather than stored separately, so the two cannot disagree. A public
// key file that drifted from the private one would produce a site whose
// signatures nothing accepts, with no error anywhere to explain why.
func keysFrom(privatePEM []byte) (string, crypto.Signer, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return "", nil, fmt.Errorf("the signing key is not a PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		k, rerr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if rerr != nil {
			return "", nil, fmt.Errorf("the signing key cannot be parsed: %w", err)
		}
		key = k
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", nil, fmt.Errorf("the signing key is a %T and cannot sign", key)
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", nil, fmt.Errorf("cannot render the public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: der,
	})), signer, nil
}

// fediverseFetcher retrieves a remote actor document.
//
// # Two things a naive fetch gets wrong
//
// The same URL serves a web page to a person and an actor document to a
// server, chosen on Accept. A fetch that does not ask gets HTML, which fails
// later as "not an actor" while succeeding at the HTTP level — quiet enough
// to lose an afternoon to.
//
// And a large part of the fediverse runs authorized fetch, where an unsigned
// GET for an actor is answered 401. mastodon.social does. So the request this
// server makes to verify somebody else's signature is itself signed, which is
// circular-sounding and is how the protocol works: their server verifies ours
// against the key in our actor document, which they can fetch unsigned because
// this server does not require authorized fetch of its own.
//
// # The limit, stated
//
// The signature is RFC 9421, which Mastodon has verified since 4.5. A server
// old enough to accept only draft-cavage-http-signatures will answer 401 and a
// follow from it will not complete. Supporting the draft as well is a second
// wire format for a shrinking set of servers, and it is a decision worth
// making on evidence rather than in advance.
func fediverseFetcher(keyID string, signer crypto.Signer) func(string) ([]byte, error) {
	return func(raw string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		res, err := fetch.New().GetSigned(ctx, raw,
			"application/activity+json, application/ld+json",
			func(r *http.Request) error {
				return httpsig.Sign(r, keyID, httpsig.RSAPKCS1SHA256, signer,
					[]string{"@method", "@authority", "@path"}, time.Now())
			})
		if err != nil {
			return nil, err
		}
		return res.Body, nil
	}
}
