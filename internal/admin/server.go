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
// The other reasons point the same way. scrivet is one static binary in a
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
	"errors"
	"fmt"
	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/throttle"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/a11y"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/collab"
	"github.com/rsh1k/scrivet/internal/collection"
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
	Store  *store.Store
	Policy *auth.Policy
	Tokens *auth.TokenStore
	// NavPosition is "top" or "left", from configuration. A person can flip it
	// for themselves with a cookie, which is what the toggle in the header
	// does — it is a preference about a screen rather than a setting about a
	// store, and forcing everybody to share one would make it an argument.
	NavPosition string
	// LoadAudit reads the audit log. Nil means the log page says it has no
	// access rather than showing an empty list, because an empty list and no
	// access look identical and mean opposite things.
	//
	// A function rather than a path: this process does not know where the log
	// lives, and after the writer was separated out it deliberately must not
	// open it for writing. Reading is all it is given.
	LoadAudit func() ([]audit.Event, error)
	// ResolvePrincipal turns a pseudonym back into a name, for principals this
	// store knows. It cannot reverse the HMAC — it computes forward for each
	// known principal and matches — so somebody the policy has never heard of
	// stays opaque, which is the right outcome rather than a limitation.
	ResolvePrincipal func(pseudonym string) string
	// LogSeparated reports whether the writer runs as another account, so the
	// page can say what the record is worth rather than implying it.
	LogSeparated bool

	// Settings gives the admin the store's configuration.
	Settings *Settings
	// Types gives the admin the site's content types, so what an application
	// stores can be declared from the interface rather than only from a
	// terminal. Nil means the screen says so rather than showing none.
	Types *Types
	// Publishing is the deployment pipeline: environments, promotion and work
	// queued for later.
	Publishing *Publishing
	// Media is the asset store.
	Media *Media
	// Languages is the locale set and how much of the site each one has.
	Languages *Languages
	// Integrations is everything this store talks to: webhooks, log
	// forwarding, the identity provider and extensions.
	Integrations *Integrations
	// Assurance is the evidence: the code scanner, the generated policy, the
	// inventory, the store's own integrity, the vault and the anchors.
	Assurance *Assurance
	// Transfer moves whole sites in and out, and applies starters.
	Transfer *Transfer
	// Decentralised renders the published site so its IPFS identifier can be
	// computed here rather than taken from whoever stores it.
	Decentralised *Decentralised
	// Forms is what visitors sent, and the declarations that shaped it.
	Forms *Forms
	// Approvals is dual authorisation: how many people must agree before
	// anything is published, and who has.
	Approvals *Approvals
	// Listings are the declared queries a page can embed.
	Listings *Listings
	// Structure is classification and navigation: the vocabularies terms come
	// from, and the menus that point at pages.
	Structure *Structure
	// Assist proposes a site from a description. Nil means no model is
	// configured, which is a complete configuration and the screen says so.
	Assist *Assist
	// Profile holds what people say about themselves — a display name and a
	// way to reach them, and nothing else. Nil means the screen shows their
	// permissions and sessions and offers no details to edit.
	Profile *Profile
	// Records is the decoded-collection cache, shared across requests.
	//
	// Keyed by tree, so it can never be stale: a different content is a
	// different tree identifier. Nil is safe and means every query pays the
	// full scan, which is correct for a test and wrong for a server.
	Records *collection.Cache
	// Data gives the admin access to records. Nil means the screen says it has
	// no access rather than showing an empty list, because empty and absent
	// look identical and mean opposite things.
	Data *Data
	// API is the content API, served under /api/ so the playground can call
	// it same-origin. Nil means the routes 404, which is what a server built
	// without one should do.
	API http.Handler
	// ReloadTokens re-reads the credential store when it has changed on disk.
	// Nil means never, which is only right for a test.
	ReloadTokens func()
	// Throttle slows repeated authentication failures. Nil means no
	// throttling, which is only right in tests: the host wires one in from
	// configuration, and a nil check here rather than a panic means a caller
	// who forgets gets an unthrottled server rather than a crashed one — so
	// the CLI is where the wiring is asserted, by a test that walks it.
	Throttle *throttle.Limiter
	// OnAuthFailure is called when the alerting threshold is crossed, so the
	// host can write an audit record. The admin package does not open the
	// audit log itself: it does not know where it lives, and after the
	// separated-writer work it deliberately must not.
	OnAuthFailure func(source string, failures int)
	Template      string // the site template, for preview and the a11y check
	tpl           *template.Template

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

	// OIDC, when an identity provider is configured. Nil means the only way in
	// is a token, which is the default and is a complete configuration.
	OIDC *OIDC
	// SaveTokens persists a session minted after an OIDC sign-in, so it
	// survives a restart and so revoking it is possible from the CLI.
	SaveTokens func(*auth.TokenStore) error
	// SavePolicy persists an access change made from the admin.
	SavePolicy func(*auth.Policy) error
	// Audit records an action. The admin does not open the audit log itself:
	// it does not know where the log lives, and since the writer was separated
	// out it must not.
	Audit func(action, resource string, detail map[string]string)
	// OnSignIn records an authentication. Separate from the handler so the
	// audit log stays the host's concern.
	OnSignIn func(principal, tokenID string)

	// Locks are advisory claims on pages, so two people do not each spend an
	// afternoon on the same one. They never prevent a write — compare-and-swap
	// does that — and they expire on their own.
	Locks     func() (*collab.Locks, error)
	SaveLocks func(*collab.Locks) error

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
		// A moment, stated rather than described relative to now. "ago" is
		// right for history and wrong for a schedule: a publication set for
		// next Tuesday rendered through it reads "just now", because
		// time.Since of a future instant is negative and every branch below
		// assumes it is not.
		"when": func(unix int64) string {
			if unix == 0 {
				return "—"
			}
			return time.Unix(unix, 0).UTC().Format("15:04 on 2 Jan 2006") + " UTC"
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
	return &Server{Store: s, Policy: p, Tokens: ts, Template: siteTemplate,
		Records: collection.NewCache(), tpl: t}, nil
}

// errNoCredential means nothing was presented, as distinct from something
// being rejected.
//
// The two used to be one error, and the sign-in screen showed "no token" in a
// red alert box to everybody arriving for the first time — announcing a
// failure to somebody who had not yet done anything. An error message is for
// something that went wrong, and opening a page you are not signed in to is
// not that.
var errNoCredential = errors.New("no token")

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
		return principal{}, errNoCredential
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
func (s *Server) can(w http.ResponseWriter, r *http.Request, p principal,
	act auth.Action, resource string) bool {
	d := s.Policy.Evaluate(p.Name, act, resource)
	if d.Allowed {
		return true
	}
	w.WriteHeader(http.StatusForbidden)
	s.render(w, r, "message.html", map[string]any{
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
func (s *Server) renderTypeFailures(w http.ResponseWriter, r *http.Request,
	p principal, page string, failures []schema.Failure) {

	w.WriteHeader(http.StatusUnprocessableEntity)
	s.render(w, r, "message.html", map[string]any{
		"Title": "Not saved", "Principal": p,
		"Heading":  "This does not match its content type",
		"Page":     page,
		"Failures": failures,
	})
}

// renderConflict explains a refused save.
//
// 409 rather than 500: nothing failed. Somebody else got there first, which is
// a normal outcome of two people working, and a 500 would send an operator
// looking at logs for a problem that is not there.
func (s *Server) renderConflict(w http.ResponseWriter, r *http.Request, p principal, page string,
	c *site.Conflict) {

	w.WriteHeader(http.StatusConflict)
	s.render(w, r, "conflict.html", map[string]any{
		"Nav": "pages", "Title": "Not saved", "Principal": p,
		"Page": page, "Conflict": c,
		// Whether the other change touched this page decides whether the
		// person has to merge anything or can simply save again.
		"Collides": len(c.Touches([]string{page})) > 0,
	})
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string,
	data map[string]any) {

	// Everything the shell needs, resolved here rather than in each handler.
	//
	// Set in one place because a screen added later cannot forget it. The
	// earlier version required each handler to pass "Nav", and a handler that
	// did not made the template compare a nil against a string — which surfaces
	// as a half-rendered page rather than as a failure, so it is exactly the
	// kind of mistake that ships.
	data["NavPosition"] = s.navFor(r)
	if _, ok := data["Nav"]; !ok {
		data["Nav"] = ""
	}
	navKey, _ := data["Nav"].(string)

	theme := themeOf(r)
	next, nextLabel := nextTheme(theme)
	data["Theme"] = theme
	data["ThemeNow"] = themeLabel(theme)
	data["ThemeNext"] = next
	data["ThemeNextLabel"] = nextLabel

	// The documentation anchor for the screen being rendered, so the footer
	// link means "help with this" rather than "help".
	data["Doc"] = docFor(navKey)

	// The navigation itself, filtered to what this person may use and sorted
	// into the order they chose.
	if p, ok := data["Principal"].(principal); ok {
		data["Nav"] = navKey
		data["NavGroups"] = s.navigation(r, p, navKey)
	}
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
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}
		// A file upload is exempt here and limited by its own handler, which
		// applies MaxUpload. Wrapping it twice would leave the tighter limit
		// in place: MaxBytesReader wraps the body it is given, so the 2 MiB
		// intended for a form would still be the effective cap and every
		// photograph larger than a paragraph of text would be refused with an
		// error about the request body. The limit is not removed, it is moved
		// to the handler that knows what is being sent.
		if r.URL.Path == uploadPath {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBody)
		next.ServeHTTP(w, r)
	})
}

// uploadPath is the one route that carries a file rather than a form.
//
// Named here rather than written twice, so the exemption in limitBody and the
// registration in Handler cannot drift apart — a mismatch would silently
// restore the 2 MiB cap on uploads, which is exactly the bug this constant
// exists to prevent.
const uploadPath = "/media/upload"

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

		// Sec-Fetch-Site is authoritative when the browser sends it.
		//
		// It is set by the browser itself and a page cannot forge it, so
		// "same-origin" is a stronger statement than anything Origin can make
		// — and once it has been made, re-checking Origin can only produce
		// disagreements with a request that is already known to be fine.
		//
		// It did. Signing in from Brave failed with "this request came from
		// another origin" while the same POST from curl succeeded: the
		// browser said same-origin, and then sent an Origin the comparison
		// did not like — privacy-hardened browsers send `null` in situations
		// where a stricter one sends the real value. Both lines of defence
		// were present, and the second one refused what the first had just
		// approved.
		//
		// So Sec-Fetch-Site decides when it is there, and Origin is the
		// fallback for clients that do not send it. Belt and braces, with the
		// braces no longer able to drop the trousers.
		switch r.Header.Get("Sec-Fetch-Site") {
		case "same-origin", "none":
			next.ServeHTTP(w, r)
			return
		case "":
			// Not sent. Fall through to Origin.
		default:
			http.Error(w, "cross-site requests cannot change anything here",
				http.StatusForbidden)
			return
		}

		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				// Named, because "another origin" gives somebody staring at a
				// blank page nothing to act on. This is the message an
				// operator behind a proxy that rewrites Host will need.
				http.Error(w, fmt.Sprintf(
					"this request says it came from %q and this server is "+
						"%q. If something in front of this rewrites the Host "+
						"header, it needs to preserve it.",
					origin, r.Host), http.StatusForbidden)
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
	mux.HandleFunc("/page/delete", s.handlePageDelete)
	mux.HandleFunc("/security", s.handleSecurity)
	mux.HandleFunc("/security/rules", s.handleRules)
	mux.HandleFunc("/security/rule/", s.handleRule)
	mux.HandleFunc("/security/scan", s.handleScanScreen)
	mux.HandleFunc("/security/policy", s.handleCSPScreen)
	mux.HandleFunc("/security/inventory", s.handleComplianceScreen)
	mux.HandleFunc("/security/integrity", s.handleIntegrityScreen)
	mux.HandleFunc("/security/verify", s.handleVerify)
	mux.HandleFunc("/security/agents", s.handleAgentsScreen)
	mux.HandleFunc("/languages", s.handleLanguages)
	mux.HandleFunc("/languages/add", s.handleLanguageAdd)
	mux.HandleFunc("/languages/translated", s.handleLanguageTranslated)
	mux.HandleFunc("/integrations", s.handleIntegrations)
	mux.HandleFunc("/integrations/webhook", s.handleWebhookSave)
	mux.HandleFunc("/integrations/webhook/remove", s.handleWebhookRemove)
	mux.HandleFunc("/integrations/extension", s.handleExtensionSave)
	mux.HandleFunc("/integrations/extension/remove", s.handleExtensionRemove)
	mux.HandleFunc("/integrations/siem", s.handleSIEMExport)
	mux.HandleFunc("/forms", s.handleForms)
	mux.HandleFunc("/forms/save", s.handleFormSave)
	mux.HandleFunc("/forms/close", s.handleFormClose)
	mux.HandleFunc("/forms/export", s.handleFormExport)
	mux.HandleFunc("/forms/expire", s.handleFormExpire)
	mux.HandleFunc("/forms/purge", s.handleFormPurge)
	mux.HandleFunc("/forms/submission/delete", s.handleSubmissionDelete)
	mux.HandleFunc("/listings", s.handleListings)
	mux.HandleFunc("/listings/save", s.handleListingSave)
	mux.HandleFunc("/listings/remove", s.handleListingRemove)
	mux.HandleFunc("/structure", s.handleStructure)
	mux.HandleFunc("/structure/vocabulary", s.handleVocabularySave)
	mux.HandleFunc("/structure/term/remove", s.handleTermRemove)
	mux.HandleFunc("/structure/menu", s.handleMenuSave)
	mux.HandleFunc("/structure/menu/item/remove", s.handleMenuItemRemove)
	mux.HandleFunc("/decentralised", s.handleDecentralised)
	mux.HandleFunc("/decentralised/bundle", s.handleBundleDownload)
	mux.HandleFunc("/decentralised/verify", s.handleVerifyCID)
	mux.HandleFunc("/transfer", s.handleTransfer)
	mux.HandleFunc("/transfer/export", s.handleExport)
	mux.HandleFunc("/transfer/import", s.handleImport)
	mux.HandleFunc("/transfer/starter", s.handleStarter)
	mux.HandleFunc("/assist", s.handleAssist)
	mux.HandleFunc("/assist/accept", s.handleAssistAccept)
	mux.HandleFunc("/review", s.handleReview)
	mux.HandleFunc("/publish", s.handlePublish)
	mux.HandleFunc("/review/propose", s.handlePropose)
	mux.HandleFunc("/review/approve", s.handleApprove)
	mux.HandleFunc("/access", s.handleAccess)
	mux.HandleFunc("/nav", s.handleNav)
	mux.HandleFunc("/theme", s.handleTheme)
	mux.HandleFunc("/nav/order", s.handleNavOrder)
	mux.HandleFunc("/profile", s.handleProfile)
	mux.HandleFunc("/profile/session/end", s.handleSessionEnd)
	mux.HandleFunc("/settings", s.handleSettings)
	mux.HandleFunc("/settings/save", s.handleSettingSave)
	mux.HandleFunc("/media", s.handleMedia)
	mux.HandleFunc(uploadPath, s.handleMediaUpload)
	mux.HandleFunc("/media/delete", s.handleMediaDelete)
	mux.HandleFunc("/media/file/", s.handleMediaFile)
	mux.HandleFunc("/publishing", s.handlePublishing)
	mux.HandleFunc("/publishing/promote", s.handlePromote)
	mux.HandleFunc("/publishing/environment", s.handleEnvSave)
	mux.HandleFunc("/publishing/environment/remove", s.handleEnvRemove)
	mux.HandleFunc("/publishing/schedule", s.handleScheduleAdd)
	mux.HandleFunc("/publishing/schedule/cancel", s.handleScheduleCancel)
	mux.HandleFunc("/publishing/lock/release", s.handleLockRelease)
	mux.HandleFunc("/types", s.handleTypes)
	mux.HandleFunc("/types/save", s.handleTypeSave)
	mux.HandleFunc("/types/field/remove", s.handleTypeFieldRemove)
	mux.HandleFunc("/types/delete", s.handleTypeDelete)
	mux.HandleFunc("/types/bind", s.handleTypeBind)
	mux.HandleFunc("/records", s.handleRecords)
	mux.HandleFunc("/records/save", s.handleRecordSave)
	mux.HandleFunc("/records/delete", s.handleRecordDelete)
	mux.HandleFunc("/logs", s.handleLogs)
	mux.HandleFunc("/people", s.handlePeople)
	mux.HandleFunc("/people/grant", s.handlePeopleGrant)
	mux.HandleFunc("/people/revoke", s.handlePeopleRevoke)
	mux.HandleFunc("/sessions/revoke", s.handleSessionRevoke)
	mux.HandleFunc("/provenance", s.handleProvenance)
	mux.HandleFunc("/provenance/set", s.handleProvenanceSet)
	mux.HandleFunc("/history", s.handleHistory)
	mux.HandleFunc("/rollback", s.handleRollback)
	mux.HandleFunc("/preview/", s.handlePreview)
	mux.HandleFunc("/signin", s.handleSignIn)
	mux.HandleFunc("/signin/oidc", s.handleOIDCStart)
	mux.HandleFunc("/auth/callback", s.handleOIDCCallback)
	mux.HandleFunc("/signout", s.handleSignOut)
	mux.HandleFunc("/playground", s.playground)
	// The content API, mounted here so the playground can reach it.
	//
	// Its relative URLs resolve against this origin, and there is deliberately
	// no CORS, so an API on another port is an API the console cannot call —
	// which is what it did before this. Read-only unless the operator asked
	// otherwise: the playground exists to show people the API, and showing
	// them is a read.
	if s.API != nil {
		mux.Handle("/api/", s.API)
	}
	mux.HandleFunc("/docs", s.handleDocs)
	mux.HandleFunc("/docs/img/", s.handleDocImage)
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
		s.render(w, r, "signin.html", map[string]any{
			"Title": "Sign in", "OIDC": s.OIDC != nil})
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(r.FormValue("token"))
	if _, err := s.Tokens.Authenticate(raw, time.Now()); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "signin.html", map[string]any{
			"Title": "Sign in", "Error": err.Error(), "OIDC": s.OIDC != nil})
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
	// Throttled before the credential is looked at, so that a refused attempt
	// costs nothing to check and, more importantly, so the time taken to
	// answer does not depend on whether the presented token exists.
	// The throttle blocks failures, not successes. See the note in the API
	// middleware: only the source is known before authentication, so refusing
	// on its history alone locks out everyone behind one address. A throttled
	// request is still authenticated and a valid credential is let through.
	// Re-read the credentials before deciding anything.
	//
	// The store is shared between processes — the admin, the public site and
	// the CLI all hold the same file — and each loaded it once at startup.
	// So a credential revoked through the admin kept working on the site
	// until that container restarted, which makes "revoked" a claim about a
	// file rather than a fact about a credential. Found by revoking a token
	// in one container and watching another keep accepting it.
	//
	// The hook stats the file and reloads only when it has changed, so this
	// is one stat per request rather than a parse.
	if s.ReloadTokens != nil {
		s.ReloadTokens()
	}

	sub := throttle.Subject{Source: sourceOf(r)}
	throttled := false
	var tdec throttle.Decision
	if s.Throttle != nil {
		if tdec = s.Throttle.Check(sub); !tdec.Allowed {
			throttled = true
		}
	}

	p, err := s.authenticate(r)
	if err != nil {
		if throttled {
			s.tooManyAttempts(w, r, tdec)
			return principal{}, false
		}
		if s.Throttle != nil {
			d, alert := s.Throttle.Fail(sub)
			if alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(sub.Source, d.Failures)
			}
			if !d.Allowed {
				s.tooManyAttempts(w, r, d)
				return principal{}, false
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		data := map[string]any{"Title": "Sign in", "OIDC": s.OIDC != nil}
		if !errors.Is(err, errNoCredential) {
			data["Error"] = err.Error()
		}
		s.render(w, r, "signin.html", data)
		return principal{}, false
	}
	if s.Throttle != nil {
		// The principal, not the address: see the note in the API middleware.
		s.Throttle.Succeed(throttle.Subject{Principal: p.Name})
	}
	return p, true
}

// tooManyAttempts answers a throttled request.
//
// 429 with Retry-After rather than a delay held open on the server. Sleeping
// here would let an attacker exhaust this process's own handlers by failing
// authentication in parallel, which turns the control into the outage.
func (s *Server) tooManyAttempts(w http.ResponseWriter, r *http.Request, d throttle.Decision) {
	secs := int(d.RetryAfter.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.WriteHeader(http.StatusTooManyRequests)
	s.render(w, r, "signin.html", map[string]any{
		"Title": "Too many attempts", "Error": d.Why,
	})
}

// sourceOf is the address an attempt came from.
//
// RemoteAddr only. A forwarded header is set by whatever is in front, and a
// throttle keyed on a value the client controls is a throttle the client
// switches off by varying it. An operator running behind a proxy wants the
// proxy to do this — it is the thing that can see the real address.
func sourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
	if !s.can(w, r, p, auth.ActView, "/") {
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

	// When each page is public, so an embargo or an expiry is visible in the
	// listing rather than only on the page itself.
	windows := map[string]string{}
	for _, h := range site.Windows(pages, time.Now()) {
		windows[h.Page] = h.State
	}

	s.render(w, r, "pages.html", map[string]any{
		"Windows": windows,
		"Nav":     "pages",
		"Message": r.URL.Query().Get("m"),
		"Error":   r.URL.Query().Get("e"),
		"Title":   "Pages", "Principal": p, "Names": names,
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
	if !s.can(w, r, p, auth.ActView, "/"+name) {
		return
	}

	// The commit this form was rendered from. It travels back with the save so
	// a change made in another tab, by another person, in the meantime is
	// refused rather than silently overwritten.
	base := s.Store.GetRef(site.RefDraft)

	pages, _ := site.PagesAt(s.Store, site.RefDraft)
	body, exists := pages[name]

	// Claim the page, advisorily. Somebody else holding it does not stop this
	// edit; it is shown so the two of them can talk before one loses work.
	var heldBy *collab.Lock
	if s.Locks != nil && s.SaveLocks != nil {
		if locks, err := s.Locks(); err == nil {
			_, existing := locks.Claim(name, p.Name, "", time.Now())
			heldBy = existing
			_ = s.SaveLocks(locks)
		}
	}

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

	s.render(w, r, "edit.html", map[string]any{
		"Nav":   "pages",
		"Title": "Edit " + name, "Principal": p, "Name": name,
		"Fields": fields, "Exists": exists, "Type": typeName,
		"Base": base, "HeldBy": heldBy,
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
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Posture == nil {
		s.render(w, r, "message.html", map[string]any{
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

	s.render(w, r, "security.html", map[string]any{
		"Nav":   "security",
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
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	s.render(w, r, "rules.html", map[string]any{
		"Nav":   "security",
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
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/security/rule/")
	rule, found := posture.Explain(id)
	if !found {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "rules.html", map[string]any{
		"Nav":   "security",
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
	if !s.can(w, r, p, auth.ActEditDraft, "/"+name) {
		return
	}

	// Two different situations arrive here as the same error, and only one of
	// them may be turned into an empty page set.
	//
	// A store where nobody has saved anything has no draft ref, and that is
	// exactly the state the first save runs in — the page being written is the
	// first page. Starting from empty is correct.
	//
	// A store whose draft ref is set and whose objects will not load is corrupt,
	// and starting from empty there would commit a one-page draft over the top
	// of whatever could not be read. That is the failure worth being careful
	// about: it turns a recoverable read error into silent data loss.
	//
	// The ref itself is what separates them, so it is what gets asked.
	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		if s.Store.GetRef(site.RefDraft) != "" {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		pages = map[string]any{}
	}
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
	//
	// The page being written, and not the whole draft. Checking everything on
	// every save sounds stricter and is worse in the one way that matters: any
	// page can be made invalid without being written to — give an existing page
	// a type it does not satisfy — and from that moment nobody can save
	// anything. The error names a page the author was not touching and may not
	// have permission to fix, so an author scoped to their own posts is simply
	// stuck until somebody else notices.
	//
	// Nothing is lost by narrowing it, because the whole-draft check now runs
	// at publish, which is where it belongs and where it was missing: types
	// were checked on every save and not at all on the way out, so binding a
	// type after saving was enough to put content on the live site that
	// violated its own type.
	if s.CheckTypes != nil {
		if failures := s.CheckTypes(map[string]any{name: body}); len(failures) > 0 {
			s.renderTypeFailures(w, r, p, name, failures)
			return
		}
	}

	if _, err := site.SaveDraftFrom(s.Store, pages, msg, p.Name,
		r.FormValue("__base")); err != nil {

		var c *site.Conflict
		if errors.As(err, &c) {
			s.renderConflict(w, r, p, name, c)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The claim is released on save. Holding it after the work is done is how
	// a lock outlives its purpose.
	if s.Locks != nil && s.SaveLocks != nil {
		if locks, err := s.Locks(); err == nil {
			locks.Release(name, p.Name, time.Now())
			_ = s.SaveLocks(locks)
		}
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
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}

	draft := s.Store.GetRef(site.RefDraft)
	live := s.Store.GetRef(site.RefLive)
	var changes []site.Change
	if draft != "" {
		changes, _ = site.Diff(s.Store, live, draft)
	}

	reports := s.checkAll(draft)
	s.render(w, r, "review.html", map[string]any{
		"Approval": s.approvalFor(p, draft),
		"Message":  r.URL.Query().Get("m"),
		"Nav":      "review",
		"Title":    "Review", "Principal": p, "Changes": changes,
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
	if !s.can(w, r, p, auth.ActPublish, "/") {
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
		s.render(w, r, "review.html", map[string]any{
			"Nav":   "review",
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

	// Dual authorisation, and this one has no override.
	//
	// The other gates accept a written reason because an accessibility failure
	// somebody takes responsibility for is a judgement call. "Publish without
	// the approvals the policy requires" is the thing the policy exists to
	// prevent, so accepting a reason here would be offering a button that
	// switches the control off.
	if blocked := s.blockedByApproval(p, draft); blocked != "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "review.html", map[string]any{
			"Nav": "review", "Title": "Review", "Principal": p,
			"Reports": reports, "Blocking": blocking, "CanPublish": true,
			"Approval": s.approvalFor(p, draft),
			"Error":    blocked,
		})
		return
	}

	// A page that expired before it was published.
	//
	// Almost always a date typed with the wrong year, or a draft that sat for
	// a month. Publishing it writes content that is invisible from the instant
	// it goes live, which looks exactly like a broken publish and is very hard
	// to diagnose from outside.
	if stale := site.AlreadyExpired(site.PagesOf(s.Store, draft),
		time.Now()); len(stale) > 0 && reason == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "review.html", map[string]any{
			"Nav": "review", "Title": "Review", "Principal": p,
			"Reports": reports, "Blocking": blocking, "CanPublish": true,
			"Expired": stale,
			"Error": fmt.Sprintf(
				"%d page%s already past the date it stops being public. "+
					"Publishing would put up content nobody can see.",
				len(stale), plural(len(stale))),
		})
		return
	}

	// Every page satisfies its type, checked over the whole draft.
	//
	// This is the check that used to run on every save and never here, which is
	// exactly backwards. Saving is per-page because a page can be made invalid
	// without being written to, and one such page blocking every author is a
	// worse failure than the one being prevented. Publishing is the whole set,
	// because that is the moment the site becomes something readers see, and
	// "only the pages you touched" is the exception somebody routes around by
	// touching something else.
	//
	// No override. The other gates here take a written reason because an
	// accessibility finding can be a judgement call; content that violates the
	// shape it was declared to have is not a judgement call, and the type is
	// the thing whoever set it up asked to be true.
	if s.CheckTypes != nil {
		if failures := s.CheckTypes(site.PagesOf(s.Store, draft)); len(failures) > 0 {
			names := make([]string, 0, len(failures))
			for _, f := range failures {
				names = append(names, f.Page)
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			s.render(w, r, "review.html", map[string]any{
				"Nav": "review", "Title": "Review", "Principal": p,
				"Reports": reports, "Blocking": blocking, "CanPublish": true,
				"TypeFailures": failures,
				"Error": fmt.Sprintf(
					"%d page%s in this draft do not satisfy the type they were "+
						"given: %s. A page can end up here without being edited — "+
						"giving an existing page a type it does not match is "+
						"enough — so this is checked on the way out.",
					len(failures), plural(len(failures)), strings.Join(names, ", ")),
			})
			return
		}
	}

	// Navigation integrity, gated rather than warned about.
	//
	// A menu entry pointing at a page that is not going live works for the
	// person who wrote it and 404s for every reader — which is the version of
	// the dangling-link bug that actually ships. Drupal has an open issue and
	// five contributed modules for this; here it is the same kind of refusal
	// as an inaccessible page, with the same override.
	if broken := s.brokenLinks(site.PagesOf(s.Store, draft)); len(broken) > 0 && reason == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "review.html", map[string]any{
			"Nav": "review", "Title": "Review", "Principal": p,
			"Reports": reports, "Blocking": blocking, "CanPublish": true,
			"BrokenLinks": broken,
			"Error": fmt.Sprintf(
				"%d navigation entr%s point at pages that are not being "+
					"published. They work for you and 404 for every reader.",
				len(broken), map[bool]string{true: "y", false: "ies"}[len(broken) == 1]),
		})
		return
	}

	// The same gate as the CLI, for the same reason. An override that is
	// available in the interface but not on the command line, or the reverse, is
	// a control with a hole in whichever one people actually use.
	if blocking > 0 && reason == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "review.html", map[string]any{
			"Nav":   "review",
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

	// Publishing with nothing to publish is a thing somebody did, not a thing
	// that went wrong, so it is answered on the screen they pressed the button
	// on rather than as a server error. Every other refusal in this handler
	// already does that; this one was reaching the store first and reporting
	// whatever came back.
	if draft == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "review.html", map[string]any{
			"Nav":   "review",
			"Title": "Review", "Principal": p, "Reports": reports,
			"Blocking": blocking, "CanPublish": true,
			"Error": "There is no draft to publish. Save a page first, and it " +
				"becomes the draft that publishing makes live.",
		})
		return
	}

	pub, err := site.Publish(s.Store, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "message.html", map[string]any{
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
	if !s.can(w, r, p, auth.ActGrant, "/") {
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

	s.render(w, r, "access.html", map[string]any{
		"Nav":   "access",
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
	if !s.can(w, r, p, auth.ActView, "/") {
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
	// An empty store has no draft ref, and asking the store for commit "" gets
	// back "not an object id", which is a true statement about the lookup and
	// tells somebody who has just run init that their new installation is
	// broken. Nothing to describe is not a failure; it renders as no rows.
	var tree map[string]string
	if draft := s.Store.GetRef(site.RefDraft); draft != "" {
		c, err := s.Store.GetCommit(draft)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tree, _ = s.Store.GetTree(c.Tree)
	}

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

	s.render(w, r, "provenance.html", map[string]any{
		"Nav":   "provenance",
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
	if !s.can(w, r, p, auth.ActEditDraft, "/"+page) {
		return
	}

	// No draft means no page to mark, which is the same answer as a page that
	// is not in the draft: not found. Reaching the store for commit "" would
	// answer it with a 500 instead.
	draft := s.Store.GetRef(site.RefDraft)
	if draft == "" {
		http.NotFound(w, r)
		return
	}
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
		s.render(w, r, "message.html", map[string]any{
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
	if !s.can(w, r, p, auth.ActView, "/") {
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
	s.render(w, r, "history.html", map[string]any{
		"Nav":   "history",
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
	if !s.can(w, r, p, auth.ActRollback, "/") {
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
	s.render(w, r, "message.html", map[string]any{
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
	if !s.can(w, r, p, auth.ActView, "/"+name) {
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
	// Listings resolved against the draft, because this is a preview: showing
	// published data on a preview of an unpublished page would be a preview of
	// something that does not exist.
	ctx := map[string]any{"page": body}
	if res := s.resolver(site.RefDraft); res != nil {
		built, berr := res.Context(body, firstOf(r.URL.Query()))
		if berr != nil {
			http.Error(w, berr.Error(), http.StatusUnprocessableEntity)
			return
		}
		ctx = built
	}
	out, err := tmpl.Render(s.Template, ctx)
	if err != nil {
		http.Error(w, "template: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// firstOf flattens a query string to one value per name.
//
// A repeated parameter is somebody probing, or a link built wrong. Taking the
// first is what every framework does; the point of doing it explicitly is that
// a listing parameter then has exactly one value and cannot be given two that
// disagree.
func firstOf(v url.Values) map[string]string {
	out := make(map[string]string, len(v))
	for k, vals := range v {
		if len(vals) > 0 {
			out[k] = vals[0]
		}
	}
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
