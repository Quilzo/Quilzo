// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/throttle"
)

// The agent interface, as the admin serves it.
//
// Quilzo is what agents run against: the interface at /mcp is how any of
// them, wherever it runs and whoever made it, reads and changes what Quilzo
// holds, under the same access policy, shield and audit log as a person at
// this screen. An app connects on a person's behalf by OAuth (see
// internal/oauthas): the person signs in here as they always do, agrees to
// what the app may do, and the app gets a token that works at /mcp and
// nowhere else.
//
// Off until an administrator turns it on (mcp.remote). An interface reached
// from outside is a decision, not a default.

// AgentInterface is what the admin needs to serve it.
type AgentInterface struct {
	// Enabled says whether the interface answers at all.
	Enabled func() bool
	// Config is the OAuth configuration; false when the admin's own address
	// (admin.base_url) is not set, so nothing can be advertised and only
	// Quilzo's own tokens are accepted.
	Config func() (oauthas.Config, bool)
	OAuth  *oauthas.Server
	// Build makes the server answering one caller; Called is told about
	// every tool call, for the audit log.
	Build  func(r *http.Request, c *mcp.Caller) (*mcp.Server, error)
	Called func(r *http.Request, c *mcp.Caller, tool, operation string, err *mcp.Error)
	// Docs is the manual's page about it.
	Docs string
	// Receipt is every call made through one connection, with proofs of
	// inclusion and a signed head: what the person it acted for keeps.
	Receipt func(connection string) ([]byte, error)
}

func (s *Server) interfaceOn() (oauthas.Config, bool, bool) {
	ai := s.Interface
	if ai == nil || ai.Enabled == nil || !ai.Enabled() {
		return oauthas.Config{}, false, false
	}
	if ai.Config == nil {
		return oauthas.Config{}, false, true
	}
	cfg, ok := ai.Config()
	return cfg, ok && ai.OAuth != nil, true
}

// handleMCP is the interface itself.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	cfg, oauth, on := s.interfaceOn()
	if !on {
		http.NotFound(w, r)
		return
	}
	if s.shieldedOff(w, "mcp") {
		return
	}
	resource, metadata, scope := "", "", ""
	if oauth {
		resource, metadata, scope = cfg.Resource(), cfg.MetadataURL(), oauthas.DefaultScope
	}
	own := s.ownOrigin(r)
	e := &mcp.Endpoint{
		Metadata: metadata, DefaultScope: scope,
		Authenticate: func(r *http.Request, token string) (*mcp.Caller, error) {
			return s.interfaceCaller(r, token, resource)
		},
		Build:  s.Interface.Build,
		Called: s.Interface.Called,
		SameOrigin: func(o string) bool {
			return o == own || (oauth && o == cfg.Issuer)
		},
	}
	e.ServeHTTP(w, r)
}

// interfaceCaller authenticates a bearer token at the interface: through
// the same throttle as every other door, with failures told to the shield.
func (s *Server) interfaceCaller(r *http.Request, token, resource string) (*mcp.Caller, error) {
	if s.ReloadTokens != nil {
		s.ReloadTokens()
	}
	if s.Tokens == nil {
		return nil, errors.New("no token store")
	}
	sub := throttle.Subject{Source: sourceOf(r)}
	if s.Throttle != nil {
		if d := s.Throttle.Check(sub); !d.Allowed {
			return nil, errors.New("too many failed attempts from this address. " + d.Why)
		}
	}
	tok, err := s.Tokens.AuthenticateFor(token, resource, time.Now())
	if err != nil {
		if s.Throttle != nil {
			if d, alert := s.Throttle.Fail(sub); alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(sub.Source, d.Failures)
			}
		}
		if s.OnBadToken != nil {
			s.OnBadToken(r, token, err)
		}
		if errors.Is(err, auth.ErrStepUp) {
			return nil, errors.New("this session must confirm it is its person first: sign in to the admin")
		}
		return nil, err
	}
	if s.Throttle != nil {
		s.Throttle.Succeed(throttle.Subject{Principal: tok.Principal})
	}
	return &mcp.Caller{Principal: tok.Principal, Client: tok.Client, Data: *tok}, nil
}

// ownOrigin is this admin's origin as the request reached it.
func (s *Server) ownOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || s.behindTLSProxy() {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func writeMetadata(w http.ResponseWriter, r *http.Request, doc map[string]any) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

// handleResourceMetadata is the interface's RFC 9728 document.
func (s *Server) handleResourceMetadata(w http.ResponseWriter, r *http.Request) {
	cfg, oauth, _ := s.interfaceOn()
	if !oauth {
		http.NotFound(w, r)
		return
	}
	writeMetadata(w, r, cfg.ResourceMetadata(s.Interface.Docs))
}

// handleServerMetadata is the authorization server's RFC 8414 document.
func (s *Server) handleServerMetadata(w http.ResponseWriter, r *http.Request) {
	cfg, oauth, _ := s.interfaceOn()
	if !oauth {
		http.NotFound(w, r)
		return
	}
	writeMetadata(w, r, cfg.AuthorizationMetadata(s.Interface.Docs))
}

func (s *Server) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	if _, oauth, _ := s.interfaceOn(); !oauth {
		http.NotFound(w, r)
		return
	}
	s.Interface.OAuth.Token(w, r)
}

func (s *Server) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	if _, oauth, _ := s.interfaceOn(); !oauth {
		http.NotFound(w, r)
		return
	}
	s.Interface.OAuth.Revoke(w, r)
}

// The page a person returns to after signing in, when they were on their
// way to agree to an app. Only that page: a cookie that could send somebody
// anywhere after sign-in would be an open redirect with a session attached.
const nextCookie = "quilzo_next"

func validNext(p string) bool {
	return strings.HasPrefix(p, "/oauth/authorize?") && len(p) <= 4096 &&
		!strings.ContainsAny(p, "\\\r\n")
}

// authorizeAgain is where to send somebody back to, rebuilt from a request
// validNext accepted: the path is this program's own and only the query is
// carried over, so the redirect stays on this origin whatever it held.
func authorizeAgain(p string) string {
	return "/oauth/authorize?" + strings.TrimPrefix(p, "/oauth/authorize?")
}

func (s *Server) rememberNext(w http.ResponseWriter, r *http.Request, p string) {
	if !validNext(p) {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: nextCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(p)),
		Path: "/", MaxAge: 600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: r.TLS != nil || s.behindTLSProxy()})
}

// takeNext returns, once, where a person who just signed in was going.
func (s *Server) takeNext(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(nextCookie)
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: nextCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || s.behindTLSProxy()})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || !validNext(string(b)) {
		return ""
	}
	return string(b)
}

// roleActions are the actions each scope's role is checked with.
var roleActions = map[auth.Role]auth.Action{
	auth.RoleReader: auth.ActView, auth.RoleAuthor: auth.ActEditDraft,
	auth.RolePublisher: auth.ActPublish, auth.RoleAdmin: auth.ActGrant,
}

// scopesFor are the scopes a person may give an app: what their role
// reaches across the whole site, and what the credential they signed in
// with reaches. An app is never given more than the person.
func (s *Server) scopesFor(p principal) []string {
	var out []string
	for _, sc := range oauthas.Scopes {
		act := roleActions[sc.Role]
		if s.Policy == nil || !s.Policy.Evaluate(p.Name, act, "/").Allowed {
			continue
		}
		if auth.CheckCredential(p.Role, p.Scope, p.Limits, act, "/") != nil {
			continue
		}
		out = append(out, sc.Name)
	}
	return out
}

// vouched reports whether this session was proved by a passkey or single
// sign-on, which is what a lockdown lets through.
func (s *Server) vouched(p principal) bool {
	if s.Tokens == nil {
		return false
	}
	for _, t := range s.Tokens.Snapshot() {
		if t.ID == p.TokenID {
			return t.Session
		}
	}
	return false
}

type scopeChoice struct {
	Name, What string
	Offered    bool
}

// handleAuthorize is where a person agrees, or does not, to an app.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	cfg, oauth, _ := s.interfaceOn()
	if !oauth {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method == http.MethodGet {
		if _, err := s.authenticate(r); err != nil {
			// The session cookie is SameSite=Strict, so somebody arriving
			// from the app's site looks signed out even when they are not.
			// One hop through this page is a navigation from this site,
			// which carries it.
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				s.render(w, r, "signin.html", map[string]any{"Title": "Sign in",
					"Continue": ssoProviderRow{Label: "the app's request", Href: r.URL.RequestURI()}})
				return
			}
			s.rememberNext(w, r, r.URL.RequestURI())
		}
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Here now, so the way back is spent: it must not send them here again
	// from the next page they open.
	s.takeNext(w, r)
	ai := s.Interface
	page := func(status int, data map[string]any) {
		data["Title"] = "Connect an app"
		data["Principal"] = p
		data["Status"] = status
		s.render(w, r, "oauth.html", data)
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			page(http.StatusBadRequest, map[string]any{"Mode": "error", "Why": "The form could not be read."})
			return
		}
		pend, err := ai.OAuth.Take(r.PostForm.Get("request"), p.Name)
		if err != nil {
			page(http.StatusBadRequest, map[string]any{"Mode": "error", "Why": err.Error()})
			return
		}
		to := ""
		if r.PostForm.Get("decision") == "allow" {
			allowed := map[string]bool{}
			for _, n := range s.scopesFor(p) {
				allowed[n] = true
			}
			var chosen []string
			for _, n := range pend.Request.Scopes {
				if allowed[n] && contains(r.PostForm["scope"], n) {
					chosen = append(chosen, n)
				}
			}
			if len(chosen) == 0 {
				to = ai.OAuth.Deny(pend)
			} else if to, err = ai.OAuth.Approve(pend, chosen, s.vouched(p)); err != nil {
				page(http.StatusServiceUnavailable, map[string]any{"Mode": "error", "Why": err.Error()})
				return
			}
		} else {
			to = ai.OAuth.Deny(pend)
		}
		// Not a redirect: the admin's policy allows forms to submit only to
		// this site, and a browser holds every hop of a submission to that.
		page(http.StatusOK, map[string]any{"Mode": "onward", "Onward": to, "Refresh": "0;url=" + to,
			"Host": hostOf(pend.Request.RedirectURI)})
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		return
	}

	req, err := ai.OAuth.Parse(r.Context(), r.URL.Query())
	var re *oauthas.RedirectError
	var na *oauthas.NotAllowed
	switch {
	case errors.As(err, &re):
		// The return address was proved before anything was found wrong,
		// so the app is told there, as OAuth expects.
		http.Redirect(w, r, oauthas.ErrorRedirect(re, cfg.Issuer), http.StatusSeeOther)
		return
	case errors.As(err, &na):
		page(http.StatusForbidden, map[string]any{"Mode": "notallowed", "Host": na.Host,
			"CanAllow": s.Policy != nil && s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed &&
				auth.CheckCredential(p.Role, p.Scope, p.Limits, auth.ActGrant, "/") == nil,
			"Return": r.URL.RequestURI()})
		return
	case err != nil:
		page(http.StatusBadRequest, map[string]any{"Mode": "error", "Why": err.Error()})
		return
	}
	if (p.Scope != "" && p.Scope != "/") || !p.Limits.Empty() {
		page(http.StatusForbidden, map[string]any{"Mode": "error", "Why": "You signed in with a credential limited to part of the site. " +
			"Sign in with your passkey or single sign-on to connect an app."})
		return
	}
	offered := map[string]bool{}
	for _, n := range s.scopesFor(p) {
		offered[n] = true
	}
	var choices []scopeChoice
	someOffered := false
	for _, n := range req.Scopes {
		for _, sc := range oauthas.Scopes {
			if sc.Name == n {
				choices = append(choices, scopeChoice{Name: n, What: sc.What, Offered: offered[n]})
				someOffered = someOffered || offered[n]
			}
		}
	}
	if !someOffered {
		page(http.StatusForbidden, map[string]any{"Mode": "error", "Why": "The app asks for access you do not have yourself, so you cannot give it."})
		return
	}
	pend, err := ai.OAuth.Hold(req, p.Name)
	if err != nil {
		page(http.StatusServiceUnavailable, map[string]any{"Mode": "error", "Why": err.Error()})
		return
	}
	redirect, _ := url.Parse(req.RedirectURI)
	page(http.StatusOK, map[string]any{"Mode": "consent", "Request": pend.ID, "App": req.Client,
		"Publisher": req.Client.Host(), "Returns": redirect.Host,
		"Local":   redirect.Scheme == "http" && oauthas.Loopback(redirect.Hostname()),
		"Choices": choices, "Resource": req.Resource})
}

func (s *Server) saveTokens() {
	if s.SaveTokens != nil && s.Tokens != nil {
		_ = s.SaveTokens(s.Tokens)
	}
}

func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type appRow struct {
	oauthas.Grant
	Mine bool
}

// handleApps lists the apps connected on a person's behalf, and for an
// administrator everybody's, with what may connect.
func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	cfg, oauth, on := s.interfaceOn()
	admin := s.Policy != nil && s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed &&
		auth.CheckCredential(p.Role, p.Scope, p.Limits, auth.ActGrant, "/") == nil
	data := map[string]any{"Nav": "apps", "Title": "Connected apps", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"On": on, "OAuth": oauth, "Admin": admin}
	if s.Interface != nil {
		data["Docs"] = s.Interface.Docs
		data["Receipts"] = s.Interface.Receipt != nil
	}
	if on {
		if oauth {
			data["Endpoint"] = cfg.Resource()
		} else {
			data["Endpoint"] = s.ownOrigin(r) + "/mcp"
		}
	}
	if s.Interface != nil && s.Interface.OAuth != nil {
		grants, err := s.Interface.OAuth.Store.Grants()
		if err != nil {
			data["Error"] = err.Error()
		}
		now := time.Now()
		var rows []appRow
		for _, g := range grants {
			if !g.Live(now) || (!admin && g.Principal != p.Name) {
				continue
			}
			rows = append(rows, appRow{Grant: g, Mine: g.Principal == p.Name})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Created.After(rows[j].Created) })
		data["Apps"] = rows
		if admin {
			clients, hosts, err := s.Interface.OAuth.Store.Clients()
			if err != nil {
				data["Error"] = err.Error()
			}
			data["Registered"], data["Hosts"] = clients, hosts
		}
	}
	s.render(w, r, "apps.html", data)
}

// handleAppsReceipt gives a connection's receipt to the person it acted
// for, or to an administrator: a file to keep, which checks anywhere with
// the store's published keys.
func (s *Server) handleAppsReceipt(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Interface == nil || s.Interface.OAuth == nil || s.Interface.Receipt == nil {
		http.NotFound(w, r)
		return
	}
	id := r.URL.Query().Get("id")
	grants, err := s.Interface.OAuth.Store.Grants()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	admin := s.Policy != nil && s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed &&
		auth.CheckCredential(p.Role, p.Scope, p.Limits, auth.ActGrant, "/") == nil
	var found *oauthas.Grant
	for i := range grants {
		if grants[i].ID == id && (admin || grants[i].Principal == p.Name) {
			found = &grants[i]
		}
	}
	// Somebody else's connection and no connection at all look the same.
	if found == nil {
		http.Redirect(w, r, "/apps?e="+url.QueryEscape("no connection of yours has that id"), http.StatusSeeOther)
		return
	}
	body, err := s.Interface.Receipt(found.ID)
	if err != nil {
		http.Redirect(w, r, "/apps?e="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if s.Audit != nil {
		s.Audit("oauth.receipt", "/apps", map[string]string{"by": p.Name, "grant": found.ID, "client": found.Client})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="receipt-`+found.ID+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// handleAppsAct changes connected apps: disconnecting one's own (or, for an
// administrator, anybody's), and what may connect.
func (s *Server) handleAppsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Interface == nil || s.Interface.OAuth == nil {
		http.NotFound(w, r)
		return
	}
	oa := s.Interface.OAuth
	back := func(e, m string) {
		v := url.Values{}
		if e != "" {
			v.Set("e", e)
		}
		if m != "" {
			v.Set("m", m)
		}
		http.Redirect(w, r, "/apps?"+v.Encode(), http.StatusSeeOther)
	}
	action := r.FormValue("action")
	if action == "disconnect" {
		id := r.FormValue("grant")
		grants, err := oa.Store.Grants()
		if err != nil {
			back(err.Error(), "")
			return
		}
		for _, g := range grants {
			if g.ID != id {
				continue
			}
			if g.Principal != p.Name && !s.can(w, r, p, auth.ActGrant, "/") {
				return
			}
			if err := oa.End(id, p.Name, "disconnected on the Connected apps screen"); err != nil {
				back(err.Error(), "")
				return
			}
			s.saveTokens()
			back("", g.ClientName+" is disconnected. Its tokens stopped working at once.")
			return
		}
		back("No such connection.", "")
		return
	}
	// Everything else decides what may connect at all.
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	switch action {
	case "allow-host", "remove-host":
		host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
		if err := oauthas.CheckHost(host); err != nil {
			back(err.Error(), "")
			return
		}
		err := oa.Store.ChangeClients(func(_ *[]oauthas.Client, hosts *[]string) error {
			var keep []string
			for _, h := range *hosts {
				if h != host {
					keep = append(keep, h)
				}
			}
			if action == "allow-host" {
				keep = append(keep, host)
			}
			sort.Strings(keep)
			*hosts = keep
			return nil
		})
		if err != nil {
			back(err.Error(), "")
			return
		}
		oa.Directory.Forget()
		s.audit("oauth."+action, "/", map[string]string{"by": p.Name, "host": host})
		if ret := r.FormValue("return"); action == "allow-host" && validNext(ret) {
			http.Redirect(w, r, authorizeAgain(ret), http.StatusSeeOther)
			return
		}
		if action == "allow-host" {
			back("", "Apps from "+host+" may now ask people to connect.")
			return
		}
		n := oa.EndWhere(func(g oauthas.Grant) bool {
			c := oauthas.Client{ID: g.Client}
			return host == "*" || c.Host() == host
		}, p.Name, "apps from "+host+" are no longer allowed")
		s.saveTokens()
		back("", "Apps from "+host+" can no longer connect, and "+countOf(n, "connection", "connections")+" from there ended.")
	case "register":
		redirects := strings.Fields(r.FormValue("redirects"))
		c, err := oauthas.NewRegistered(r.FormValue("name"), redirects, p.Name, time.Now())
		if err != nil {
			back(err.Error(), "")
			return
		}
		if err := oa.Store.ChangeClients(func(cs *[]oauthas.Client, _ *[]string) error {
			if len(*cs) >= 200 {
				return errors.New("200 registered apps is the limit")
			}
			*cs = append(*cs, c)
			return nil
		}); err != nil {
			back(err.Error(), "")
			return
		}
		s.audit("oauth.app-registered", "/", map[string]string{"by": p.Name, "client": c.ID, "app": c.Name,
			"redirects": strings.Join(redirects, " ")})
		back("", "Registered "+c.Name+". Its client_id is "+c.ID+".")
	case "unregister":
		id := r.FormValue("client")
		removed := false
		_ = oa.Store.ChangeClients(func(cs *[]oauthas.Client, _ *[]string) error {
			var keep []oauthas.Client
			for _, c := range *cs {
				if c.ID == id {
					removed = true
					continue
				}
				keep = append(keep, c)
			}
			*cs = keep
			return nil
		})
		if !removed {
			back("No such app.", "")
			return
		}
		s.audit("oauth.app-removed", "/", map[string]string{"by": p.Name, "client": id})
		n := oa.EndWhere(func(g oauthas.Grant) bool { return g.Client == id }, p.Name, "the app was removed from the register")
		s.saveTokens()
		back("", "Removed, and "+countOf(n, "connection", "connections")+" ended.")
	default:
		back("That is not something this screen does.", "")
	}
}
