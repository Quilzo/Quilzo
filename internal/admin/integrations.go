package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/ext"
	"github.com/quilzo/quilzo/internal/siem"
	"github.com/quilzo/quilzo/internal/webhook"
)

// Everything this store talks to, on one screen.
//
// Webhooks, log forwarding, the identity provider and extensions were four
// terminal-only capabilities, and they belong together because they answer one
// question an auditor and an operator both ask: what leaves this system, and
// what runs inside it that we did not write.
//
// Secrets are shown once, at creation, and never again. A webhook secret is a
// shared key — the receiver needs the same bytes, so it cannot be stored
// hashed — and a screen that redisplays it turns every glance at the page into
// an exposure.

// Integrations gives the admin what this store connects to.
type Integrations struct {
	// Webhooks and their delivery history.
	Webhooks     func() ([]webhook.Endpoint, []webhook.Delivery, error)
	SaveWebhooks func([]webhook.Endpoint) error
	// Extensions are the sandboxed processes this store will run.
	Extensions     func() ([]ext.Manifest, error)
	SaveExtensions func([]ext.Manifest) error
	// Pin computes the hash of an extension's executable, so the binary that
	// runs is the binary that was reviewed.
	Pin func(path string) (string, error)
	// Provider describes the identity provider, if one is configured. It never
	// returns the client secret: that lives in the environment and this
	// process has no reason to put it on a page.
	Provider func() (issuer, clientID, redirect, claim string, verified bool, ok bool)
	// Events reads the audit log, for a SIEM export.
	Events func() ([]audit.Event, error)
}

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Administrator information: a list of every endpoint this system posts to
	// and every process it runs is a map of the blast radius. Gated on the same
	// permission as the posture dashboard, for the same reason.
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Integrations == nil {
		s.unwired(w, r, p, "Integrations", "webhooks, extensions and log forwarding")
		return
	}

	data := map[string]any{
		"Nav": "integrations", "Title": "Integrations", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"Formats": siem.Formats(),
		"Hooks":   []ext.Hook{ext.OnValidate, ext.OnTransform, ext.OnPublish},
	}

	if s.Integrations.Webhooks != nil {
		endpoints, deliveries, err := s.Integrations.Webhooks()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Redacted before it reaches a template. The secret never leaves this
		// function, so no future change to the page can accidentally print it.
		safe := make([]webhook.Endpoint, 0, len(endpoints))
		for _, e := range endpoints {
			safe = append(safe, webhook.Redact(e))
		}
		data["Endpoints"] = safe
		data["Hints"] = secretHints(endpoints)
		if len(deliveries) > 20 {
			deliveries = deliveries[len(deliveries)-20:]
		}
		data["Deliveries"] = deliveries
	}
	if s.Integrations.Extensions != nil {
		exts, err := s.Integrations.Extensions()
		if err != nil {
			// A manifest that does not validate is reported rather than
			// swallowed: an unusable extension discovered at publish time is
			// discovered in the middle of somebody's work.
			data["ExtError"] = err.Error()
		} else {
			data["Extensions"] = exts
		}
	}
	if s.Integrations.Provider != nil {
		issuer, clientID, redirect, claim, verified, configured := s.Integrations.Provider()
		data["OIDC"] = configured
		data["Issuer"], data["ClientID"] = issuer, clientID
		data["Redirect"], data["Claim"] = redirect, claim
		data["RequireVerified"] = verified
	}
	s.render(w, r, "integrations.html", data)
}

// secretHints gives each endpoint a few characters of its key.
//
// Enough to tell two endpoints apart when rotating one of them, and not enough
// to be the key. The alternative is showing nothing, which makes "did I update
// the right one" unanswerable, or showing everything, which makes the page a
// credential store.
func secretHints(endpoints []webhook.Endpoint) map[string]string {
	out := map[string]string{}
	for _, e := range endpoints {
		out[e.URL] = webhook.SecretHint(e.Secret)
	}
	return out
}

// handleWebhookSave adds an endpoint and mints its secret.
func (s *Server) handleWebhookSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.integrationWriter(w, r)
	if !ok {
		return
	}
	if s.Integrations.Webhooks == nil || s.Integrations.SaveWebhooks == nil {
		s.intRedirect(w, r, "", "webhooks are not wired up in this build")
		return
	}
	target := strings.TrimSpace(r.FormValue("url"))
	if !strings.HasPrefix(target, "https://") {
		// http is refused rather than warned about. The payload carries what
		// changed and the signature proves who sent it; over cleartext both are
		// readable and the signature is replayable by anyone on the path.
		s.intRedirect(w, r, "", "a webhook endpoint has to be https. Over "+
			"cleartext the payload is readable and the signature is replayable "+
			"by anyone on the path.")
		return
	}
	endpoints, _, err := s.Integrations.Webhooks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, e := range endpoints {
		if e.URL == target {
			s.intRedirect(w, r, "", target+" is already registered")
			return
		}
	}
	secret, err := webhook.NewSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	e := webhook.Endpoint{URL: target, Secret: secret,
		Note: strings.TrimSpace(r.FormValue("note"))}
	for _, t := range strings.Split(r.FormValue("types"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			e.Types = append(e.Types, t)
		}
	}
	if err := s.Integrations.SaveWebhooks(append(endpoints, e)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "webhook.add", "/", map[string]string{"url": target,
		"types": strings.Join(e.Types, ",")})

	// Rendered, not redirected. Every other write on this screen ends in a
	// redirect so a refresh does not repeat it, and this one deliberately does
	// not: the secret would have to travel in the query string, which is the
	// same mistake the sign-in form used to make. A credential in a URL is a
	// credential in the browser's history, the server's access log and the
	// Referer of every outbound link, and none of those are places anybody
	// thinks to clear.
	s.render(w, r, "secret.html", map[string]any{
		"Title": "Endpoint added", "Principal": p,
		"URL": target, "Secret": secret,
	})
}

// handleWebhookRemove deletes an endpoint, or turns one off.
func (s *Server) handleWebhookRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.integrationWriter(w, r)
	if !ok {
		return
	}
	if s.Integrations.Webhooks == nil || s.Integrations.SaveWebhooks == nil {
		s.intRedirect(w, r, "", "webhooks are not wired up in this build")
		return
	}
	endpoints, _, err := s.Integrations.Webhooks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	target := r.FormValue("url")
	// Disabling keeps the configuration. Turning an endpoint off during an
	// incident should not mean retyping the URL and rotating the secret
	// afterwards, which is what makes people leave it on instead.
	disable := r.FormValue("disable") != ""

	kept := make([]webhook.Endpoint, 0, len(endpoints))
	found := false
	for _, e := range endpoints {
		if e.URL != target {
			kept = append(kept, e)
			continue
		}
		found = true
		if disable {
			e.Disabled = !e.Disabled
			kept = append(kept, e)
		}
	}
	if !found {
		s.intRedirect(w, r, "", "there is no endpoint "+target)
		return
	}
	if err := s.Integrations.SaveWebhooks(kept); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	action, msg := "webhook.remove", "removed "+target
	if disable {
		action, msg = "webhook.toggle", "toggled "+target
	}
	s.auditPub(p, action, "/", map[string]string{"url": target})
	s.intRedirect(w, r, msg, "")
}

// handleExtensionSave registers a sandboxed process.
func (s *Server) handleExtensionSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.integrationWriter(w, r)
	if !ok {
		return
	}
	if s.Integrations.Extensions == nil || s.Integrations.SaveExtensions == nil {
		s.intRedirect(w, r, "", "extensions are not wired up in this build")
		return
	}
	m := ext.Manifest{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Version:     strings.TrimSpace(r.FormValue("version")),
		Description: strings.TrimSpace(r.FormValue("description")),
		// Optional is a decision with consequences, so it is a box somebody
		// ticks rather than a default. An extension registered to validate
		// content exists to refuse some of it: if it crashes, nothing
		// validated that page, and continuing anyway records a check that did
		// not happen.
		Optional: r.FormValue("optional") != "",
	}
	for _, part := range strings.Fields(r.FormValue("command")) {
		m.Command = append(m.Command, part)
	}
	for _, h := range r.Form["hooks"] {
		m.Hooks = append(m.Hooks, ext.Hook(h))
	}
	// Fields are what it is sent, and empty means none rather than all. An
	// extension that gets everything by default is one that sees the
	// unpublished legal review because somebody added a field last Tuesday.
	for _, f := range strings.Split(r.FormValue("fields"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			m.Fields = append(m.Fields, f)
		}
	}

	// Pinned at registration. The binary that runs is the binary that was
	// reviewed; without a pin, replacing the file on disk replaces the code
	// with no record and no signal.
	if len(m.Command) > 0 && s.Integrations.Pin != nil {
		if sum, err := s.Integrations.Pin(m.Command[0]); err == nil {
			m.SHA256 = sum
		} else {
			s.intRedirect(w, r, "", fmt.Sprintf(
				"cannot hash %s, so it cannot be pinned: %v", m.Command[0], err))
			return
		}
	}
	if err := m.Validate(); err != nil {
		s.intRedirect(w, r, "", err.Error())
		return
	}

	exts, err := s.Integrations.Extensions()
	if err != nil {
		s.intRedirect(w, r, "", err.Error())
		return
	}
	replaced := false
	for i := range exts {
		if exts[i].Name == m.Name {
			exts[i], replaced = m, true
			break
		}
	}
	if !replaced {
		exts = append(exts, m)
	}
	if err := s.Integrations.SaveExtensions(exts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "ext.add", "/", map[string]string{"extension": m.Name,
		"sha256": shortHash(m.SHA256), "optional": fmt.Sprint(m.Optional)})
	s.intRedirect(w, r, "registered "+m.Name+", pinned to "+shortHash(m.SHA256), "")
}

func (s *Server) handleExtensionRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.integrationWriter(w, r)
	if !ok {
		return
	}
	if s.Integrations.Extensions == nil || s.Integrations.SaveExtensions == nil {
		s.intRedirect(w, r, "", "extensions are not wired up in this build")
		return
	}
	exts, err := s.Integrations.Extensions()
	if err != nil {
		s.intRedirect(w, r, "", err.Error())
		return
	}
	name := r.FormValue("name")
	kept := make([]ext.Manifest, 0, len(exts))
	for _, m := range exts {
		if m.Name != name {
			kept = append(kept, m)
		}
	}
	if len(kept) == len(exts) {
		s.intRedirect(w, r, "", "there is no extension "+name)
		return
	}
	if err := s.Integrations.SaveExtensions(kept); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "ext.remove", "/", map[string]string{"extension": name})
	s.intRedirect(w, r, "removed "+name, "")
}

// handleSIEMExport writes the audit log in a format a SIEM ingests.
//
// It answers as a download rather than rendering into the page. The export
// carries an integrity envelope over the events it contains, and a copy that
// went through a browser's rendering is a copy whose bytes nobody can verify.
func (s *Server) handleSIEMExport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.integrationWriter(w, r)
	if !ok {
		return
	}
	if s.Integrations.Events == nil {
		s.intRedirect(w, r, "", "this build has no access to the audit log")
		return
	}
	events, err := s.Integrations.Events()
	if err != nil {
		s.intRedirect(w, r, "", err.Error())
		return
	}
	format := siem.Format(r.FormValue("format"))
	// Pseudonyms stay on unless somebody asks otherwise, and asking is
	// recorded. Revealing cannot recover identifiers the log never stored in
	// the clear — it only stops this from redacting what the log does hold.
	reveal := r.FormValue("reveal") != ""

	res, err := siem.Export(format, events, siem.Options{Reveal: reveal},
		time.Now())
	if err != nil {
		s.intRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "siem.export", "/", map[string]string{
		"format": string(format), "events": fmt.Sprint(res.Count),
		"revealed": fmt.Sprint(reveal)})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="audit-%s.log"`, format))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(res.Body))
}

func (s *Server) integrationWriter(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return principal{}, false
	}
	if s.Integrations == nil {
		s.unwired(w, r, p, "Integrations",
			"webhooks, extensions and log forwarding")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) intRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/integrations"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
