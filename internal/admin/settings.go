// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
)

// Configuration in the admin.
//
// Twenty-five settings that decide how every other control behaves, and until
// now the only way to see or change one was a terminal. An operator evaluating
// this could not tell what it was configured to do.
//
// The screen has to carry the thing that makes the configuration model work,
// or it becomes a plain form and the model is lost: a setting weaker than its
// default is allowed, needs a reason, and is reported until it is put back.
// That is the whole design — nothing is forbidden and nothing is quiet — and a
// form that either refused the change or accepted it silently would be
// implementing a different product.

// Settings is what the host supplies so the admin can read and write the
// configuration without knowing where it is stored.
type Settings struct {
	Load func() (*config.Config, error)
	Save func(*config.Config) error
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Reading these needs the permission to write, not merely to read.
	//
	// The reason to show them at all is that somebody whose write was refused
	// has to be able to find out which limit refused it. That argument covers
	// an author and stops there: a reader never writes, so there is no
	// refusal to explain to them, and the list does say which security
	// controls this deployment has relaxed — which is a small target list for
	// the lowest-privileged account in the building.
	//
	// Changing one still needs more than this; the save handler is gated
	// separately and a weakening also needs a recorded reason.
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Settings == nil || s.Settings.Load == nil {
		s.render(w, r, "settings.html", map[string]any{
			"Title": "Settings", "Principal": p, "Nav": "settings",
			"Unavailable": "this server was started without the configuration",
		})
		return
	}
	cfg, err := s.Settings.Load()
	if err != nil {
		s.render(w, r, "settings.html", map[string]any{
			"Title": "Settings", "Principal": p, "Nav": "settings",
			"Unavailable": err.Error(),
		})
		return
	}

	type group struct {
		Name  string
		Items []config.Effective
	}
	var groups []group
	byName := map[string]int{}
	for _, e := range cfg.Effectives() {
		g, _, _ := strings.Cut(e.Setting.Key, ".")
		i, seen := byName[g]
		if !seen {
			groups = append(groups, group{Name: g})
			i = len(groups) - 1
			byName[g] = i
		}
		groups[i].Items = append(groups[i].Items, e)
	}

	s.render(w, r, "settings.html", map[string]any{
		"Title": "Settings", "Principal": p, "Nav": "settings",
		"Groups": groups, "Weakened": cfg.Weakened(),
		"Message":  r.URL.Query().Get("m"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed,
		"Days":     int(config.MaxAcceptance.Hours() / 24),
	})
}

func (s *Server) handleSettingSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return
	}
	if s.Settings == nil {
		http.Error(w, "no configuration", http.StatusNotFound)
		return
	}
	key := strings.TrimSpace(r.FormValue("key"))
	value := strings.TrimSpace(r.FormValue("value"))
	reason := strings.TrimSpace(r.FormValue("reason"))

	cfg, err := s.Settings.Load()
	if err != nil {
		s.settingsBack(w, r, err.Error())
		return
	}
	before := cfg.Raw(key)

	if r.FormValue("reset") == "1" {
		if err := cfg.Unset(key); err != nil {
			s.settingsBack(w, r, err.Error())
			return
		}
	} else if err := cfg.Set(key, value, reason, p.Name); err != nil {
		// The acceptance path is surfaced rather than flattened into "invalid".
		// A refusal that does not say a reason would make this work is a
		// refusal somebody reads as "you cannot", which is not what it means.
		var need *config.ErrNeedsAcceptance
		if asAcceptance(err, &need) {
			s.settingsBack(w, r, need.Why+
				" — supply a reason to make this change")
			return
		}
		s.settingsBack(w, r, err.Error())
		return
	}
	if err := s.Settings.Save(cfg); err != nil {
		s.settingsBack(w, r, err.Error())
		return
	}
	detail := map[string]string{
		"setting": key, "from": before, "to": cfg.Raw(key), "by": p.Name,
	}
	if reason != "" {
		detail["accepted_risk"] = reason
	}
	s.audit("config.set", "/", detail)
	s.settingsBack(w, r, key+" is now "+cfg.Raw(key))
}

func (s *Server) settingsBack(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/settings?m="+urlQueryEscape(msg), http.StatusSeeOther)
}

func asAcceptance(err error, target **config.ErrNeedsAcceptance) bool {
	e, ok := err.(*config.ErrNeedsAcceptance)
	if ok {
		*target = e
	}
	return ok
}

// secureCookie reports whether a cookie this response sets may be marked
// Secure.
//
// It was `r.TLS != nil` at every one of the eight places this program sets a
// cookie. That is correct when this process terminates TLS itself, and false
// in the deployment almost everybody actually has: a reverse proxy speaking
// HTTPS to the browser and plain HTTP to this. The session cookie carries the
// API token, so without Secure a browser will send a working credential over
// a plain-HTTP request to the same host — one mixed-content link, or one
// downgraded request, and it is in clear.
//
// Read from configuration rather than from a header. The header that would
// answer this is X-Forwarded-Proto and anybody can write it; internal/httpsig
// already refuses to trust it and says why. Trusting it here to decide whether
// a credential may travel in clear would be the same mistake with a worse
// consequence, so the deployment states once what it is.
//
// Off by default, because the admin is on loopback by default and a Secure
// cookie over plain HTTP is dropped by the browser — which would stop sign-in
// working rather than make anything safer.
func (s *Server) secureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.Settings == nil || s.Settings.Load == nil {
		return false
	}
	cfg, err := s.Settings.Load()
	if err != nil || cfg == nil {
		return false
	}
	return cfg.Bool("admin.behind_tls_proxy")
}
