// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/profile"
)

// SecurityProfile is the Security profile screen: which features this
// installation runs, the change that set each, and the signed manifest that
// records them (internal/profile).
type SecurityProfile struct {
	// View is the profile as it stands.
	View func() (ProfileView, error)
	// Switch turns a feature on or off with a reason, as by. Nil leaves the
	// screen read-only.
	Switch func(feature string, on bool, reason string, by Actor) error
	// Manifest is the signed manifest's file, nil when none has been
	// signed.
	Manifest func() ([]byte, error)
}

// ProfileView is the profile as the screen shows it.
type ProfileView struct {
	Profile  string
	Since    time.Time
	By       string
	Features []ProfileFeature
	// Manifest and Key are the signed manifest's digest and the key that
	// signed it; Problem says why it cannot be shown as evidence, when it
	// cannot.
	Manifest, Key, Problem string
}

// ProfileFeature is one feature on the screen.
type ProfileFeature struct {
	profile.Feature
	On     bool
	Change *profile.Change
}

// Where is everywhere the feature is reached, for the screen to say what
// switching it off closes.
func (f ProfileFeature) Where() string {
	var parts []string
	for _, c := range f.Commands {
		parts = append(parts, "quilzo "+c)
	}
	parts = append(parts, f.Admin...)
	parts = append(parts, f.Site...)
	return strings.Join(parts, ", ")
}

func (s *Server) handleSecurityProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	data := map[string]any{"Nav": "security", "Title": "Security profile", "Principal": p,
		"Message": q.Get("m"), "Error": q.Get("e"), "Field": q.Get("f")}
	if s.SecurityProfile == nil || s.SecurityProfile.View == nil {
		data["Off"] = true
		s.render(w, r, "secprofile.html", data)
		return
	}
	v, err := s.SecurityProfile.View()
	if err != nil {
		data["Error"] = err.Error()
	}
	data["View"] = v
	data["Secured"] = v.Profile == profile.Security
	data["CanSwitch"] = s.SecurityProfile.Switch != nil && s.allows(p, auth.ActGrant, "/")
	data["HasManifest"] = v.Manifest != "" && s.SecurityProfile.Manifest != nil
	s.render(w, r, "secprofile.html", data)
}

// handleSecurityProfileAct switches one feature, for an administrator, with
// the reason the form asks for.
func (s *Server) handleSecurityProfileAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	feature := r.FormValue("feature")
	back := func(k, v string) {
		to := "/security/profile?" + k + "=" + url.QueryEscape(v)
		if k == "e" {
			to += "&f=" + url.QueryEscape(feature) + "#reason-" + url.PathEscape(feature)
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
	}
	if s.SecurityProfile == nil || s.SecurityProfile.Switch == nil {
		back("e", "switching features is not wired up in this build")
		return
	}
	f, known := profile.Lookup(feature)
	if !known {
		back("e", "choose a feature to switch")
		return
	}
	on := r.FormValue("to") == "on"
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		back("e", "Give a reason: switching "+f.Title+" changes what this installation runs, and the record keeps why.")
		return
	}
	if err := s.SecurityProfile.Switch(feature, on, reason, p.actor()); err != nil {
		back("e", err.Error())
		return
	}
	if on {
		back("m", f.Title+" is switched back on. The change and its reason are in the audit log and the signed manifest.")
		return
	}
	back("m", f.Title+" is switched off. The change and its reason are in the audit log and the signed manifest.")
}

// handleSecurityProfileManifest is the signed manifest, to download and hand
// to an auditor.
func (s *Server) handleSecurityProfileManifest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.assuranceReader(w, r); !ok {
		return
	}
	if s.SecurityProfile == nil || s.SecurityProfile.Manifest == nil {
		http.Error(w, "this build keeps no feature manifest", http.StatusServiceUnavailable)
		return
	}
	body, err := s.SecurityProfile.Manifest()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if body == nil {
		http.Error(w, "no feature manifest has been signed: no profile was applied to this store", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="quilzo.feature-manifest.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
