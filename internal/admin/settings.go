package admin

import (
	"net/http"
	"strings"

	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/config"
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
	// Reading is a view: an author who cannot see the settings cannot tell why
	// their publish was refused.
	if !s.can(w, r, p, auth.ActView, "/") {
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
