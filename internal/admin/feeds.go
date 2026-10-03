// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
)

// The Feeds screen: what other systems push here, whether it is arriving,
// and what it has said.
//
// A feed is added here or with quilzo inbound. Either way it takes an
// administrator of the whole site, because what a feed says reaches the
// automations, and some of them change who can get in.

// FeedView is one feed, for the screen.
type FeedView struct {
	Name, Kind, KindWords, Path      string
	Off                              bool
	Issuer, Stream, Status, Verified string
	Mapping                          string
	Deliveries, Records, Stored      int
	Known, Missed, Signals, Refused  int
	Last, LastRefused, Why, Error    string
	Field                            string
	Recent                           []FeedSignal
}

// FeedSignal is one signal a feed carried.
type FeedSignal struct {
	At, Type, Words, Person, Severity, Tone, Reason string
}

// FeedsAdmin is what the screen needs from the program.
type FeedsAdmin struct {
	List func() ([]FeedView, error)
	// Mappings are the source mappings a webhook's records can go through.
	Mappings func() []string
	// Add makes a feed and returns what to tell the sender, once.
	Add    func(kind, name, mapping, issuer, publicURL, alias, by string) ([]string, error)
	SetOff func(name string, off bool, by string) error
	Remove func(name, by string) error
}

func (s *Server) handleFeeds(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Feeds", "Nav": "feeds", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"Base":      "https://" + r.Host,
		"SiteAdmin": s.Policy != nil && s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed}
	if s.Feeds == nil || s.Feeds.List == nil {
		data["Unavailable"] = "This build was started without feeds."
		s.render(w, r, "feeds.html", data)
		return
	}
	feeds, err := s.Feeds.List()
	if err != nil {
		data["Unavailable"] = err.Error()
	}
	data["Feeds"] = feeds
	if s.Feeds.Mappings != nil {
		data["Mappings"] = s.Feeds.Mappings()
	}
	s.render(w, r, "feeds.html", data)
}

func (s *Server) handleFeedsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	back := func(k, v string) {
		http.Redirect(w, r, "/security/feeds?"+url.Values{k: {v}}.Encode(), http.StatusSeeOther)
	}
	if s.Feeds == nil {
		back("e", "This build has no feeds.")
		return
	}
	// Whoever could add a feed could make a signal up and have it acted
	// on, so it is the whole site's decision.
	if s.Policy == nil || !s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed {
		back("e", "Changing a feed takes an administrator of the whole site: what a feed says reaches the automations.")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	switch r.FormValue("do") {
	case "add":
		kind := r.FormValue("kind")
		shown, err := s.Feeds.Add(kind, name, r.FormValue("mapping"), strings.TrimSpace(r.FormValue("issuer")),
			"https://"+r.Host, strings.TrimSpace(r.FormValue("alias")), p.Name)
		if err != nil {
			back("e", err.Error())
			return
		}
		s.audit("inbound.added", "/feeds/"+name, map[string]string{"by": p.Name, "kind": kind})
		// The secret is shown on this answer and nowhere else: not in a
		// redirect, which would put it in the address bar and the history.
		w.Header().Set("Cache-Control", "no-store")
		type pair struct{ Label, Value string }
		var pairs []pair
		for _, line := range shown {
			label, value, ok := strings.Cut(line, ": ")
			if !ok {
				label, value = "Secret", line
			}
			pairs = append(pairs, pair{strings.ToUpper(label[:1]) + label[1:], value})
		}
		s.render(w, r, "feeds.html", map[string]any{"Title": "Feeds", "Nav": "feeds", "Principal": p,
			"Added": name, "Shown": pairs, "AddedURL": "https://" + r.Host + "/feeds/" + name, "AddedKind": kind})
		return
	case "on", "off":
		if err := s.Feeds.SetOff(name, r.FormValue("do") == "off", p.Name); err != nil {
			back("e", err.Error())
			return
		}
		s.audit("inbound."+r.FormValue("do"), "/feeds/"+name, map[string]string{"by": p.Name})
		back("m", name+" is "+r.FormValue("do")+".")
	case "remove":
		if err := s.Feeds.Remove(name, p.Name); err != nil {
			back("e", err.Error())
			return
		}
		s.audit("inbound.removed", "/feeds/"+name, map[string]string{"by": p.Name})
		back("m", "Removed "+name+". Anything sent to it is refused from now.")
	default:
		back("e", "Nothing to do.")
	}
}
