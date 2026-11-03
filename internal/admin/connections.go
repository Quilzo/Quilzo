// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connect"
)

// Connected accounts: a person's own accounts at the providers an
// administrator declared (internal/connect), for agents acting for them.
//
// Each person sees and changes only their own. Connecting starts here and
// finishes here, at /connections/callback, in the browser of the person
// who started it: the provider's answer is refused for anybody else, so a
// link to somebody's half-finished connection cannot put their account in
// another person's name.

// Connections are the hooks the screen uses.
type Connections struct {
	Providers func() ([]connect.Provider, error)
	Mine      func(person string) ([]ConnectedAccount, error)
	// Start keeps a connection in progress for person, and says where to
	// send their browser.
	Start func(provider, person string) (string, error)
	// Finish completes one, for the person signed in: the provider's title.
	Finish func(ctx context.Context, state, code, person string) (string, error)
	Revoke func(ctx context.Context, provider, person string) error
}

// ConnectedAccount is one of a person's connections, as the screen shows it.
type ConnectedAccount struct {
	Provider  string
	Scope     string
	Connected time.Time
}

func (s *Server) connectionsReady(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return p, false
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return p, false
	}
	return p, true
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	p, ok := s.connectionsReady(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Nav": "accounts", "Title": "Connected accounts", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Connections == nil || s.Connections.Providers == nil || s.Connections.Mine == nil {
		data["Unavailable"] = "This build was started without connected accounts."
		s.render(w, r, "connections.html", data)
		return
	}
	providers, err := s.Connections.Providers()
	if err != nil {
		data["Unavailable"] = "The providers could not be read: " + err.Error()
		s.render(w, r, "connections.html", data)
		return
	}
	mine, err := s.Connections.Mine(p.Name)
	if err != nil {
		data["Unavailable"] = "Your connections could not be read: " + err.Error()
		s.render(w, r, "connections.html", data)
		return
	}
	connected := map[string]ConnectedAccount{}
	for _, a := range mine {
		connected[a.Provider] = a
	}
	data["Providers"], data["Connected"] = providers, connected
	s.render(w, r, "connections.html", data)
}

func (s *Server) handleConnectionsChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.connectionsReady(w, r)
	if !ok {
		return
	}
	back := func(key, msg string) {
		http.Redirect(w, r, "/connections?"+key+"="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	if s.Connections == nil || s.Connections.Start == nil || s.Connections.Revoke == nil {
		back("e", "this build cannot connect accounts")
		return
	}
	if p.Limits.ReadOnly {
		back("e", "a read-only session connects nothing")
		return
	}
	provider := strings.TrimSpace(r.FormValue("provider"))
	switch r.FormValue("op") {
	case "connect":
		to, err := s.Connections.Start(provider, p.Name)
		if err != nil {
			back("e", err.Error())
			return
		}
		s.audit("connect.start", "/connections", map[string]string{"by": p.Name, "provider": provider})
		http.Redirect(w, r, to, http.StatusSeeOther)
	case "revoke":
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := s.Connections.Revoke(ctx, provider, p.Name); err != nil {
			back("e", err.Error())
			return
		}
		s.audit("connect.revoked", "/connections", map[string]string{"by": p.Name, "provider": provider, "own": "true"})
		back("m", "Disconnected. Agents acting for you no longer reach it as you.")
	default:
		back("e", "nothing asked")
	}
}

// handleConnectionsCallback finishes a connection, where the provider sends
// the person back.
func (s *Server) handleConnectionsCallback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.connectionsReady(w, r)
	if !ok {
		return
	}
	back := func(key, msg string) {
		http.Redirect(w, r, "/connections?"+key+"="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	if s.Connections == nil || s.Connections.Finish == nil {
		back("e", "this build cannot connect accounts")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		// The provider's error code, and only when it is one: this address
		// is a GET anybody can link to, with no state yet checked, so its
		// free text would be a sentence of the linker's on a screen this
		// server vouches for (flash.go). OAuth's codes are a word with
		// underscores (RFC 6749 4.1.2.1).
		msg := "The provider did not connect it."
		if oauthErrorCode.MatchString(e) {
			msg = "The provider did not connect it (" + e + ")."
		}
		back("e", msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	title, err := s.Connections.Finish(ctx, q.Get("state"), q.Get("code"), p.Name)
	if err != nil {
		back("e", err.Error())
		return
	}
	back("m", "Connected your "+title+" account. Agents acting for you may now use it where an integration says so.")
}

// oauthErrorCode is the shape of an OAuth error code.
var oauthErrorCode = regexp.MustCompile(`^[a-z_]{1,40}$`)
