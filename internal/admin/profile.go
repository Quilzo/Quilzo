package admin

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Your own account, and only your own.
//
// The split here is the whole design: a person may change how this looks to
// them and may end their own sessions, and may not change what they are
// allowed to do. That second half is not a limitation to be worked around —
// self-service privilege escalation is the shape of most access-control
// failures, and the way it usually arrives is a profile page that lets
// somebody edit one field too many.
//
// So the screen is in three parts, and the middle one is deliberately
// read-only:
//
//	what you may do        read-only, with the rule that decided it
//	your sessions          you can end any of your own, including this one
//	how this looks to you  yours entirely, stored in a cookie
//
// A display name is the one piece of information about a person this stores,
// because "dana" is a principal and a policy is written in terms of it, while
// "Dana Okonkwo" is what a colleague reading an audit log needs. Changing it
// changes a label and nothing else — which is why it is safe to let people do
// it, and why the principal itself is not editable here at any level.

// Profile is the person-supplied part of an account.
type Profile struct {
	// Load and Save hold display names, keyed by principal.
	Load func() (map[string]PersonDetails, error)
	Save func(map[string]PersonDetails) error
}

// PersonDetails is what somebody may say about themselves.
//
// Deliberately short. Every field here is data this system did not need before
// and now stores about a person, which is a privacy cost paid per field — so
// each one has to earn its place, and "what shall I call you" and "where can a
// colleague reach you" are the two that do.
type PersonDetails struct {
	// DisplayName is shown beside the principal. Never instead of it: an audit
	// record that says "Dana Okonkwo" and not which principal acted is an
	// audit record that cannot be checked against the policy.
	DisplayName string `json:"display_name,omitempty"`
	// Contact is free text — a room, a handle, a rota. Not validated as an
	// email address, because validating it would imply this sends mail, and
	// this program does not send mail.
	Contact string `json:"contact,omitempty"`
	// UpdatedAt is when they last changed it.
	UpdatedAt int64 `json:"updated_at,omitempty"`
}

// MaxDetail bounds a self-supplied field.
//
// A limit rather than none, because these are rendered on a screen an
// administrator reads, and an unbounded field somebody controls is a way to
// make that screen unreadable for everybody else.
const MaxDetail = 120

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}

	if r.Method == http.MethodPost {
		s.saveProfile(w, r, p)
		return
	}

	// What this person may do, resolved against the policy as written rather
	// than inferred from their role. A role is a rung; a binding can be
	// own-only, scoped to a subtree, or a deny — and only Evaluate knows.
	type permission struct {
		Action  string
		Allowed bool
		Reason  string
	}
	var may []permission
	for _, a := range auth.Actions() {
		d := s.Policy.Evaluate(p.Name, a, "/")
		may = append(may, permission{string(a), d.Allowed, d.Reason})
	}

	// Their own sessions, and nobody else's. The people screen is where an
	// administrator sees everybody; this is where a person sees themselves,
	// and the filter is the difference.
	type session struct {
		ID, Role, Resource string
		Issued, Expires    int64
		Current            bool
	}
	var mine []session
	here := s.currentTokenID(r)
	if s.Tokens != nil {
		for _, t := range s.Tokens.Snapshot() {
			if t.Principal != p.Name || t.Revoked {
				continue
			}
			mine = append(mine, session{
				ID: t.ID, Role: string(t.Role), Resource: t.Resource,
				Issued: t.CreatedAt, Expires: t.ExpiresAt,
				// Marked, so ending a session is a decision rather than a
				// surprise. Signing yourself out of a list of eight identical
				// rows is how somebody locks themselves out.
				Current: here != "" && t.ID == here,
			})
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Issued > mine[j].Issued })

	details := PersonDetails{}
	if s.Profile != nil && s.Profile.Load != nil {
		if all, err := s.Profile.Load(); err == nil {
			details = all[p.Name]
		}
	}

	s.render(w, r, "profile.html", map[string]any{
		"Nav": "profile", "Title": "You", "Principal": p,
		"Details": details, "May": may, "Sessions": mine,
		"Arrangement": s.arrangement(r, p),
		"Message":     r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
	})
}

// arrangement is the person's navigation order, as rows with move buttons.
type navRow struct {
	Key, Label, Group string
	First, Last       bool
}

func (s *Server) arrangement(r *http.Request, p principal) []navRow {
	ordered := applyOrder(visibleTo(s, p), storedOrder(r))

	// First and last within a group, because that is the boundary a move
	// respects. Without it the buttons at the edges do nothing and look
	// broken rather than disabled.
	count := map[string]int{}
	seen := map[string]int{}
	for _, d := range ordered {
		count[d.Group]++
	}
	out := make([]navRow, 0, len(ordered))
	for _, d := range ordered {
		seen[d.Group]++
		out = append(out, navRow{
			Key: d.Key, Label: d.Label, Group: d.Group,
			First: seen[d.Group] == 1, Last: seen[d.Group] == count[d.Group],
		})
	}
	return out
}

// saveProfile records what somebody says about themselves.
func (s *Server) saveProfile(w http.ResponseWriter, r *http.Request, p principal) {
	if s.Profile == nil || s.Profile.Save == nil {
		s.profileRedirect(w, r, "", "this build cannot store profile details")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	all := map[string]PersonDetails{}
	if s.Profile.Load != nil {
		if existing, err := s.Profile.Load(); err == nil && existing != nil {
			all = existing
		}
	}
	// Keyed by the authenticated principal, taken from the session and never
	// from the form. A profile screen that accepts "which account am I editing"
	// as a parameter is a profile screen that edits somebody else's.
	d := all[p.Name]
	d.DisplayName = clip(strings.TrimSpace(r.FormValue("display_name")), MaxDetail)
	d.Contact = clip(strings.TrimSpace(r.FormValue("contact")), MaxDetail)
	d.UpdatedAt = time.Now().Unix()
	all[p.Name] = d

	if err := s.Profile.Save(all); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "profile.update", "/"+p.Name, map[string]string{
		"display_name": d.DisplayName})
	s.profileRedirect(w, r, "saved", "")
}

// handleSessionEnd revokes one of the caller's own sessions.
//
// Separate from the administrator's revoke on the people screen, and gated on
// the token belonging to the person asking rather than on a role. Somebody
// with no administrative permission at all must still be able to end a session
// they think has been taken — making that an administrator's job means it
// happens tomorrow.
func (s *Server) handleSessionEnd(w http.ResponseWriter, r *http.Request) {
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
	id := r.FormValue("id")

	// Ownership is checked here and not taken from the form. The id names a
	// token; whether it is yours is a fact about the store.
	owned := false
	for _, t := range s.Tokens.Snapshot() {
		if t.ID == id && t.Principal == p.Name {
			owned = true
			break
		}
	}
	if !owned {
		// Not found rather than forbidden: telling somebody that a token
		// exists and belongs to another person is telling them something.
		s.profileRedirect(w, r, "", "you have no session with that identifier")
		return
	}
	n, err := s.Tokens.Revoke(id)
	if err != nil {
		s.profileRedirect(w, r, "", err.Error())
		return
	}
	if n == 0 {
		s.profileRedirect(w, r, "", "that session had already ended")
		return
	}
	if s.SaveTokens != nil {
		if err := s.SaveTokens(s.Tokens); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.auditPub(p, "session.end", "/"+p.Name, map[string]string{"session": id})

	// Ending the session you are using signs you out, which is the honest
	// outcome — leaving the cookie in place would mean a revoked credential
	// that still works until the next request notices.
	if s.currentTokenID(r) == "" {
		// The credential on this request no longer authenticates, which means
		// it was the one just revoked. Clearing the cookie is the honest
		// outcome; leaving it would be a revoked credential that still looks
		// signed in until the next request notices.
		s.handleSignOut(w, r)
		return
	}
	s.profileRedirect(w, r, plural2(n, "that session has ended",
		"that session and the ones minted from it have ended"), "")
}

// currentTokenID is the id of the credential this request arrived with.
//
// Resolved by authenticating it rather than by comparing strings, because the
// secret is never stored — only its hash is — so the only way to know which
// row a presented credential is, is to present it. Empty when there is none or
// when it no longer authenticates, and the second case is the useful one: it
// is how ending your own session is detected.
func (s *Server) currentTokenID(r *http.Request) string {
	raw := presentedToken(r)
	if raw == "" || s.Tokens == nil {
		return ""
	}
	t, err := s.Tokens.Authenticate(raw, time.Now())
	if err != nil {
		return ""
	}
	return t.ID
}

// presentedToken is the raw credential on this request, if there is one.
func presentedToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie("quilzo_token"); err == nil {
		return c.Value
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *Server) profileRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/profile"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
