package admin

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
)

// Managing people, and managing the credentials they hold.
//
// These are two different questions that look like one, and conflating them is
// how an administrator comes to believe they have removed somebody's access
// when they have not.
//
//	Who is allowed to do what        — the policy. Bindings. Durable.
//	Who can act right now            — the tokens. Credentials. Live.
//
// Revoking a binding stops the *next* authorisation check from passing. It does
// not invalidate a token already in somebody's hand, because the token carries
// its own role: that is what makes a scoped token narrower than its principal.
// So removing a person means both, and a screen that offers only the first is a
// screen that lies about what it did.
//
// This program has no server-side sessions. Sign-in produces a bearer token in
// a cookie, and the token is the session — there is no session table to look
// at. So "who is logged in" has to be answered honestly as "who holds a usable
// credential, and when did they last use it", which is a slightly different
// question and the only one the design can answer truthfully.

// person is one principal and everything known about them.
type person struct {
	Name     string
	Bindings []auth.Binding
	// Roles is the effective set, deduplicated, for the summary column.
	Roles []string
	// Sessions are their usable credentials.
	Sessions []session
	// LastSeen is the most recent use of any of their tokens. Zero means
	// never, which is different from long ago and worth showing as such.
	LastSeen time.Time
	IsSelf   bool
}

// session is one usable credential.
type session struct {
	ID        string
	Name      string
	Role      auth.Role
	Scope     string
	Created   time.Time
	Expires   time.Time
	LastUsed  time.Time
	Never     bool
	IsSession bool // exchanged from another token
	// Active is a judgement rather than a fact, and the threshold is stated
	// where it is made rather than buried: a token used within the last
	// fifteen minutes is somebody working now. Longer than that and the
	// honest answer is "holds a credential", not "is logged in".
	Active bool
}

const activeWithin = 15 * time.Minute

// handlePeople lists everybody, what they may do, and what they hold.
func (s *Server) handlePeople(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	now := time.Now()

	byName := map[string]*person{}
	for _, b := range s.Policy.Snapshot() {
		who := byName[b.Principal]
		if who == nil {
			who = &person{Name: b.Principal, IsSelf: b.Principal == p.Name}
			byName[b.Principal] = who
		}
		who.Bindings = append(who.Bindings, b)
	}

	// Somebody holding a token but named in no binding still has to appear.
	// A person invisible on this screen is a person nobody removes.
	for _, t := range s.Tokens.Snapshot() {
		if usable, _ := t.Usable(now); !usable {
			continue
		}
		who := byName[t.Principal]
		if who == nil {
			who = &person{Name: t.Principal, IsSelf: t.Principal == p.Name}
			byName[t.Principal] = who
		}
		sess := session{
			ID: t.ID, Name: t.Name, Role: t.Role,
			Scope:     t.Scope.String(),
			Created:   time.Unix(t.CreatedAt, 0),
			Expires:   time.Unix(t.ExpiresAt, 0),
			IsSession: t.IsSession(),
		}
		if t.LastUsed > 0 {
			sess.LastUsed = time.Unix(t.LastUsed, 0)
			sess.Active = now.Sub(sess.LastUsed) < activeWithin
			if sess.LastUsed.After(who.LastSeen) {
				who.LastSeen = sess.LastUsed
			}
		} else {
			sess.Never = true
		}
		who.Sessions = append(who.Sessions, sess)
	}

	people := make([]*person, 0, len(byName))
	for _, who := range byName {
		seen := map[string]bool{}
		for _, b := range who.Bindings {
			label := string(b.Role)
			if b.Deny {
				label = "deny " + label
			}
			if b.Resource != "/" {
				label += " on " + b.Resource
			}
			if b.OwnOnly {
				label += ", own only"
			}
			if !seen[label] {
				seen[label] = true
				who.Roles = append(who.Roles, label)
			}
		}
		sort.Strings(who.Roles)
		sort.Slice(who.Sessions, func(i, j int) bool {
			return who.Sessions[i].LastUsed.After(who.Sessions[j].LastUsed)
		})
		people = append(people, who)
	}
	sort.Slice(people, func(i, j int) bool { return people[i].Name < people[j].Name })

	s.render(w, r, "people.html", map[string]any{
		"Title": "People", "Principal": p, "People": people,
		"Roles": auth.Roles, "ActiveWithin": activeWithin.String(),
		"Message": r.URL.Query().Get("m"),
	})
}

// handlePeopleGrant adds or changes what somebody may do.
func (s *Server) handlePeopleGrant(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return
	}
	who := strings.TrimSpace(r.FormValue("principal"))
	role := auth.Role(strings.TrimSpace(r.FormValue("role")))
	on := strings.TrimSpace(r.FormValue("resource"))
	if on == "" {
		on = "/"
	}
	b := auth.Binding{
		Principal: who, Role: role, Resource: on,
		Deny:      r.FormValue("deny") == "on",
		OwnOnly:   r.FormValue("own_only") == "on",
		GrantedBy: p.Name,
		Note:      strings.TrimSpace(r.FormValue("note")),
	}
	if err := s.Policy.Grant(b); err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	if err := s.save(); err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	s.audit("access.grant", "/"+who, map[string]string{
		"role": string(role), "resource": on, "by": p.Name,
		"own_only": fmt.Sprintf("%t", b.OwnOnly),
	})
	s.peopleBack(w, r, fmt.Sprintf("%s is now %s on %s", who, role, on))
}

// handlePeopleRevoke removes a binding.
func (s *Server) handlePeopleRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return
	}
	who := strings.TrimSpace(r.FormValue("principal"))
	role := auth.Role(strings.TrimSpace(r.FormValue("role")))
	on := strings.TrimSpace(r.FormValue("resource"))

	// Removing your own last admin binding locks the store. Refused here
	// rather than left to be discovered: the recovery path exists and is
	// deliberately unpleasant, and nobody should reach it by clicking a button
	// on a list.
	if who == p.Name && role == auth.RoleAdmin {
		if s.lastAdmin(who) {
			s.peopleBack(w, r, "that is the last administrator binding, and "+
				"removing it would leave nobody able to administer this store")
			return
		}
	}
	n := s.Policy.Revoke(who, role, on)
	if n == 0 {
		s.peopleBack(w, r, "no such binding")
		return
	}
	if err := s.save(); err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	s.audit("access.revoke", "/"+who, map[string]string{
		"role": string(role), "resource": on, "by": p.Name,
		"removed": fmt.Sprintf("%d", n),
	})
	s.peopleBack(w, r, fmt.Sprintf(
		"removed %s from %s — any token they already hold still works until "+
			"it is revoked below", role, who))
}

// handleSessionRevoke revokes one credential.
func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActToken)
	if !ok {
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	n, err := s.Tokens.Revoke(id)
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	if err := s.save(); err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	s.audit("token.revoke", "/", map[string]string{
		"token": id, "by": p.Name, "cascaded": fmt.Sprintf("%d", n),
	})
	msg := "that credential no longer works"
	if n > 1 {
		// The cascade is the point and is worth saying: revoking a token that
		// sessions were minted from has to invalidate them too, or revocation
		// does not revoke.
		msg = fmt.Sprintf("revoked, along with %d session(s) minted from it", n-1)
	}
	s.peopleBack(w, r, msg)
}

// postFrom is the shared preamble for the write handlers here: POST only,
// authenticated, authorised, same-origin, form parsed.
func (s *Server) postFrom(w http.ResponseWriter, r *http.Request, act auth.Action) (
	principal, bool) {

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, act, "/") {
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) peopleBack(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/people?m="+urlQueryEscape(msg), http.StatusSeeOther)
}

// lastAdmin reports whether this principal is the only one who can grant.
func (s *Server) lastAdmin(who string) bool {
	for _, other := range s.Policy.Principals() {
		if other == who {
			continue
		}
		if s.Policy.Evaluate(other, auth.ActGrant, "/").Allowed {
			return false
		}
	}
	return true
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ' ':
			if c == ' ' {
				b.WriteByte('+')
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

// save persists whatever the host gave it a way to persist.
//
// Both are optional so a test can construct a server without them, and both
// failing loudly matters more than either succeeding quietly: an access change
// that is not written is an access change that disappears at the next restart,
// and the administrator has already been told it worked.
func (s *Server) save() error {
	if s.SavePolicy != nil {
		if err := s.SavePolicy(s.Policy); err != nil {
			return fmt.Errorf("the change was not saved: %w", err)
		}
	}
	if s.SaveTokens != nil {
		if err := s.SaveTokens(s.Tokens); err != nil {
			return fmt.Errorf("the change was not saved: %w", err)
		}
	}
	return nil
}

func (s *Server) audit(action, resource string, detail map[string]string) {
	if s.Audit != nil {
		s.Audit(action, resource, detail)
	}
}
