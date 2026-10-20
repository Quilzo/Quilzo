// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
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

// bindingView is a binding as the screen shows it, with whether it is still
// in force worked out, because a template cannot ask a method about now.
type bindingView struct {
	auth.Binding
	Live  bool
	Until string
	// AppRole is the role an app declares that this row stands for, and
	// Parts what it grants: a role is shown and removed as one.
	AppRole string
	Parts   []string
}

func viewBinding(b auth.Binding) bindingView {
	v := bindingView{Binding: b, Live: b.Live(time.Now())}
	if b.Expires != 0 {
		v.Until = time.Unix(b.Expires, 0).UTC().Format("2 Jan 2006")
	}
	return v
}

// person is one principal and everything known about them.
type person struct {
	Name     string
	Bindings []bindingView
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
		part := fmt.Sprintf("%s on %s", b.What(), b.Resource)
		if role, ok := b.AppRoleOf(); ok {
			if i := slices.IndexFunc(who.Bindings, func(v bindingView) bool { return v.AppRole == role }); i >= 0 {
				who.Bindings[i].Parts = append(who.Bindings[i].Parts, part)
				continue
			}
			v := viewBinding(b)
			v.AppRole, v.Parts = role, []string{part}
			who.Bindings = append(who.Bindings, v)
			continue
		}
		who.Bindings = append(who.Bindings, viewBinding(b))
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
			label := b.What()
			if b.AppRole != "" {
				label = b.AppRole
			} else if b.Deny {
				label = "deny " + label
			}
			if b.Resource != "/" && b.AppRole == "" {
				label += " on " + b.Resource
			}
			if b.OwnOnly {
				// A binding written before the flag was withdrawn. It is shown
				// because it is in the policy file, and shown as inert because
				// it always was — reading "own only" as a restriction is the
				// mistake this whole change is about.
				label += " (own-only: never enforced, ignored)"
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

	// Everybody this store has heard of, for the grant form.
	//
	// Free text was a way to create a principal nobody notices: "dana " with a
	// trailing space, or "Dana", is a grant that silently applies to nobody,
	// and the screen showed it beside the real one as though both were real.
	// The store knows who exists — from the policy and from the credentials —
	// so the form offers them, and adding somebody genuinely new is a separate
	// field that says so.
	known := map[string]bool{}
	for _, who := range s.Policy.Principals() {
		known[who] = true
	}
	for _, t := range s.Tokens.Snapshot() {
		known[t.Principal] = true
	}
	names := make([]string, 0, len(known))
	for who := range known {
		names = append(names, who)
	}
	sort.Strings(names)

	s.render(w, r, "people.html", map[string]any{
		"Nav": "people", "Title": "People", "Principal": p, "People": people,
		"Roles": auth.Roles, "Jobs": auth.Jobs, "Permissions": auth.Permissions, "AppRoles": s.appRoles(),
		"ActiveWithin": activeWithin.String(),
		"Known":        names, "Message": r.URL.Query().Get("m"),
		"Error": r.URL.Query().Get("e"),
	})
}

// appRoles is the roles the installed features declare, or none when they
// cannot be read: the screen still grants everything else.
func (s *Server) appRoles() []auth.AppRole {
	if s.AppRoles == nil {
		return nil
	}
	roles, err := s.AppRoles()
	if err != nil {
		return nil
	}
	return roles
}

func (s *Server) appRoleNamed(name string) (auth.AppRole, bool) {
	for _, r := range s.appRoles() {
		if r.Name == name {
			return r, true
		}
	}
	return auth.AppRole{}, false
}

// handlePeopleGrant adds or changes what somebody may do.
func (s *Server) handlePeopleGrant(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return
	}
	// The list, or the new-person field when the list's blank option was
	// chosen. Named separately rather than overloading one input, so "I meant
	// to pick from the list and typed instead" cannot happen silently.
	who := strings.TrimSpace(r.FormValue("principal"))
	if who == "" {
		who = strings.TrimSpace(r.FormValue("new_principal"))
	}
	role := auth.Role(strings.TrimSpace(r.FormValue("role")))
	on := strings.TrimSpace(r.FormValue("resource"))
	if on == "" {
		on = "/"
	}
	var expires int64
	if u := strings.TrimSpace(r.FormValue("until")); u != "" {
		t, err := time.Parse("2006-01-02", u)
		if err != nil || !t.After(time.Now()) {
			s.peopleBack(w, r, "Until has to be a day in the future.")
			return
		}
		expires = t.Unix()
	}
	base := auth.Binding{
		Principal: who, Role: role, Resource: on,
		Deny: r.FormValue("deny") == "on",
		// own_only is not read from the form any more. The checkbox said
		// "only content they created", stored a binding that said so, and
		// nothing enforced it — see the error `quilzo auth grant --own-only`
		// now returns. A form field that cannot be honoured is not read.
		GrantedBy: p.Name,
		Note:      strings.TrimSpace(r.FormValue("note")),
		Expires:   expires,
	}
	bindings := []auth.Binding{base}
	// A permission, granted alone.
	if name, isPerm := strings.CutPrefix(string(role), "permission:"); isPerm {
		perm, ok := auth.PermissionNamed(name)
		if !ok {
			s.peopleBack(w, r, "That is not a permission.")
			return
		}
		bindings[0].Role, bindings[0].Permission = "", perm.Action
		role = auth.Role(perm.Action)
	}
	// A role an app declares is the bindings it stands for, on its own
	// blocks, granted together.
	if name, isApp := strings.CutPrefix(string(role), "app:"); isApp {
		ar, ok := s.appRoleNamed(name)
		if !ok || base.Deny {
			s.peopleBack(w, r, "That role cannot be granted like that: a role an app declares is never a deny.")
			return
		}
		if err := s.changePolicy(func(p *auth.Policy) error { return p.Assign(who, ar, base) }); err != nil {
			s.peopleBack(w, r, err.Error())
			return
		}
		s.audit("access.grant", "/"+who, map[string]string{"role": ar.Name, "resource": "its feature", "by": p.Name})
		s.peopleBack(w, r, fmt.Sprintf("%s is now %s: %s", who, ar.Name, strings.Join(ar.Grants, "; ")))
		return
	}
	// A job is the bindings it stands for, each on its own area.
	if name, isJob := strings.CutPrefix(string(role), "job:"); isJob {
		job, ok := auth.JobNamed(name)
		if !ok || base.Deny {
			s.peopleBack(w, r, "That job cannot be granted like that: a job is never a deny.")
			return
		}
		if job.Ends && expires == 0 {
			s.peopleBack(w, r, "An "+job.Name+"'s access has to end by itself: choose the day in Until.")
			return
		}
		bindings = nil
		for _, jb := range job.Bindings {
			b := base
			b.Role, b.Resource = jb.Role, jb.Resource
			bindings = append(bindings, b)
		}
		role, on = auth.Role(job.Name), "its areas"
	}
	if err := s.changePolicy(func(p *auth.Policy) error {
		for _, b := range bindings {
			if err := p.Grant(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	s.audit("access.grant", "/"+who, map[string]string{
		"role": string(role), "resource": on, "by": p.Name,
	})
	s.peopleBack(w, r, fmt.Sprintf("%s is now %s on %s", who, role, on))
}

// errNoSuchBinding is a revocation that matched nothing.
var errNoSuchBinding = errors.New("no such binding")

// handlePeopleRevoke removes a binding.
func (s *Server) handlePeopleRevoke(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return
	}
	// The list, or the new-person field when the list's blank option was
	// chosen. Named separately rather than overloading one input, so "I meant
	// to pick from the list and typed instead" cannot happen silently.
	who := strings.TrimSpace(r.FormValue("principal"))
	if who == "" {
		who = strings.TrimSpace(r.FormValue("new_principal"))
	}
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
	var n int
	if err := s.changePolicy(func(pol *auth.Policy) error {
		// Asked again of the policy as stored, as the one read at the start
		// of the request may be missing another administrator's removal.
		if who == p.Name && role == auth.RoleAdmin && lastAdminIn(pol, who) {
			return errLastAdmin
		}
		if name, isApp := strings.CutPrefix(string(role), "app:"); isApp {
			n = pol.RevokeAppRole(who, name)
		} else {
			n = pol.RevokeNamed(who, string(role), on)
		}
		if n == 0 {
			return errNoSuchBinding
		}
		return nil
	}); err != nil {
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
	// "credential" and not "token".
	//
	// Append refuses any Detail key containing token, secret, password, key,
	// body or content — and refuses the whole record, not the key. So every
	// revocation made through this screen was dropped: the credential stopped
	// working and the log said nothing about it having been revoked, or by
	// whom, which is exactly the entry an incident review goes looking for.
	// The id of a credential is not a secret; the name of the field was.
	s.audit("token.revoke", "/", map[string]string{
		"credential": id, "by": p.Name, "cascaded": fmt.Sprintf("%d", n),
	})
	msg := "that credential no longer works"
	if n > 1 {
		// The cascade is the point and is worth saying: revoking a token that
		// sessions were minted from has to invalidate them too, or revocation
		// does not revoke.
		msg = "revoked, along with " + countOf(n-1, "session", "sessions") + " minted from it"
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
func (s *Server) lastAdmin(who string) bool { return lastAdminIn(s.Policy, who) }

// lastAdminIn reports whether who is the only principal a policy lets
// administer the whole store.
func lastAdminIn(p *auth.Policy, who string) bool {
	for _, other := range p.Principals() {
		if other == who {
			continue
		}
		if p.Evaluate(other, auth.ActGrant, "/").Allowed {
			return false
		}
	}
	return true
}

// errLastAdmin is removing the last binding that administers the store.
var errLastAdmin = errors.New("that is the last administrator binding, and removing it would leave " +
	"nobody able to administer this store")

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

// save persists the credentials, merged by the host with what is stored,
// so a token revoked elsewhere stays revoked (auth.TokenStore.MergeInto).
//
// Only the credentials. Writing the policy back from here too meant every
// sign-in and every revoked session rewrote who may do what from a copy
// read at the start of the request; a change to the policy goes through
// changePolicy instead. Failing loudly matters more than succeeding
// quietly: a change that is not written disappears at the next restart,
// and the administrator has already been told it worked.
func (s *Server) save() error {
	if s.SaveTokens != nil {
		if err := s.SaveTokens(s.Tokens); err != nil {
			return fmt.Errorf("the change was not saved: %w", err)
		}
	}
	return nil
}

// changePolicy makes an access change to the policy as stored now, and
// takes the result as this server's policy.
func (s *Server) changePolicy(change func(*auth.Policy) error) error {
	if s.UpdatePolicy == nil {
		return change(s.Policy)
	}
	pol, err := s.UpdatePolicy(change)
	if err != nil {
		return err
	}
	s.Policy = pol
	return nil
}

func (s *Server) audit(action, resource string, detail map[string]string) {
	if s.Audit != nil {
		s.Audit(action, resource, detail)
	}
}
