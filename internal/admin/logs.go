package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/auth"
)

// The audit log, in the admin, read-only and unable to be anything else.
//
// It was reachable only from the command line, which is a gap: the person who
// most needs to see who did what is the administrator, and telling them to open
// a terminal is telling them not to look.
//
// Read-only is not a policy decision that could have gone the other way. This
// process does not hold the log — after the writer was separated out it
// deliberately cannot open it for writing — so there is no edit path to leave
// out. What would otherwise be a button that is missing is a capability that
// does not exist, and the page says so, because an administrator who believes
// they could delete an entry will eventually be asked whether they did.
//
// Two things this page has to get right and most log viewers do not.
//
// **It shows whether the log verifies**, at the top, before any entries. A list
// of events with no statement about whether the chain is intact invites the
// reader to trust what they are seeing, which is exactly backwards: the whole
// apparatus underneath — the hash chain, the Merkle tree, the anchoring —
// exists so that trust is unnecessary, and a viewer that does not surface the
// result throws that away.
//
// **It resolves pseudonyms honestly.** Principals are stored HMAC'd, so the log
// can be exported to a SIEM without carrying identities. That cannot be
// reversed. What can be done is the forward direction: compute the pseudonym
// for each principal this store knows and match. So known people are named and
// unknown ones stay opaque — which is the correct outcome rather than a
// limitation. An entry attributed to somebody the policy has never heard of is
// itself worth seeing.

// logRow is one entry, prepared for display.
type logRow struct {
	Seq      int64
	At       string
	Action   string
	Resource string
	Outcome  string
	Kind     string
	Verified bool
	// Who is the resolved principal when this store can name them, and the
	// pseudonym when it cannot.
	Who      string
	Resolved bool
	Detail   map[string]string
	Failed   bool
}

// handleLogs shows the audit log.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Reading the audit log is an administrative act: it holds who did what,
	// across everybody, and is the one record that is worth reading to plan an
	// attack as well as to investigate one.
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.LoadAudit == nil {
		s.render(w, r, "logs.html", map[string]any{
			"Title": "Audit log", "Principal": p,
			"Unavailable": "this server was started without access to the " +
				"audit log",
		})
		return
	}

	events, err := s.LoadAudit()
	if err != nil {
		s.render(w, r, "logs.html", map[string]any{
			"Title": "Audit log", "Principal": p,
			"Unavailable": err.Error(),
		})
		return
	}

	// Verified before anything is rendered. A list of events with no statement
	// about whether the chain holds invites the reader to trust it, which is
	// the opposite of what the chain is for.
	intact, problems := audit.Verify(events)

	action := strings.TrimSpace(r.URL.Query().Get("action"))
	outcome := strings.TrimSpace(r.URL.Query().Get("outcome"))
	who := strings.TrimSpace(r.URL.Query().Get("who"))

	// Newest first: an administrator opening this is nearly always asking what
	// just happened, not what happened first.
	rows := make([]logRow, 0, len(events))
	actions := map[string]int{}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		actions[e.Action]++

		if action != "" && e.Action != action {
			continue
		}
		if outcome != "" && string(e.Outcome) != outcome {
			continue
		}

		row := logRow{
			Seq: e.Seq, At: e.At, Action: e.Action, Resource: e.Resource,
			Outcome: string(e.Outcome), Kind: string(e.Kind),
			Verified: e.Verified, Detail: e.Detail,
			Who: e.Principal, Failed: e.Outcome == audit.Denied,
		}
		if s.ResolvePrincipal != nil {
			if name := s.ResolvePrincipal(e.Principal); name != "" {
				row.Who, row.Resolved = name, true
			}
		}
		if who != "" && !strings.EqualFold(row.Who, who) {
			continue
		}
		rows = append(rows, row)
	}

	// Bounded. A log with a hundred thousand entries would otherwise become a
	// hundred thousand table rows, and the browser is not the place to
	// discover that.
	const pageSize = 200
	total := len(rows)
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	if offset > total {
		offset = total
	}
	end := offset + pageSize
	if end > total {
		end = total
	}
	page := rows[offset:end]

	var names []string
	for a := range actions {
		names = append(names, a)
	}
	sortStrings(names)

	s.render(w, r, "logs.html", map[string]any{
		"Title": "Audit log", "Principal": p,
		"Rows": page, "Total": total, "Entries": len(events),
		"Offset": offset, "Next": end, "HasNext": end < total,
		"Intact": intact, "Problems": problems,
		"Actions": names, "Action": action, "Outcome": outcome, "Who": who,
		"Separated": s.LogSeparated,
	})
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// handleNav flips the navigation between the top bar and the side.
//
// A cookie rather than a stored setting. Where the menu sits is a preference
// about a screen — its width, and how many sections that person keeps open —
// not a property of the content store, and making everybody share one value
// turns a preference into an argument. The configured value is the default for
// anybody who has not chosen.
func (s *Server) handleNav(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Authenticated, because it sets a cookie on this origin and there is no
	// reason for an unauthenticated request to be doing that.
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	to := r.FormValue("to")
	if to != "top" && to != "left" {
		http.Error(w, "nav must be top or left", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "scrivet_nav", Value: to, Path: "/",
		MaxAge: 365 * 24 * 3600, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
	// Back where they were. Referer is only used to return to a path on this
	// same server — an open redirect through a preference toggle would be an
	// embarrassing way to acquire one.
	back := "/"
	if ref := r.Referer(); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host == r.Host &&
			strings.HasPrefix(u.Path, "/") {
			back = u.Path
		}
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// navFor resolves the position for one request: the person's choice, else the
// store's configured default, else top.
func (s *Server) navFor(r *http.Request) string {
	if c, err := r.Cookie("scrivet_nav"); err == nil {
		if c.Value == "top" || c.Value == "left" {
			return c.Value
		}
	}
	if s.NavPosition == "left" {
		return "left"
	}
	return "top"
}
