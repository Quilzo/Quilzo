// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
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
	// Failed is whether the outcome was anything but a success.
	Failed bool
	// Tag is how the outcome is drawn (outcomeTag).
	Tag string
}

// outcomeTag is the class an outcome is drawn with.
//
// Denied is kept apart from Failure in the log (audit.Outcome): being refused
// is not the same as breaking, and the reader needs to tell them apart. The
// page marked only a refusal, so a failed backup was drawn in the success
// colour, and an outcome the log never writes, which only an edit can put
// there, was drawn as a success too. Only a success looks like one.
func outcomeTag(o audit.Outcome) string {
	switch o {
	case audit.Success:
		return "tag tag-ok"
	case audit.Denied:
		return "tag tag-bad"
	case audit.Failure:
		return "tag tag-warn"
	}
	return "tag"
}

// shown is a value from the log as the page draws it, with every control
// character in it replaced by a mark that can be seen, as the command line
// shows them.
//
// The template escapes what a browser would read as markup, and nothing
// else. The escape sequences somebody holding a decoy put in the path they
// asked for reached this page byte for byte, and a browser draws them as
// nothing, so the row read as an ordinary path with stray brackets in it and
// kept quiet about what had been sent. A control character in an entry is a
// fact worth seeing. The log, its exports and a filter's own value keep the
// exact bytes; this is only what a person is shown.
func shown(s string) string {
	if !strings.ContainsFunc(s, control) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if control(r) {
			return '�'
		}
		return r
	}, s)
}

// control is a C0 control other than a tab or a line feed, which HTML draws
// as space, or DEL, or a C1 control, which some terminals take as an escape
// of its own.
func control(r rune) bool {
	return r < 0x20 && r != '\t' && r != '\n' || r == 0x7f || r >= 0x80 && r <= 0x9f
}

// handleLogs shows the audit log.
// handles finds a person's handle in the log's text (audit.Pseudonym).
var handles = regexp.MustCompile(`\bp_[0-9a-f]{32}\b`)

// orHandle is resolve, keeping the handle when nobody known has it.
func orHandle(resolve func(string) string) func(string) string {
	return func(h string) string {
		if name := resolve(h); name != "" {
			return name
		}
		return h
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// The audit log holds who did what, across everybody, and is the one
	// record that is worth reading to plan an attack as well as to
	// investigate one. A guarded area: an administrator over the site, or
	// somebody granted the log itself, such as an auditor, reads it.
	if !s.can(w, r, p, auth.ActView, auth.AreaLog) {
		return
	}
	unavailable := func(why string) {
		s.render(w, r, "logs.html", map[string]any{
			"Nav":   "logs",
			"Title": "Audit log", "Principal": p,
			"Unavailable": why,
		})
	}
	if s.AuditIndex == nil && s.LoadAudit == nil {
		unavailable("this server was started without access to the audit log")
		return
	}

	q := r.URL.Query()
	action := strings.TrimSpace(q.Get("action"))
	outcome := strings.TrimSpace(q.Get("outcome"))
	who := strings.TrimSpace(q.Get("who"))
	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}

	// A line edited between the look at the log and the reading of the page
	// is not shown as the line that verified (audit.ErrChanged). The page
	// looks again, and that look sees the edit and says so.
	var data map[string]any
	var err error
	for try := 0; try < 2; try++ {
		if data, err = s.logPage(action, outcome, who, offset); !errors.Is(err, audit.ErrChanged) {
			break
		}
	}
	if err != nil {
		unavailable(err.Error())
		return
	}

	byWriter, keys, refused := false, "", ""
	if s.LogHeads != nil {
		byWriter, keys, refused = s.LogHeads()
	}
	for k, v := range map[string]any{
		"Nav":   "logs",
		"Title": "Audit log", "Principal": p,
		"Action": action, "Outcome": outcome, "Who": who,
		"Separated": s.LogSeparated, "HeadsByWriter": byWriter,
		"HeadsRefused": refused, "HeadKeys": keys,
	} {
		data[k] = v
	}
	s.render(w, r, "logs.html", data)
}

// logPage is one page of the log, newest first, and what the page says about
// the whole of it.
//
// A view costs the page it shows. This read every entry into memory, built
// and resolved a row for each, and then showed two hundred: on a year of
// logging that was seconds and hundreds of megabytes a view, and every new
// pseudonym, which every visitor makes, was one more lookup. The filters now
// look at what the index keeps of each entry; only the rows on the page are
// read in full, built and resolved; and a filter on a name resolves each
// person once.
func (s *Server) logPage(action, outcome, who string, offset int) (map[string]any, error) {
	var snap *audit.Snapshot
	if s.AuditIndex != nil {
		var err error
		if snap, err = s.AuditIndex().Look(); err != nil {
			return nil, err
		}
	} else {
		// A line that is not an entry is among what the check found, not
		// instead of the page. Reading stopped at one, and the page showed
		// that error alone, with no entries and no banner: one crash part
		// way through a write took this screen away for good, and every
		// record after it with it. The index reads past one in the same way.
		var err error
		if snap, err = audit.SnapshotOfRead(s.LoadAudit()); err != nil {
			return nil, err
		}
	}
	// Verified before anything is rendered, and the whole chain, not the
	// page: a list of events with no statement about whether the chain holds
	// invites the reader to trust it, which is the opposite of what the
	// chain is for. The snapshot holds that answer for the whole log.
	report := snap.Report()
	// And against the heads saved beside it (SavedHeads says why). The page
	// names the largest.
	var head *audit.Head
	if s.SavedHeads != nil {
		heads, err := s.SavedHeads()
		if err != nil {
			report.Problems = append(report.Problems, audit.Problem{Reason: "the heads saved beside " +
				"the log cannot be read, so it was not checked against them: " + err.Error()})
			report.Intact = false
		} else if p := snap.AgainstHeads(heads); p != nil {
			report.Problems = append(report.Problems, *p)
			report.Intact = false
		}
		head = audit.LargestHead(heads)
	}

	// Each pseudonym resolved once for the page, through one table where
	// the server offers one (Resolver).
	lookup := s.ResolvePrincipal
	if s.Resolver != nil {
		lookup = s.Resolver()
	}
	var resolve func(string) string
	if lookup != nil {
		resolved := map[string]string{}
		resolve = func(p string) string {
			if name, ok := resolved[p]; ok {
				return name
			}
			name := lookup(p)
			resolved[p] = name
			return name
		}
	}

	// Newest first: an administrator opening this is nearly always asking
	// what just happened, not what happened first.
	//
	// Bounded. A log with a hundred thousand entries would otherwise become
	// a hundred thousand table rows, and the browser is not the place to
	// discover that.
	const pageSize = 200
	var at []int
	total := 0
	for i := snap.Len() - 1; i >= 0; i-- {
		e := snap.Entry(i)
		if action != "" && e.Action != action {
			continue
		}
		if outcome != "" && string(e.Outcome) != outcome {
			continue
		}
		if who != "" {
			name := e.Principal
			if resolve != nil {
				if n := resolve(e.Principal); n != "" {
					name = n
				}
			}
			if !strings.EqualFold(name, who) {
				continue
			}
		}
		if total >= offset && total < offset+pageSize {
			at = append(at, i)
		}
		total++
	}
	if offset > total {
		offset = total
	}
	end := min(offset+pageSize, total)

	events, err := snap.Events(at)
	if err != nil {
		return nil, err
	}
	rows := make([]logRow, 0, len(events))
	for _, e := range events {
		rows = append(rows, rowOf(e, resolve))
	}
	return map[string]any{
		"Rows": rows, "Total": total, "Entries": snap.Len(),
		"Offset": offset, "Next": end, "HasNext": end < total,
		"Intact": report.Intact, "Problems": report.Problems, "Crashed": report.Crashed(), "Head": head,
		"Actions": snap.Actions(),
	}, nil
}

// rowOf prepares one entry for the page, naming the people this store knows
// when resolve is set.
func rowOf(e audit.Event, resolve func(string) string) logRow {
	row := logRow{
		Seq: e.Seq, At: e.At, Action: e.Action, Resource: e.Resource,
		Outcome: string(e.Outcome), Kind: string(e.Kind),
		Verified: e.Verified, Detail: e.Detail,
		Who: e.Principal, Failed: e.Outcome != audit.Success,
		Tag: outcomeTag(e.Outcome),
	}
	if resolve == nil {
		return row
	}
	if name := resolve(e.Principal); name != "" {
		row.Who, row.Resolved = name, true
	}
	// Details naming a person are pseudonymised like the principal, and
	// named here the same way: known people by name, anybody else left
	// opaque. A sentence or a resource that names somebody the record names
	// carries their handle too, and is named the same way.
	var named map[string]string
	for k, v := range e.Detail {
		var name string
		if audit.IdentityKeys[k] {
			name = resolve(v)
		} else if strings.Contains(v, "p_") {
			if name = handles.ReplaceAllStringFunc(v, orHandle(resolve)); name == v {
				name = ""
			}
		}
		if name != "" {
			if named == nil {
				named = make(map[string]string, len(e.Detail))
				for k2, v2 := range e.Detail {
					named[k2] = v2
				}
			}
			named[k] = name
		}
	}
	if strings.Contains(row.Resource, "p_") {
		row.Resource = handles.ReplaceAllStringFunc(row.Resource, orHandle(resolve))
	}
	if named != nil {
		row.Detail = named
	}
	return row
}

// The navigation used to be movable between the top bar and the side, with a
// POST handler, a cookie, a configuration key and a button in the header.
//
// It is at the side, and only at the side. The two arrangements meant the
// navigation was rendered twice into every response so that CSS could hide
// one, which is a duplicate set of links in the document whose absence from
// the accessibility tree depended on a display rule staying right. One
// arrangement removes the second copy, the setting that chose between them,
// and the button that set the setting — and the group headings, which the top
// arrangement had to hide for want of room, are now always drawn.
//
// A person's own ordering of the destinations survives all of this: that is
// NavOrderCookie in nav.go, which is a different preference and still theirs.
