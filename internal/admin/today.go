// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/site"
)

// Today: the first screen after signing in.
//
// What somebody needs first is what is waiting for them, and then what
// happened in the parts of the store they work in. So the screen is a fixed
// frame in that order, the same every day, and nothing on it is generated:
// a page a model lays out at sign-in is slow, different each time, hard to
// read with a screen reader, and a place for what the model read to speak.
// Chat as the first screen was tried at scale and people asked for their
// tools back; people find their way faster in a screen they can learn than
// in one that rearranges itself, and that they arrange themselves when they
// want to.
//
// Each part is shown by the same grant check as the menu, so nobody sees a
// count for a screen they cannot open, and every figure is a link to the
// records it counts. Somebody who would rather start where they always did
// chooses Pages, and Today stays in the menu.

// StartCookie holds where somebody starts after signing in. Absent means
// Today.
const StartCookie = "quilzo_start"

// startPath is where a sign-in lands.
func startPath(r *http.Request) string {
	if c, err := r.Cookie(StartCookie); err == nil && c.Value == "pages" {
		return "/"
	}
	return "/today"
}

// todayWaitingShown is how many waiting items Today lists before pointing
// at Approvals for the rest.
const todayWaitingShown = 7

// todayLine is one figure and where its records are.
type todayLine struct {
	N          int
	Text, Href string
	// Warn marks a figure that is about something going wrong.
	Warn bool
}

func (s *Server) handleToday(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()

	waiting := s.waitingItems(p, now)
	slices.SortStableFunc(waiting, func(a, b approvalItem) int {
		if a.Expired != b.Expired {
			// One asked too long ago to agree to is cleared first, so it
			// stops holding its run.
			if a.Expired {
				return -1
			}
			return 1
		}
		if d := slices.Index(commitsOrder, a.Commits) - slices.Index(commitsOrder, b.Commits); d != 0 {
			return d
		}
		return a.Since.Compare(b.Since)
	})
	all, total := waiting, len(waiting)
	if len(waiting) > todayWaitingShown {
		waiting = waiting[:todayWaitingShown]
	}

	visible := map[string]bool{}
	for _, d := range visibleTo(s, p) {
		visible[d.Key] = true
	}
	var lines []todayLine
	add := func(n int, one, many, href string, warn bool) {
		if n == 0 {
			return
		}
		text := many
		if n == 1 {
			text = one
		}
		lines = append(lines, todayLine{N: n, Text: text, Href: href, Warn: warn})
	}
	if visible["review"] {
		add(s.unpublishedFor(p), "Page changed in the draft and not published", "Pages changed in the draft and not published", "/review", false)
	}
	if visible["agents"] && s.Agents != nil && s.Agents.Runs != nil {
		if runs, err := s.Agents.Runs(""); err == nil {
			done, wrong, going := 0, 0, 0
			for _, rec := range runs {
				if rec.Eval != "" || now.Sub(rec.Started) > 24*time.Hour {
					continue
				}
				switch rec.OutcomeAt(now) {
				case "complete":
					done++
				case "failed", "refused", "interrupted", "stopped":
					wrong++
				case agent.Running:
					going++
				}
			}
			add(going, "Agent run going now", "Agent runs going now", "/agents", false)
			add(done, "Agent run finished in the last day", "Agent runs finished in the last day", "/agents", false)
			add(wrong, "Agent run failed, was refused or stopped in the last day", "Agent runs failed, were refused or stopped in the last day", "/agents", true)
		}
	}
	if visible["inbox"] && s.Inbox != nil && s.Inbox.List != nil {
		if all, err := s.Inbox.List(); err == nil {
			n := 0
			for _, c := range all {
				if c.Waiting() {
					n++
				}
			}
			add(n, "Visitor waiting for a reply", "Visitors waiting for a reply", "/inbox", false)
		}
	}
	// What Quilzo is doing to protect itself, and who has to prove it is
	// them before they can do anything.
	if visible["shield"] && s.ShieldAdmin != nil && s.ShieldAdmin.Root != "" {
		if st, err := shield.Load(s.ShieldAdmin.Root); err == nil {
			add(len(st.Active(now)), "Protection in force, put on by the shield or a person",
				"Protections in force, put on by the shield or people", "/security/shield", true)
		}
	}
	if visible["signins"] && s.Tokens != nil {
		n := 0
		for _, t := range s.Tokens.Snapshot() {
			if t.StepUp != "" && !t.Revoked && (t.ExpiresAt == 0 || now.Unix() < t.ExpiresAt) {
				n++
			}
		}
		add(n, "Sign-in waiting to confirm it is its person", "Sign-ins waiting to confirm they are their person", "/security/signins", true)
	}

	var answer *shownView
	if a := s.lastAsked(p); a != nil {
		v := s.drawView(p, "", a.Title, a.Question, a.Cards, now)
		v.Notes, v.Problem = a.Notes, a.Problem
		answer = &v
	}
	var views []shownView
	canKeep := s.Ask != nil && s.Ask.Load != nil && s.Ask.Save != nil
	if canKeep {
		kept, _ := s.Ask.Load(p.Name)
		for _, v := range kept {
			views = append(views, s.drawView(p, v.ID, v.Title, v.Question, v.Cards, now))
		}
	}

	s.render(w, r, "today.html", map[string]any{
		"Message": r.URL.Query().Get("m"),
		"CanAsk":  s.askAllowed(p), "Answer": answer, "Views": views, "CanKeep": canKeep,
		"Title": "Today", "Nav": "today", "Principal": p,
		"Waiting": waiting, "WaitingTotal": total, "MoreWaiting": total - len(waiting),
		"Brief": s.briefFor(p, briefFacts(all, lines, now), now),
		"Lines": lines, "StartsHere": startPath(r) == "/today",
		"Date": now.Format("Monday 2 January"),
	})
}

// unpublishedFor counts the pages changed in the draft and not yet live
// that a person may read.
func (s *Server) unpublishedFor(p principal) int {
	if s.Store == nil {
		return 0
	}
	draft, live := s.Store.GetRef(site.RefDraft), s.Store.GetRef(site.RefLive)
	if draft == "" || draft == live {
		return 0
	}
	changes, err := site.Diff(s.Store, live, draft)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range changes {
		if s.mayUse(p, auth.ActView, pageResource(c.Path)) {
			n++
		}
	}
	return n
}

// handleTodayStart records where somebody starts after signing in.
func (s *Server) handleTodayStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	switch to := r.FormValue("to"); to {
	case "pages":
		http.SetCookie(w, &http.Cookie{
			Name: StartCookie, Value: "pages", Path: "/",
			MaxAge: 365 * 24 * 3600, HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || s.behindTLSProxy(),
		})
	case "today":
		s.clearCookie(w, r, StartCookie)
	default:
		http.Error(w, fmt.Sprintf("%q is not a place to start", to), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/today", http.StatusSeeOther)
}
