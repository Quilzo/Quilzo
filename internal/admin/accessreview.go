// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/accessreview"
	"github.com/quilzo/quilzo/internal/auth"
)

// The review of who has access, on the People screen.
//
// A section of People rather than a screen of its own, because People is
// where an administrator already looks at who holds what, and a review
// somewhere else is a second list that disagrees with the first the day a
// grant is made. The work is the command line's (cmd/quilzo, the same four
// functions as quilzo access review): this package shows the review and
// passes on what a person pressed, as the session they pressed it in.

// AccessReview is what the host gives the screen.
type AccessReview struct {
	// Current is the review still being decided, or nil.
	Current func() (*accessreview.Review, error)
	// Last is when a review last closed, if one ever has.
	Last func() (time.Time, bool, error)
	// Every is how often one is due.
	Every func() time.Duration
	// Start takes the snapshot, Decide gives a verdict and applies a
	// revoke at once, and Close ends the review and writes its evidence,
	// each as the session it is handed and each refused with the reason.
	Start  func(by Actor) (*accessreview.Review, error)
	Decide func(by Actor, item string, v accessreview.Verdict, why string) (accessreview.Item, error)
	Close  func(by Actor) (accessreview.Summary, error)
}

// reviewRow is one item as the screen shows it.
type reviewRow struct {
	accessreview.Item
	What     string
	Facts    string
	Decision *accessreview.Decision
	// Own is the signed-in person's own access, which they may not decide.
	Own bool
}

// reviewView is the section: the open review, or when the last one closed.
type reviewView struct {
	Unavailable string
	Open        *accessreview.Review
	Rows        []reviewRow
	Undecided   int
	Last        string
	Every       string
	Due         bool
}

// reviewSection is the Review section for the person signed in.
func (s *Server) reviewSection(p principal, now time.Time) *reviewView {
	if s.AccessReview == nil {
		return nil
	}
	v := &reviewView{}
	every := s.AccessReview.Every()
	v.Every = fmt.Sprintf("%d days", int(every.Hours()/24))
	last, ok, err := s.AccessReview.Last()
	if err != nil {
		v.Unavailable = err.Error()
		return v
	}
	if ok {
		v.Last = last.UTC().Format("2 Jan 2006")
		v.Due = now.Sub(last) > every
	}
	open, err := s.AccessReview.Current()
	if err != nil {
		v.Unavailable = err.Error()
		return v
	}
	if open == nil {
		return v
	}
	v.Open, v.Undecided = open, open.Undecided()
	for _, it := range open.Items {
		row := reviewRow{Item: it, What: it.Describe(), Facts: reviewFacts(it), Own: it.Holder(p.Name)}
		if d, ok := open.Decided(it.ID); ok {
			row.Decision = &d
		}
		v.Rows = append(v.Rows, row)
	}
	return v
}

func reviewFacts(it accessreview.Item) string {
	var parts []string
	how := "granted " + it.Via
	if it.GrantedBy != "" {
		how += " by " + it.GrantedBy
	}
	if !it.GrantedAt.IsZero() {
		how += " on " + it.GrantedAt.Format("2 Jan 2006")
	}
	parts = append(parts, how)
	if !it.Expires.IsZero() {
		parts = append(parts, "until "+it.Expires.Format("2 Jan 2006"))
	}
	if it.LastActive.IsZero() {
		parts = append(parts, "no activity recorded")
	} else {
		parts = append(parts, "last active "+it.LastActive.Format("2 Jan 2006"))
	}
	if len(it.Members) > 0 {
		parts = append(parts, countOf(len(it.Members), "member", "members"))
	}
	return strings.Join(parts, "; ")
}

// reviewPost is the shared preamble for the three review buttons: an
// administrator of the whole store, signed in as a person. A credential
// sent by a program is refused whatever it holds, since a service token
// reviews nothing.
func (s *Server) reviewPost(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return principal{}, false
	}
	if s.AccessReview == nil {
		s.peopleBack(w, r, "this server was started without access reviews")
		return principal{}, false
	}
	if !p.Session {
		http.Error(w, "an access review is decided by a person signed in, not by a program's credential",
			http.StatusForbidden)
		return principal{}, false
	}
	return p, true
}

func (s *Server) handleReviewStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.reviewPost(w, r)
	if !ok {
		return
	}
	rev, err := s.AccessReview.Start(p.actor())
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	s.peopleBack(w, r, fmt.Sprintf("review %s started: %s to decide", rev.ID,
		countOf(len(rev.Items), "item", "items")))
}

func (s *Server) handleReviewDecide(w http.ResponseWriter, r *http.Request) {
	p, ok := s.reviewPost(w, r)
	if !ok {
		return
	}
	it, err := s.AccessReview.Decide(p.actor(), strings.TrimSpace(r.FormValue("item")),
		accessreview.Verdict(r.FormValue("verdict")), r.FormValue("why"))
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	s.peopleBack(w, r, fmt.Sprintf("item %s: %s", it.ID, r.FormValue("verdict")))
}

func (s *Server) handleReviewClose(w http.ResponseWriter, r *http.Request) {
	p, ok := s.reviewPost(w, r)
	if !ok {
		return
	}
	sum, err := s.AccessReview.Close(p.actor())
	if err != nil {
		s.peopleBack(w, r, err.Error())
		return
	}
	msg := fmt.Sprintf("the review is closed: %d kept, %d revoked", sum.Kept, sum.Revoked)
	if n := len(sum.NotReviewed); n > 0 {
		msg += fmt.Sprintf("; %s granted since it started, not reviewed by it", countOf(n, "grant", "grants"))
	}
	if sum.Alone {
		msg += "; done alone, as the only administrator, and the record says so"
	}
	s.peopleBack(w, r, msg)
}
