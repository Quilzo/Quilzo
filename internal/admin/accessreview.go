// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
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
	// CloseHint is what closing waits for, when anything is undecided:
	// the signed-in person's own items wait for another administrator,
	// unless there is none, when the review closes without them.
	CloseHint string
	// Alone is the signed-in person being the only administrator, whose
	// own items nobody else can decide and the review closes without.
	Alone     bool
	Last      string
	Next      string
	Every     string
	Due       bool
	CanDecide bool
	// Message and Error are what the last button pressed came back with,
	// and At the item it was pressed on: shown where it was pressed, on
	// the card or at the top of the section, not at the top of the page.
	Message, Error, At string
}

// reviewSection is the Review section for the person signed in.
func (s *Server) reviewSection(r *http.Request, p principal, now time.Time) *reviewView {
	if s.AccessReview == nil {
		return nil
	}
	q := r.URL.Query()
	v := &reviewView{CanDecide: canReview(p), Message: q.Get("rm"), Error: q.Get("re"), At: q.Get("ri")}
	every := s.AccessReview.Every()
	v.Every = fmt.Sprintf("%d days", int(every.Hours()/24))
	last, ok, err := s.AccessReview.Last()
	if err != nil {
		v.Unavailable = err.Error()
		return v
	}
	if ok {
		v.Last = last.UTC().Format("2 Jan 2006")
		v.Next = last.Add(every).UTC().Format("2 Jan 2006")
		v.Due = now.Sub(last) > every
	}
	open, err := s.AccessReview.Current()
	if err != nil {
		v.Unavailable = err.Error()
		return v
	}
	if open == nil {
		// A decision that came back about a card that is not there, for a
		// review somebody else closed meanwhile, says so at the top of the
		// section rather than nowhere.
		v.At = ""
		return v
	}
	v.Open, v.Undecided = open, open.Undecided()
	var own []string
	for _, it := range open.Items {
		row := reviewRow{Item: it, What: it.Describe(), Facts: reviewFacts(it), Own: it.Holder(p.Name)}
		if d, ok := open.Decided(it.ID); ok {
			row.Decision = &d
		} else if row.Own {
			own = append(own, it.ID)
		}
		v.Rows = append(v.Rows, row)
	}
	if _, ok := open.Item(v.At); !ok {
		v.At = ""
	}
	v.Alone = lastAdminIn(s.Policy, p.Name)
	v.CloseHint = closeHint(v.Undecided, own, v.Alone)
	return v
}

// closeHint says what closing a review waits for, beside the button.
//
// The button was there and said nothing, and an administrator who had
// decided all they could pressed it to be told that items 1 and 3 were
// undecided: their own, which they may not decide and somebody else must.
func closeHint(undecided int, own []string, alone bool) string {
	if undecided == 0 {
		return ""
	}
	var ids string
	switch n := len(own); n {
	case 0:
		return "Closing waits until every item is decided."
	case 1:
		ids = "item " + own[0]
	default:
		ids = "items " + strings.Join(own[:n-1], ", ") + " and " + own[n-1]
	}
	if alone {
		hint := "You are the only administrator, so the review closes without " + ids +
			", your own, and the record says so"
		if undecided > len(own) {
			hint += "; closing waits until every other item is decided"
		}
		return hint + "."
	}
	return "Closing waits until every item is decided; " + ids + map[bool]string{true: " is", false: " are"}[len(own) == 1] +
		" your own, for another administrator to decide."
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

// canReview is whether this session may press the review's buttons: a
// person's sign-in with two factors (reviewPost says why). The section
// asks it as well, so a session that may not is told how to instead of
// being offered buttons that answer with a bare refusal.
func canReview(p principal) bool { return p.Session && p.Level >= 2 }

// reviewPost is the shared preamble for the three review buttons: an
// administrator of the whole store, signed in as a person with two
// factors. A credential sent by a program is refused whatever it holds,
// since a service token reviews nothing.
//
// Two factors, because nothing else here tells a person from a program.
// authenticate refuses a one-factor credential once two factors are
// compulsory, and in the grace before then it let one through: a program's
// token sent in a header as a session exchanged from it, or pasted into the
// sign-in form and held in a cookie as a browser holds one, counted as a
// person signed in, and the program started, decided and closed reviews in
// somebody's name. The grace is for people to enrol a second factor, so it
// is not extended to deciding who keeps access; the command line, with the
// person's own token, is the other way in.
func (s *Server) reviewPost(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.postFrom(w, r, auth.ActGrant)
	if !ok {
		return principal{}, false
	}
	if s.AccessReview == nil {
		s.peopleBack(w, r, "this server was started without access reviews")
		return principal{}, false
	}
	if !canReview(p) {
		http.Error(w, reviewNeedsTwoFactors, http.StatusForbidden)
		return principal{}, false
	}
	return p, true
}

// reviewNeedsTwoFactors is why a session may not decide, and what to do.
const reviewNeedsTwoFactors = "an access review is decided by a person signed in with two factors, not by a " +
	"program's credential: sign in with your passkey, or decide with quilzo access review and your own token"

// reviewBack returns to the review with what a button came to: to the card
// it was pressed on (item), or to the top of the section, with the message
// shown there as a success or as a refusal.
//
// It went back to the top of People, where every message on the screen is
// shown alike: an administrator forty cards down who pressed Keep on a
// privileged item without a reason landed above the grant form, with the
// refusal in the same grey as a success, and scrolled back to find which
// card it was about.
func (s *Server) reviewBack(w http.ResponseWriter, r *http.Request, item, msg string, failed bool) {
	q := url.Values{}
	if failed {
		q.Set("re", msg)
	} else {
		q.Set("rm", msg)
	}
	anchor := "#review"
	if item != "" {
		q.Set("ri", item)
		anchor = "#item-" + url.PathEscape(item)
	}
	http.Redirect(w, r, "/people?"+q.Encode()+anchor, http.StatusSeeOther)
}

func (s *Server) handleReviewStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.reviewPost(w, r)
	if !ok {
		return
	}
	rev, err := s.AccessReview.Start(p.actor())
	if err != nil {
		s.reviewBack(w, r, "", err.Error(), true)
		return
	}
	s.reviewBack(w, r, "", fmt.Sprintf("review %s started: %s to decide", rev.ID,
		countOf(len(rev.Items), "item", "items")), false)
}

func (s *Server) handleReviewDecide(w http.ResponseWriter, r *http.Request) {
	p, ok := s.reviewPost(w, r)
	if !ok {
		return
	}
	item := strings.TrimSpace(r.FormValue("item"))
	v := accessreview.Verdict(r.FormValue("verdict"))
	it, err := s.AccessReview.Decide(p.actor(), item, v, r.FormValue("why"))
	if err != nil {
		s.reviewBack(w, r, item, err.Error(), true)
		return
	}
	// The command line's words: item 4: revoke, kit is author on /blog.
	msg := fmt.Sprintf("item %s: %s, %s", it.ID, v, it.Describe())
	if v == accessreview.Revoke {
		msg += "; " + it.Revoked()
	}
	s.reviewBack(w, r, it.ID, msg, false)
}

func (s *Server) handleReviewClose(w http.ResponseWriter, r *http.Request) {
	p, ok := s.reviewPost(w, r)
	if !ok {
		return
	}
	sum, err := s.AccessReview.Close(p.actor())
	if err != nil {
		s.reviewBack(w, r, "", err.Error(), true)
		return
	}
	msg := fmt.Sprintf("the review is closed: %s, %d kept, %d revoked", countOf(sum.Items, "item", "items"),
		sum.Kept, sum.Revoked)
	if sum.Gone > 0 {
		msg += fmt.Sprintf("; %s taken away some other way since it started, and counted as gone",
			countOf(sum.Gone, "item", "items"))
	}
	if n := len(sum.NotReviewed); n > 0 {
		msg += fmt.Sprintf("; %s made since it started, not reviewed by it", countOf(n, "grant", "grants"))
	}
	if sum.Alone {
		msg += fmt.Sprintf("; done alone, as the only administrator, with %s of your own unreviewed, and the "+
			"record says so", countOf(sum.Own, "item", "items"))
	}
	if sum.Unreviewable > 0 {
		msg += fmt.Sprintf("; %s held by every administrator went unreviewed, and the record says so",
			countOf(sum.Unreviewable, "item", "items"))
	}
	s.reviewBack(w, r, "", msg+". Closing it is evidence for the control "+accessreview.ControlID+
		" (quilzo assurance show).", false)
}
