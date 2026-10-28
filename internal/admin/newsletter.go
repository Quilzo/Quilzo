// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/newsletter"
)

// Newsletter: who asked for the site's newsletter and said yes, and the
// issues sent to them (internal/newsletter). The addresses are read here
// and nowhere else: the public site writes them and cannot read them back.

// NewsletterHooks are what the screen asks of the list.
type NewsletterHooks struct {
	// Problems is what stops sign-ups or sending, as a person fixes it.
	Problems func() []string
	Counts   func() (newsletter.Counts, error)
	// List is every address, the newest first.
	List   func() ([]newsletter.Subscriber, error)
	Issues func() ([]newsletter.Issue, error)
	// Pages is the published pages an issue can be made from.
	Pages func() ([]string, error)
	// Add asks an address, with the same link a sign-up gets.
	Add func(addr string, by Actor) error
	// Remove takes an address off, and keeps it from being imported back.
	Remove func(id string, by Actor) (bool, error)
	// Import reads a list exported elsewhere; agreed says where its people
	// said yes.
	Import func(r io.Reader, agreed string, by Actor) (newsletter.Imported, error)
	// Export writes the confirmed list as a file other platforms import.
	Export func(w io.Writer, by Actor) (int, error)
	// Test sends one copy of an issue to one address.
	Test func(page, subject, to string, by Actor) error
	// Send starts an issue, new or proposed by an agent, in the background.
	Send func(page, subject, proposed string, by Actor) (newsletter.Issue, error)
	// Continue carries on with an issue that stopped; Stop stops one.
	Continue func(id string, by Actor) error
	Stop     func(id string, by Actor) error
	// Dismiss sets aside an issue an agent proposed.
	Dismiss func(id string, by Actor) error
}

// subscriberRow is one address as the screen lists it.
type subscriberRow struct {
	ID, Email, Name, Since, Source string
	Waiting                        bool
}

// issueRow is one issue as the screen lists it.
type issueRow struct {
	newsletter.Issue
	When string
}

// newsletterShown is how many addresses the screen lists; the export has
// them all.
const newsletterShown = 300

func (s *Server) handleNewsletter(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	// Addresses: never kept by a browser.
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Title": "Newsletter", "Nav": "newsletter", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Newsletter == nil {
		data["Unavailable"] = "This build was started without the newsletter wired in."
		s.render(w, r, "newsletter.html", data)
		return
	}
	n := s.Newsletter
	data["Problems"] = n.Problems()
	data["CanSend"] = s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed
	counts, err := n.Counts()
	if err != nil {
		data["Error"] = err.Error()
	}
	data["Counts"] = counts
	if pages, err := n.Pages(); err == nil {
		sort.Strings(pages)
		data["Pages"] = pages
	}
	data["Pick"] = r.URL.Query().Get("page")
	issues, err := n.Issues()
	if err != nil {
		data["Error"] = err.Error()
	}
	var proposed, sent []issueRow
	for _, is := range issues {
		row := issueRow{Issue: is}
		switch is.State {
		case newsletter.Proposed:
			row.When = is.Proposed.Local().Format("2 January 15:04")
			proposed = append(proposed, row)
		case newsletter.Dismissed:
		default:
			row.When = is.Started.Local().Format("2 January 2006, 15:04")
			sent = append(sent, row)
		}
	}
	data["Proposed"], data["Sent"] = proposed, sent
	list, err := n.List()
	if err != nil {
		data["Error"] = err.Error()
	}
	var rows []subscriberRow
	for i, sub := range list {
		if i == newsletterShown {
			data["More"] = len(list) - newsletterShown
			break
		}
		rows = append(rows, subscriberRow{ID: sub.ID, Email: sub.Email, Name: sub.Name,
			Since: sub.At.Local().Format("2 January 2006"), Source: sub.Source, Waiting: sub.Confirmed.IsZero()})
	}
	data["Rows"] = rows
	s.render(w, r, "newsletter.html", data)
}

// handleNewsletterExport is the confirmed list as CSV.
func (s *Server) handleNewsletterExport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Newsletter == nil {
		http.NotFound(w, r)
		return
	}
	var buf bytes.Buffer
	if _, err := s.Newsletter.Export(&buf, p.actor()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="subscribers.csv"`)
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// handleNewsletterAct tests and sends issues, stops and dismisses them,
// and adds, removes and imports addresses.
func (s *Server) handleNewsletterAct(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	if s.Newsletter == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "that could not be read", http.StatusBadRequest)
			return
		}
	}
	switch do := r.FormValue("do"); do {
	case "test", "send":
		s.newsletterIssue(w, r, p, do)
	case "add", "remove", "continue", "stop", "dismiss", "import":
		s.newsletterList(w, r, p, do)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// newsletterBack returns to the screen saying what happened; extra is a
// query key and value to keep, such as the page picked.
func newsletterBack(w http.ResponseWriter, r *http.Request, msg string, err error, extra ...string) {
	v := url.Values{"m": {msg}}
	if err != nil {
		v = url.Values{"e": {err.Error()}}
	}
	if len(extra) == 2 {
		v.Set(extra[0], extra[1])
	}
	http.Redirect(w, r, "/newsletter?"+v.Encode(), http.StatusSeeOther)
}

// newsletterIssue sends a test of a page, or sends it. A test is the
// page's, for whoever may edit it; sending it is the page's to publish,
// and the hook asks as well whether they may decide what the whole list
// is sent, which publishing the whole site decides.
func (s *Server) newsletterIssue(w http.ResponseWriter, r *http.Request, p principal, do string) {
	n := s.Newsletter
	page, subject := strings.TrimSpace(r.FormValue("page")), strings.TrimSpace(r.FormValue("subject"))
	if do == "test" {
		if !s.canPage(w, r, p, auth.ActEditDraft, page) {
			return
		}
		to := strings.TrimSpace(r.FormValue("to"))
		if to == "" {
			newsletterBack(w, r, "", errors.New("say which address to send the test to"), "page", page)
			return
		}
		err := n.Test(page, subject, to, p.actor())
		newsletterBack(w, r, "A test is on its way to "+to+". Read it before sending it to everybody.", err,
			"page", page)
		return
	}
	if !s.canPage(w, r, p, auth.ActPublish, page) {
		return
	}
	if r.FormValue("sure") != "1" {
		newsletterBack(w, r, "", errors.New("tick the box to say you have read a test: an issue cannot be taken back"),
			"page", page)
		return
	}
	is, err := n.Send(page, subject, r.FormValue("issue"), p.actor())
	newsletterBack(w, r, fmt.Sprintf("Sending %q to %d address(es). This page shows how far it has got.",
		is.Subject, s.newsletterCount()), err)
}

// newsletterList keeps the list: asking and removing addresses is for
// whoever reads what forms collect; importing, and carrying on, stopping or
// dismissing an issue, decide who is sent what, which is publishing's.
func (s *Server) newsletterList(w http.ResponseWriter, r *http.Request, p principal, do string) {
	n := s.Newsletter
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	switch do {
	case "add":
		err := n.Add(strings.TrimSpace(r.FormValue("email")), p.actor())
		newsletterBack(w, r, "Asked. The address joins when it says yes from the link mailed to it.", err)
		return
	case "remove":
		was, err := n.Remove(r.FormValue("id"), p.actor())
		msg := "Removed and deleted. It is kept from being imported back."
		if !was {
			msg = "It was not on the list."
		}
		newsletterBack(w, r, msg, err)
		return
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	switch do {
	case "continue":
		newsletterBack(w, r, "Carrying on where it stopped.", n.Continue(r.FormValue("issue"), p.actor()))
	case "stop":
		newsletterBack(w, r, "Stopping. Carry on from where it stopped whenever you like.",
			n.Stop(r.FormValue("issue"), p.actor()))
	case "dismiss":
		newsletterBack(w, r, "Dismissed.", n.Dismiss(r.FormValue("issue"), p.actor()))
	case "import":
		f, _, err := r.FormFile("file")
		if err != nil {
			newsletterBack(w, r, "", errors.New("choose a CSV file exported from another newsletter service"))
			return
		}
		defer f.Close()
		got, err := n.Import(f, r.FormValue("agreed"), p.actor())
		newsletterBack(w, r, fmt.Sprintf("Added %d; %d already here; %d kept as having left elsewhere, so never "+
			"sent to; %d skipped as never confirmed or not an address.", got.Added, got.Already, got.Left,
			got.Skipped+got.Bad), err)
	}
}

func (s *Server) newsletterCount() int {
	c, _ := s.Newsletter.Counts()
	return c.Subscribed
}
