// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"errors"
	"fmt"
	"github.com/quilzo/quilzo/internal/clientip"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/throttle"
)

// The one thing this server is allowed to write.
//
// # Why this is worth being careful about
//
// The argument for running the public site as a separate process has always
// been that the part exposed to the internet cannot write anything. A form
// breaks that, and pretending otherwise would be worse than the breach — so
// the capability is made as narrow as it can be and the narrowness is stated:
//
//	It writes to the submission store and nothing else. It has no handle on
//	the content store, cannot reach a ref, and cannot cause a commit.
//
//	It appends. There is no path here that reads, edits or removes a
//	submission, so an attacker who owns this process can add rubbish and
//	cannot read what anybody else sent.
//
//	It writes only declared fields of declared forms, checked against their
//	kinds. A name from the request never becomes a key.
//
//	It is rate limited per source, on the same limiter the rest of the
//	program uses.
//
// The reading, listing, exporting and deleting all live in the admin, which is
// the process behind authentication. That split is the whole design: the
// internet-facing half can receive a message and cannot read the postbag.
//
// # Why there is no CSRF token
//
// Because there is nothing to forge. A CSRF token protects an action that
// depends on who is asking, and this endpoint has no session, no cookie and no
// privilege — a request from another origin does exactly what a request from
// this one does, which is add an anonymous submission that somebody will read
// later. Adding a token would be theatre, and worse, it would have to live in
// a cache-busting header on an otherwise static page.
//
// What is defended is spam, and that is a different mechanism: see the honeypot
// and timing checks in internal/form.

// Forms gives the public server the declared forms and somewhere to put what
// arrives. Nil means the route 404s, which is right for a site with no forms.
type Forms struct {
	Set   func() (*form.Set, error)
	Store *form.Store
	// Limit is the rate limiter. Nil means unlimited, which is only right in a
	// test — the host wires one from configuration.
	Limit *throttle.Limiter
	// Audit records that something arrived, without recording what. The
	// content of a submission is personal data and does not belong in a log
	// that outlives the retention period.
	Audit func(formName, source string, accepted bool)
	// Notify tells another system that a submission arrived.
	//
	// # Why this exists
	//
	// A form held what people sent and told nobody. Publishing has fired
	// webhooks since webhooks existed; a booking, an enquiry or a complaint
	// sat in a store until somebody thought to open the admin, which for a
	// studio taking bookings is the difference between a feature and a
	// pending customer. The pieces were all here — endpoints, signing,
	// timestamps, retries — and no event ever named a form.
	//
	// # Why it carries the name and not the message
	//
	// The same rule the audit hook above follows. A submission has a retention
	// period; a copy of it posted to another system has whatever period that
	// system has, which is usually none. So this says that something arrived
	// and which form it came through, and the operator reads it where it is
	// kept.
	//
	// Nil means nothing is configured, which is the ordinary case and is not
	// an error.
	Notify func(formName string)
	// Now is the clock; nil is time.Now, as for bookings and the newsletter.
	//
	// A test holds it so a page stamped a second ago is judged a second
	// old. On the real clock a second could tick over between the test
	// stamping the page and this route reading the time, so a page sent a
	// second after it was read was judged two seconds old, and a person's,
	// about once in six hundred tries: the test that the form, a booking
	// and the sign-up judge alike failed now and then for no fault in any
	// of them.
	Now func() time.Time
}

func (st *Site) formsNow() time.Time {
	if st.Forms != nil && st.Forms.Now != nil {
		return st.Forms.Now()
	}
	return time.Now()
}

// submit receives one form.
// formStyle serves /form/NAME.css: the rules that hide a question until the
// answer that asks it is given, from the declaration alone.
func (st *Site) formStyle(w http.ResponseWriter, r *http.Request, name string) {
	set, err := st.Forms.Set()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, known := set.Get(name)
	if !known || !st.formOffered(f.Name) {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/css; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write([]byte(f.StyleSheet()))
}

// formOffered reports whether anything the site shows a visitor offers a
// form: a published page, visible now, that names it or renders through a
// layout that posts to it (the markup the forms screen prints, pasted into
// a template), or a chatbot that may fill it in. Pages for members count,
// for a form offered to members.
//
// Only what a visitor can reach: pages for members while the site lets
// anybody be one, as a board counts them, and a chatbot that is on the
// site, as /ask/NAME serves it. Both counted whatever their state, so a
// form placed only on a members' page of a site with membership off, or
// only in the actions of a chatbot still being built, took answers from a
// script that knew its name.
func (st *Site) formOffered(name string) bool {
	if pages, _, err := st.pages(); err == nil && st.pagesOffer(pages, name) {
		return true
	}
	if st.membersOn() {
		if pages, err := st.membersOnlyPages(); err == nil && st.pagesOffer(pages, name) {
			return true
		}
	}
	if st.Assistants != nil && st.Assistants.Set != nil {
		if set, err := st.Assistants.Set(); err == nil && set != nil {
			for _, a := range set.Assistants {
				if !a.Public {
					continue
				}
				for _, ac := range a.Actions {
					if ac.Kind == assistant.Form && ac.Target == name {
						return true
					}
				}
			}
		}
	}
	return false
}

// pagesOffer reports whether one of these pages carries the form.
func (st *Site) pagesOffer(pages map[string]any, name string) bool {
	posting := map[string]bool{}
	for _, l := range st.Layouts.Names() {
		if src, ok := st.Layouts.Source(l); ok && postsTo(src, "/form/"+name) {
			posting[l] = true
		}
	}
	for _, body := range pages {
		if m, ok := body.(map[string]any); ok {
			if named, _ := m["form"].(string); strings.TrimSpace(named) == name {
				return true
			}
		}
		if len(posting) > 0 {
			if l, _, err := st.Layouts.For(body); err == nil && posting[l] {
				return true
			}
		}
	}
	return false
}

// postsTo reports whether markup names this action as a whole path, so
// /form/contact is not found in /form/contact_us.
func postsTo(src, action string) bool {
	for i := strings.Index(src, action); i >= 0; {
		end := i + len(action)
		if end == len(src) {
			return true
		}
		if c := src[end]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return true
		}
		next := strings.Index(src[end:], action)
		if next < 0 {
			return false
		}
		i = end + next
	}
	return false
}

func (st *Site) submit(w http.ResponseWriter, r *http.Request) {
	if st.Forms == nil || st.Forms.Store == nil {
		http.NotFound(w, r)
		return
	}
	// A form's stylesheet: which questions wait for an answer (form.When).
	if css, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/form/"), ".css"); ok && r.Method != http.MethodPost {
		st.formStyle(w, r, css)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/form/")
	set, err := st.Forms.Set()
	if err != nil {
		http.Error(w, "this form is unavailable", http.StatusInternalServerError)
		return
	}
	f, known := set.Get(name)
	if !known || !st.formOffered(f.Name) {
		// Not found rather than a message naming what does exist. An
		// enumerable list of forms is a list of things to spam.
		//
		// And not found for a form nothing on the site offers. This took
		// any declared form by name, so one taken off every page, one on
		// a page still in draft or past its date, or a form placed on no
		// page at all kept collecting personal data, as consent given,
		// from a script that needed only the field names. Boards,
		// bookings and the newsletter already take a post only from a
		// published page that carries them.
		http.NotFound(w, r)
		return
	}
	if _, until, off := st.shielded("form:" + f.Name); off {
		st.resting(w, r, "This form", until)
		return
	}

	source := sourceOf(r)
	if st.Forms.Limit != nil {
		if d := st.Forms.Limit.Check(throttle.Subject{Source: source}); !d.Allowed {
			secs := int(d.RetryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			http.Error(w, "too many submissions from here, try again shortly",
				http.StatusTooManyRequests)
			return
		}
	}

	// The body limit is applied before parsing, not after. A limit checked
	// after ParseForm is a limit that ran once the allocation had happened.
	values, files, ok := readSubmission(w, r, f)
	if !ok {
		http.Error(w, "that submission could not be read", http.StatusBadRequest)
		return
	}

	// Every attempt counts against the limiter, accepted or not.
	//
	// Spent before the submission is judged, because the thing being bounded
	// is the rate of writes from one address and a valid write is still a
	// write. Only counting rejections was the arrangement that let a script
	// load the form once, keep the timestamp and post valid submissions in a
	// loop: measured against the demo, eighty from one address were eighty
	// accepted and none refused. The honeypot and the timing stamp both pass
	// for anything that read the page once.
	//
	// Before rather than after, so a submission that fails somewhere further
	// down — a full disk, a refused write — has still been counted. The
	// alternative charges nothing for an attempt that did work.
	if st.Forms.Limit != nil {
		st.Forms.Limit.Spend(throttle.Subject{Source: source})
	}

	sub, err := form.AcceptWithFiles(f, values, files, source, st.formsNow())
	if err != nil {
		if st.Forms.Audit != nil {
			st.Forms.Audit(name, source, false)
		}
		if errors.Is(err, form.ErrSpam) {
			st.signal(FormSpam, f.Name, r)
		}
		st.formResult(w, r, f, err.Error())
		return
	}
	if err := st.keep(r, name, source, sub); err != nil {
		// The files kept have reached their ceiling: refused as a
		// submission the form cannot take, in words, not as a fault. keep
		// has audited it as refused.
		if errors.Is(err, form.ErrFilesFull) {
			st.formResult(w, r, f, err.Error())
			return
		}
		http.Error(w, "that submission could not be stored",
			http.StatusInternalServerError)
		return
	}
	st.formResult(w, r, f, "")
}

// keep stores an accepted submission and tells everything a submission
// tells: the audit record of the source that wrote it, the form's goal, and
// the staff alert.
//
// One function for every route that writes a submission, because there are
// two and they drifted. /share stored through the same form pipeline and did
// none of the rest, so a submission from the share sheet, the less defended
// route, left no audit record and alerted nobody: an abuse investigation saw
// nothing of it, and a real enquiry sent that way waited until somebody
// opened the admin.
func (st *Site) keep(r *http.Request, name, source string, sub form.Submission) error {
	if err := st.Forms.Store.Put(sub); err != nil {
		// A submission refused for want of room is a refusal, recorded as
		// one on whichever route it came by; any other failure is a fault,
		// and the caller answers it as one.
		if errors.Is(err, form.ErrFilesFull) && st.Forms.Audit != nil {
			st.Forms.Audit(name, source, false)
		}
		return err
	}
	if st.Forms.Audit != nil {
		st.Forms.Audit(name, source, true)
	}
	st.convert(r, "form:"+name)
	// After it is stored and before the reply is written, because the person
	// who filled the form in is owed an answer whatever the receiver does. The
	// host's implementation is what bounds the wait; this end knows only that
	// something arrived.
	if st.Forms.Notify != nil {
		st.Forms.Notify(name)
	}
	return nil
}

// readSubmission reads what was sent: the fields, and for a form that
// takes files, the files its file fields were sent, each read no further
// than it may be. A form that takes none is read as it always was, with no
// multipart parser in the way of a request that should not need one.
func readSubmission(w http.ResponseWriter, r *http.Request, f *form.Form) (map[string]string, map[string]form.Upload, bool) {
	values := map[string]string{}
	if !f.HasFiles() || !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, form.MaxSubmission)
		if err := r.ParseForm(); err != nil {
			return nil, nil, false
		}
		for k, v := range r.PostForm {
			if len(v) > 0 {
				values[k] = v[0]
			}
		}
		return values, nil, true
	}
	r.Body = http.MaxBytesReader(w, r.Body, form.MaxUploadBytes+form.MaxSubmission)
	// Held in memory up to a megabyte, the rest in the site's own temporary
	// directory (TMPDIR, inside the store), removed before this returns.
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return nil, nil, false
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	for k, v := range r.MultipartForm.Value {
		if len(v) > 0 {
			values[k] = v[0]
		}
	}
	files := map[string]form.Upload{}
	for _, fl := range f.Fields {
		if fl.Kind != form.File {
			continue
		}
		hs := r.MultipartForm.File[fl.Name]
		if len(hs) == 0 || hs[0].Size == 0 {
			continue
		}
		in, err := hs[0].Open()
		if err != nil {
			return nil, nil, false
		}
		data, err := io.ReadAll(io.LimitReader(in, form.MaxFileBytes+1))
		in.Close()
		if err != nil {
			return nil, nil, false
		}
		files[fl.Name] = form.Upload{Name: hs[0].Filename, Data: data}
	}
	return values, files, true
}

// formResult answers a submission.
//
// A whole page rather than a redirect back to the form, because the form lives
// on a static page this server did not render and cannot add a message to. The
// page is deliberately plain: it is served to anybody on the internet and
// carries nothing about the site's state.
func (st *Site) formResult(w http.ResponseWriter, r *http.Request,
	f *form.Form, problem string) {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Never cached. A stored copy of "thank you" served to the next person is
	// a confusing outcome, and a stored copy of an error is worse.
	w.Header().Set("Cache-Control", "no-store")
	if problem != "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}

	title, body := "Thank you", "Your message has been received."
	if problem != "" {
		title, body = "Not sent", problem
	}
	fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title><link rel="stylesheet" href="/site.css"></head>
<body><main><h1>%s</h1><p>%s</p><p><a href="/">Back to the site</a></p>
</main></body></html>`,
		escape(title), escape(title), escape(body))
}

// escape is enough for the four characters that matter in element content and
// in an attribute value. The result page prints one error string and two fixed
// titles, so a full context-aware escaper would be more machinery than the
// surface justifies — and the error strings are ours.
func escape(s string) string { return formReplacer.Replace(s) }

// Built once. A Replacer compiles a trie on first use and is safe to share.
var formReplacer = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")

// sourceOf is the address a submission came from.
//
// RemoteAddr only. A forwarded header is set by whatever is in front, and a
// rate limit keyed on a value the client controls is a limit the client turns
// off by varying it. An operator behind a proxy wants the proxy doing this.
func sourceOf(r *http.Request) string { return clientip.SourceFrom(r) }
