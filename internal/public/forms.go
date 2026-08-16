package public

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/form"
	"github.com/lithoform/lithoform/internal/throttle"
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
}

// submit receives one form.
func (st *Site) submit(w http.ResponseWriter, r *http.Request) {
	if st.Forms == nil || st.Forms.Store == nil {
		http.NotFound(w, r)
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
	if !known {
		// Not found rather than a message naming what does exist. An
		// enumerable list of forms is a list of things to spam.
		http.NotFound(w, r)
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
	r.Body = http.MaxBytesReader(w, r.Body, form.MaxSubmission)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that submission could not be read", http.StatusBadRequest)
		return
	}
	values := make(map[string]string, len(r.PostForm))
	for k, v := range r.PostForm {
		if len(v) > 0 {
			values[k] = v[0]
		}
	}

	sub, err := form.Accept(f, values, source, time.Now())
	if err != nil {
		// Every failed attempt counts against the limiter, so a script probing
		// for what passes is slowed by its own failures rather than only by
		// its successes.
		if st.Forms.Limit != nil {
			st.Forms.Limit.Fail(throttle.Subject{Source: source})
		}
		if st.Forms.Audit != nil {
			st.Forms.Audit(name, source, false)
		}
		st.formResult(w, r, f, err.Error())
		return
	}
	if err := st.Forms.Store.Put(sub); err != nil {
		http.Error(w, "that submission could not be stored",
			http.StatusInternalServerError)
		return
	}
	if st.Forms.Audit != nil {
		st.Forms.Audit(name, source, true)
	}
	st.formResult(w, r, f, "")
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
func escape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// sourceOf is the address a submission came from.
//
// RemoteAddr only. A forwarded header is set by whatever is in front, and a
// rate limit keyed on a value the client controls is a limit the client turns
// off by varying it. An operator behind a proxy wants the proxy doing this.
func sourceOf(r *http.Request) string {
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
