package site

import (
	"fmt"
	"sort"
	"time"
)

// Content that takes itself down.
//
// # Why this is checked when the page is served
//
// Every CMS with scheduled unpublishing does it with a job: a cron entry, a
// queue worker, a timer inside the process. The content is public until that
// job runs, and the job is a second thing that can be down. An embargo that
// lifts because a worker was wedged is not an embargo, and the failure is
// silent — nobody notices content is still up, because nothing is broken.
//
// So expiry is a property of the content, evaluated at the moment somebody
// asks for it. A page past its date is not served, whatever the scheduler did
// or did not do. The scheduler is still worth having — it removes the page
// from listings and sitemaps rather than leaving a 404 in them — but it is an
// optimisation, not the control.
//
// That inverts the usual reliability argument. Normally a background job is
// the reliable part and the request path is where you avoid work; here the
// request path is the only thing guaranteed to run at the relevant moment.
//
// # Why publishing is refused rather than warned
//
// A page whose expiry has already passed is almost always a mistake — a date
// typed with the wrong year, or a draft that sat for a month. Publishing it
// would mean writing content that is invisible from the instant it goes live,
// which looks exactly like a broken publish and is very hard to diagnose from
// the outside.

// Expires is the reserved page field carrying the moment content stops being
// public. RFC 3339, because a date with no timezone is a date that means
// something different to the person who typed it and the server that reads it.
const Expires = "expires"

// Publish window fields. Both optional, both reserved.
//
// Starts exists because "publish at" is already a scheduled commit, and this is
// the other thing people mean by it: a page that is committed and live and not
// yet visible. An embargo on one page should not require holding back the whole
// publication.
const Starts = "starts"

// MaxAhead bounds how far out a date may be set.
//
// A hundred years, which is not a real limit on anybody's editorial calendar
// and does catch the two mistakes that actually happen: a millisecond timestamp
// pasted into a seconds field, and a year typed as 20226.
const MaxAhead = 100 * 365 * 24 * time.Hour

// Window is when a page is public.
type Window struct {
	// Starts is when it becomes visible. Zero means immediately.
	Starts time.Time
	// Expires is when it stops. Zero means never.
	Expires time.Time
}

// WindowOf reads the publish window from a page body.
//
// A malformed date is an error rather than an ignored field. Ignoring it would
// mean a typo silently removes an embargo, which is the direction of failure
// that matters: the mistake makes content public earlier than intended, and
// nothing says so.
func WindowOf(body any) (Window, error) {
	m, ok := body.(map[string]any)
	if !ok {
		return Window{}, nil
	}
	var w Window
	for field, into := range map[string]*time.Time{
		Starts: &w.Starts, Expires: &w.Expires,
	} {
		raw, present := m[field]
		if !present {
			continue
		}
		s, isString := raw.(string)
		if !isString {
			return Window{}, fmt.Errorf(
				"%s must be a date as text, not %T", field, raw)
		}
		if s == "" {
			continue
		}
		t, err := parseWhen(s)
		if err != nil {
			return Window{}, fmt.Errorf("%s: %w", field, err)
		}
		*into = t
	}
	if !w.Starts.IsZero() && !w.Expires.IsZero() && !w.Expires.After(w.Starts) {
		return Window{}, fmt.Errorf(
			"this page is set to expire at %s and start at %s, so it is never "+
				"visible", w.Expires.Format(time.RFC3339),
			w.Starts.Format(time.RFC3339))
	}
	return w, nil
}

// parseWhen accepts a full timestamp or a plain date.
//
// A plain date means midnight UTC, and that is stated rather than guessed at:
// "expires 2026-12-31" almost always means the end of the year somewhere, and
// picking the server's timezone would make the same content expire at different
// moments on two machines.
func parseWhen(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return checkRange(t)
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return checkRange(t.UTC())
	}
	return time.Time{}, fmt.Errorf(
		"%q is not a date. Use 2026-12-31, or 2026-12-31T09:00:00Z for a "+
			"particular moment — a date with no timezone means midnight UTC "+
			"rather than midnight wherever the server happens to be", s)
}

func checkRange(t time.Time) (time.Time, error) {
	if d := time.Until(t); d > MaxAhead || d < -MaxAhead {
		return time.Time{}, fmt.Errorf(
			"%s is %.0f years away, which is almost certainly a typo — a "+
				"millisecond timestamp in a seconds field, or a year with an "+
				"extra digit", t.Format(time.RFC3339), d.Hours()/24/365)
	}
	return t, nil
}

// Public reports whether a page may be served now.
func (w Window) Public(now time.Time) bool {
	if !w.Starts.IsZero() && now.Before(w.Starts) {
		return false
	}
	if !w.Expires.IsZero() && !now.Before(w.Expires) {
		return false
	}
	return true
}

// State names why a page is or is not visible, for a screen.
func (w Window) State(now time.Time) string {
	switch {
	case !w.Starts.IsZero() && now.Before(w.Starts):
		return "embargoed"
	case !w.Expires.IsZero() && !now.Before(w.Expires):
		return "expired"
	case !w.Expires.IsZero():
		return "expiring"
	}
	return "public"
}

// Visible filters a page set to what may be served.
//
// Called by the public site on every request path that enumerates pages —
// the page itself, the sitemap, the search index, the listing of links. A page
// filtered from one and not the others is a page that 404s from a link the
// same server printed.
func Visible(pages map[string]any, now time.Time) map[string]any {
	out := make(map[string]any, len(pages))
	for name, body := range pages {
		w, err := WindowOf(body)
		if err != nil {
			// An unreadable window is treated as not public. Failing closed
			// here is the whole point: the alternative is a malformed date
			// making an embargoed page visible, which is the failure nobody
			// notices.
			continue
		}
		if w.Public(now) {
			out[name] = body
		}
	}
	return out
}

// Hidden is what Visible removed, and why, for a screen and for a gate.
type Hidden struct {
	Page  string
	State string
	At    time.Time
}

func (h Hidden) String() string {
	return fmt.Sprintf("%s is %s (%s)", h.Page, h.State,
		h.At.Format(time.RFC3339))
}

// Windows reports the state of every page that has one.
func Windows(pages map[string]any, now time.Time) []Hidden {
	var out []Hidden
	for name, body := range pages {
		w, err := WindowOf(body)
		if err != nil {
			out = append(out, Hidden{Page: name, State: "unreadable"})
			continue
		}
		if w.Starts.IsZero() && w.Expires.IsZero() {
			continue
		}
		at := w.Expires
		if state := w.State(now); state == "embargoed" {
			at = w.Starts
		}
		out = append(out, Hidden{Page: name, State: w.State(now), At: at})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Page < out[j].Page })
	return out
}

// AlreadyExpired is the publish gate.
//
// A page whose date has already passed would be invisible from the instant it
// went live, which looks like a broken publish and is very hard to diagnose
// from outside. Refused with the same recorded override the other gates use.
func AlreadyExpired(pages map[string]any, now time.Time) []string {
	var out []string
	for name, body := range pages {
		w, err := WindowOf(body)
		if err != nil {
			out = append(out, fmt.Sprintf("%s has an unreadable date: %v",
				name, err))
			continue
		}
		if !w.Expires.IsZero() && !now.Before(w.Expires) {
			out = append(out, fmt.Sprintf(
				"%s expired at %s, so publishing it would put up a page "+
					"nobody can see", name, w.Expires.Format(time.RFC3339)))
		}
	}
	sort.Strings(out)
	return out
}
