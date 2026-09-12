// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	stdpath "path"
	"strings"
)

// Light, dark, and the one most products forget.
//
// Three states rather than two, and the third is the default: follow the
// operating system. A toggle with only light and dark makes somebody who has
// set their machine to switch at sunset choose one and lose that, and there is
// no way back to "whatever the system says" once a two-state toggle has been
// pressed.
//
// So the control cycles system → dark → light → system, and says which of the
// three it is in. A person who never touches it keeps the behaviour they
// already had.

// ThemeCookie holds the choice. Absent means follow the system.
const ThemeCookie = "quilzo_theme"

// themeOf resolves the request to a value for the root element's data-theme.
//
// Empty means no attribute, which is what lets the media query decide. The
// stylesheet was written for exactly this: its dark block is guarded by
// :root:not([data-theme="light"]), so a person who has chosen light gets light
// on a machine set to dark, and the attribute is the only thing that has to
// arrive here.
func themeOf(r *http.Request) string {
	c, err := r.Cookie(ThemeCookie)
	if err != nil {
		return ""
	}
	switch c.Value {
	case "dark", "light":
		return c.Value
	}
	return ""
}

// nextTheme is what the button will switch to, and what to call it.
//
// Computed in Go rather than branched in the template, because the label, the
// icon and the posted value have to agree and three template conditionals that
// have to agree are three places for them to stop agreeing.
func nextTheme(current string) (value, label string) {
	switch current {
	case "":
		return "dark", "Dark"
	case "dark":
		return "light", "Light"
	default:
		return "system", "System"
	}
}

// themeLabel names the current state for the button's accessible name.
func themeLabel(current string) string {
	switch current {
	case "dark":
		return "dark"
	case "light":
		return "light"
	}
	return "matching your system"
}

// handleTheme records the choice.
func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Authenticated, because it sets a cookie on this origin and nothing
	// unauthenticated has a reason to.
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	switch to := r.FormValue("to"); to {
	case "system":
		s.clearCookie(w, r, ThemeCookie)
	case "dark", "light":
		http.SetCookie(w, &http.Cookie{
			Name: ThemeCookie, Value: to, Path: "/",
			MaxAge: 365 * 24 * 3600, HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || s.behindTLSProxy(),
		})
	default:
		http.Error(w, "theme must be system, dark or light", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// backTo returns the screen the toggle was pressed on, if it is one of ours.
//
// # Why the form carries it rather than the Referer header
//
// It used to read Referer alone, and every admin response sets
// `Referrer-Policy: no-referrer` — so the browser sent nothing, backTo took
// its empty-string branch, and both toggles redirected to "/". Pressing "Hide
// menu" on any screen hid the menu and moved you to Pages. The preference was
// recorded correctly every time; you just could not see the effect on the
// screen you pressed it from, which is the only screen anybody presses it
// from.
//
// That is a header this program deliberately sends, for a reason that has not
// changed: a Referer leaks which screen of somebody's admin they were on to
// anything they navigate to. So the header stays and the destination comes
// from the form, which is a field this server rendered rather than a header
// the browser decided whether to send.
//
// Referer is still read when the field is absent, so a form somewhere that
// has not been given the field keeps whatever behaviour it had.
//
// Neither source is trusted. Both go through safeLocalPath, because a hidden
// field is as forgeable as a header — anybody can post to this endpoint with
// whatever value they like. An open redirect through a preference toggle would
// be an embarrassing way to acquire one, and a toggle is exactly the sort of
// endpoint nobody thinks to check.
//
// # The bug this had, which the host check did not catch
//
// It compared u.Host against r.Host and then returned u.Path, on the reasoning
// that a path cannot name another origin. A path beginning "//" can: browsers
// read //evil.example.com as protocol-relative and go there. So a Referer of
//
//	https://your-admin//evil.example.com/x
//
// passed the host check — the host really was your-admin — and produced
// Location: //evil.example.com/x. Confirmed live before it was fixed, and
// found by CodeQL rather than by review, which is the argument for running it.
//
// The fix is not another prefix test. It is to stop returning something the
// browser has to interpret: the path is rebuilt from its cleaned form and
// re-parsed, and anything that does not come back as a single rooted path with
// no authority is refused. A check that enumerates dangerous shapes is a check
// somebody adds a case to after the next report; this one enumerates the
// acceptable shape instead.
func backTo(r *http.Request) string {
	// The field first. ParseForm has already run in both callers, so this is
	// reading what was parsed rather than consuming the body a second time.
	if back := r.FormValue("back"); back != "" {
		u, err := url.Parse(back)
		if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
			return "/"
		}
		return safeLocalPath(u.Path, u.RawQuery)
	}
	ref := r.Referer()
	if ref == "" {
		return "/"
	}
	u, err := url.Parse(ref)
	if err != nil || u.Host != r.Host {
		return "/"
	}
	return safeLocalPath(u.Path, u.RawQuery)
}

// safeLocalPath rebuilds a same-origin destination, or gives up and returns "/".
//
// Rooted, no authority component, and no backslash — some browsers normalise
// \ to // before deciding what an authority is, so a path is only local if it
// is local under the most permissive reading of it.
func safeLocalPath(path, rawQuery string) string {
	if path == "" {
		return "/"
	}
	if strings.ContainsAny(path, "\\") {
		return "/"
	}
	// Refused if it is not already canonical, rather than cleaned into
	// something canonical.
	//
	// This used to normalise: "/../../etc/passwd" became "/etc/passwd" and a
	// redirect was issued to it. That is local, so it was never the open
	// redirect the rule is about — but it is still the wrong answer. A return
	// path carrying ".." was not written by any screen here, so it was
	// tampered with or mangled, and the honest response to "this is not a path
	// I produced" is to go home rather than to guess at a repaired version of
	// it and send somebody there.
	//
	// Nothing legitimate is lost: every path this server puts in a form is
	// already clean, so Clean is the identity on all of them.
	//
	// It also means this function now either returns its input or returns a
	// constant, which is a shape a reader — and a static analyser — can check
	// by looking at it. Both CodeQL alerts on the note handlers were this flow,
	// and both were correct that the value was unverified even though the
	// outcome was safe.
	if stdpath.Clean(path) != path {
		return "/"
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return "/"
	}
	// Re-parsed as a whole, so anything that still reads as an origin is
	// caught rather than assumed away.
	back := path
	if rawQuery != "" {
		back += "?" + rawQuery
	}
	v, err := url.Parse(back)
	if err != nil || v.Scheme != "" || v.Host != "" || v.Opaque != "" {
		return "/"
	}
	return back
}
