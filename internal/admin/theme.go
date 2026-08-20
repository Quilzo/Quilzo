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
		clearCookie(w, r, ThemeCookie)
	case "dark", "light":
		http.SetCookie(w, &http.Cookie{
			Name: ThemeCookie, Value: to, Path: "/",
			MaxAge: 365 * 24 * 3600, HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
		})
	default:
		http.Error(w, "theme must be system, dark or light", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// backTo returns the path the request came from, if it is one of ours.
//
// Referer is only ever used to return to a path on this same server. An open
// redirect through a preference toggle would be an embarrassing way to acquire
// one, and a toggle is exactly the sort of endpoint nobody thinks to check.
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
	// Cleaned so ".." cannot walk and "//" collapses. Normalisation rather
	// than the guard: the explicit // test below is what actually refuses a
	// protocol-relative path, and a sabotage removing this Clean does not
	// reopen the hole. Kept because handing a browser a path it has to
	// normalise itself is how the next variant of this gets found.
	clean := stdpath.Clean(path)
	if !strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "//") {
		return "/"
	}
	// Re-parsed as a whole, so anything that still reads as an origin is
	// caught rather than assumed away.
	back := clean
	if rawQuery != "" {
		back += "?" + rawQuery
	}
	v, err := url.Parse(back)
	if err != nil || v.Scheme != "" || v.Host != "" || v.Opaque != "" {
		return "/"
	}
	return back
}
