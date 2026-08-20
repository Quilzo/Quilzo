package admin

import "net/http"

// Hiding the navigation, without any JavaScript to do it with.
//
// The obvious way is a checkbox and a CSS sibling rule, which needs no script
// and no server. It is also useless for this: the checkbox resets on every
// navigation, so hiding the sidebar and then clicking a link brings it back.
// A preference that does not survive the next page is not a preference, it is
// a flicker.
//
// So the same shape as the theme toggle. A form, a cookie, and a redirect back
// to where the person was. It costs one round trip and it holds.
//
// # Two states, not three
//
// The theme toggle has three because "follow the system" is a real answer
// there and losing it is a real loss. There is no system preference for
// whether this application's navigation is showing, so a third state would be
// a state with nothing in it.
//
// # The control never hides with the thing it hides
//
// It lives in the top bar, which is always rendered. Putting it inside the
// sidebar would mean hiding the sidebar hides the only way to get it back, and
// the way out would be clearing a cookie. Somebody would find that out on
// their own screen, once.

// SidebarCookie holds the choice. Absent means shown, which is the default and
// stays the default for anybody who never touches the control.
const SidebarCookie = "quilzo_sidebar"

// sidebarHidden reports whether this request asked for the navigation hidden.
func sidebarHidden(r *http.Request) bool {
	c, err := r.Cookie(SidebarCookie)
	return err == nil && c.Value == "hidden"
}

// handleSidebar records the choice.
func (s *Server) handleSidebar(w http.ResponseWriter, r *http.Request) {
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
	case "hidden":
		http.SetCookie(w, &http.Cookie{
			Name: SidebarCookie, Value: "hidden", Path: "/",
			MaxAge: 365 * 24 * 3600, HttpOnly: true,
			SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
		})
	case "shown":
		clearCookie(w, r, SidebarCookie)
	default:
		// Named values rather than a toggle that flips whatever it finds. A
		// request that says what it wants is idempotent: pressing the browser's
		// back button and re-submitting lands in the state the form asked for,
		// not the opposite one.
		http.Error(w, "sidebar must be shown or hidden", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}
