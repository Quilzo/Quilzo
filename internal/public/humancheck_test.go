// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/form"
)

// humanCase is one thing a sender can put in the two fields a page this
// server rendered carries: the field nobody sees, and when the page was
// read, relative to the clock of the route that answers.
type humanCase struct {
	what     string
	honeypot string
	stamp    func(now time.Time) string
	// want is what every route makes of it: "spam", refused and told to
	// the shield; "person", taken; or "yesterday", a page opened more than
	// a day ago, which each route answers its own way.
	want string
}

func ago(d time.Duration) func(time.Time) string {
	return func(now time.Time) string { return fmt.Sprint(now.Add(-d).Unix()) }
}

var humanCases = []humanCase{
	{"a filled-in honeypot", "http://buy.example", ago(time.Minute), "spam"},
	{"a honeypot of spaces", "   ", ago(time.Minute), "person"},
	{"no stamp", "", func(time.Time) string { return "" }, "spam"},
	{"a stamp that is not a number", "", func(time.Time) string { return "soon" }, "spam"},
	{"a stamp of a second ago", "", ago(time.Second), "spam"},
	{"a stamp from the future", "", ago(-time.Minute), "spam"},
	{"a stamp of two seconds ago", "", ago(2 * time.Second), "person"},
	{"a stamp of a minute ago", "", ago(time.Minute), "person"},
	{"a stamp in spaces", "", func(now time.Time) string { return " " + ago(time.Minute)(now) + " " }, "person"},
	{"a stamp of a day ago", "", ago(24 * time.Hour), "person"},
	{"a stamp of a day and a minute ago", "", ago(24*time.Hour + time.Minute), "yesterday"},
}

// humanRoute sends one case to one route and says what it made of it.
type humanRoute func(t *testing.T, c humanCase, i int) string

// The form, a booking and the newsletter's sign-up refuse the same scripts
// and take the same people.
//
// Each made the two checks a page this server rendered lets it make in a
// copy of its own, so a change to one (what a stamp may look like, how
// quickly a person reads) would have reached one route and not the
// others. They are form.CheckHuman now; this pins that the three still
// answer alike, and that each still tells the shield under its own name.
func TestTheFormTheBookingAndTheSignUpRefuseTheSameScripts(t *testing.T) {
	for name, route := range map[string]humanRoute{
		"the form": formRoute, "a booking": bookingRoute, "the sign-up": signUpRoute,
	} {
		for i, c := range humanCases {
			want := c.want
			if want == "yesterday" {
				continue // TestAPageOpenedYesterdayIsTreatedAsEachRouteAlwaysTreatedIt
			}
			if got := route(t, c, i); got != want {
				t.Errorf("%s made %q of %s, not %q", name, got, c.what, want)
			}
		}
	}
}

// A page opened more than a day ago is answered as each route always
// answered it. The form says the questions may have changed and a booking
// asks for a time again, neither told to the shield, because a person who
// left a tab open is not a script. The sign-up takes it: a page with a
// sign-up in its footer is cached, and an old one is still somebody's page.
func TestAPageOpenedYesterdayIsTreatedAsEachRouteAlwaysTreatedIt(t *testing.T) {
	var c humanCase
	for _, hc := range humanCases {
		if hc.want == "yesterday" {
			c = hc
		}
	}
	for name, want := range map[string]string{
		"the form": "opened more than a day ago", "a booking": "old", "the sign-up": "person",
	} {
		route := map[string]humanRoute{"the form": formRoute, "a booking": bookingRoute, "the sign-up": signUpRoute}[name]
		if got := route(t, c, 0); got != want {
			t.Errorf("%s made %q of a page opened yesterday, not %q", name, got, want)
		}
	}
}

// formRoute posts the contact form, on a clock the test holds, as the
// booking and the sign-up are posted. On the real clock a second ticking
// over between stamping the page and the route reading the time made a
// second ago two, and the case was answered as a person's.
func formRoute(t *testing.T, c humanCase, _ int) string {
	st, fs := withForm(t)
	now := time.Now()
	st.Forms.Now = func() time.Time { return now }
	heard := tellingTheShield(st)
	v := good()
	v.Set(form.Honeypot, c.honeypot)
	v.Set(form.StampField, c.stamp(now))
	w := post(t, st, "/form/contact", v)
	switch subs, _ := fs.List("contact"); {
	case len(*heard) == 1 && (*heard)[0].kind == FormSpam && (*heard)[0].subject == "contact" && len(subs) == 0:
		return "spam"
	case len(*heard) > 0:
		return fmt.Sprintf("told %v", *heard)
	case len(subs) == 1:
		return "person"
	case strings.Contains(w.Body.String(), "opened more than a day ago"):
		return "opened more than a day ago"
	}
	return fmt.Sprintf("answered %d: %s", w.Code, w.Body.String())
}

var reBookSlot = regexp.MustCompile(`name="slot" id="slot-[^"]+" value="(\d+)"`)

// bookingRoute books a haircut, a different free time each case.
func bookingRoute(t *testing.T, c humanCase, i int) string {
	st, _, _, now := bookingSite(t)
	heard := tellingTheShield(st)
	slots := reBookSlot.FindAllStringSubmatch(getPage(st, "/book").Body.String(), -1)
	if len(slots) <= i {
		t.Fatalf("only %d times are offered", len(slots))
	}
	w := postTo(st, "/book/cut", url.Values{"page": {"book"}, "slot": {slots[i][1]}, "name": {"Ann Example"},
		"email": {"ann@example.com"}, form.Honeypot: {c.honeypot}, form.StampField: {c.stamp(*now)}})
	loc := w.Header().Get("Location")
	switch {
	case len(*heard) == 1 && (*heard)[0].kind == FormSpam && (*heard)[0].subject == "booking:cut" &&
		strings.Contains(loc, "booking_error=refused"):
		return "spam"
	case len(*heard) > 0:
		return fmt.Sprintf("told %v", *heard)
	case strings.Contains(loc, "booking_error=old"):
		return "old"
	case w.Code == http.StatusSeeOther && strings.Contains(loc, "booking=") && !strings.Contains(loc, "booking_error"):
		return "person"
	}
	return fmt.Sprintf("answered %d %s", w.Code, loc)
}

// signUpRoute signs an address up to the newsletter.
func signUpRoute(t *testing.T, c humanCase, i int) string {
	rig := newsletterSite(t)
	heard := tellingTheShield(rig.st)
	w := postTo(rig.st, "/newsletter/subscribe", url.Values{"page": {"news"}, "email": {fmt.Sprintf("ann%d@example.com", i)},
		form.Honeypot: {c.honeypot}, form.StampField: {c.stamp(*rig.now)}})
	loc := w.Header().Get("Location")
	switch {
	case len(*heard) == 1 && (*heard)[0].kind == FormSpam && (*heard)[0].subject == "newsletter:signup" &&
		strings.Contains(loc, "newsletter_error=refused"):
		return "spam"
	case len(*heard) > 0:
		return fmt.Sprintf("told %v", *heard)
	case strings.Contains(loc, "newsletter=sent"):
		return "person"
	}
	return fmt.Sprintf("answered %d %s", w.Code, loc)
}
