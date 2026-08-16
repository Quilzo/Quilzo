package site

import (
	"strings"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func doc(fields map[string]any) map[string]any { return fields }

// The property the whole design rests on: expiry is checked when the page is
// asked for, so a scheduler that never runs cannot leave content public.
func TestAnExpiredPageIsNotServedWhateverTheSchedulerDid(t *testing.T) {
	now := at("2026-08-16T12:00:00Z")
	pages := map[string]any{
		"current": doc(map[string]any{"title": "Current"}),
		"gone":    doc(map[string]any{"title": "Gone", Expires: "2026-08-01"}),
		"later":   doc(map[string]any{"title": "Later", Expires: "2027-01-01"}),
		"soon":    doc(map[string]any{"title": "Soon", Starts: "2026-12-01"}),
	}
	vis := Visible(pages, now)

	for _, want := range []string{"current", "later"} {
		if _, ok := vis[want]; !ok {
			t.Errorf("%s should be public", want)
		}
	}
	for _, gone := range []string{"gone", "soon"} {
		if _, ok := vis[gone]; ok {
			t.Errorf("%s is served and should not be", gone)
		}
	}
}

// The moment of expiry is exclusive: at exactly the expiry time it is gone.
func TestExpiryIsExclusiveAtTheBoundary(t *testing.T) {
	body := doc(map[string]any{Expires: "2026-08-16T12:00:00Z"})
	w, err := WindowOf(body)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Public(at("2026-08-16T11:59:59Z")) {
		t.Error("hidden one second before it expires")
	}
	if w.Public(at("2026-08-16T12:00:00Z")) {
		t.Error("still public at the exact moment it expires")
	}
}

// A start date is inclusive at its own boundary, for the same reason.
func TestAnEmbargoLiftsAtItsOwnMoment(t *testing.T) {
	w, err := WindowOf(doc(map[string]any{Starts: "2026-08-16T12:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	if w.Public(at("2026-08-16T11:59:59Z")) {
		t.Error("visible before the embargo lifts")
	}
	if !w.Public(at("2026-08-16T12:00:00Z")) {
		t.Error("still hidden at the moment the embargo lifts")
	}
}

// A malformed date hides the page rather than being ignored.
//
// The direction of failure is the point. Ignoring a bad date means a typo
// silently removes an embargo, and nothing says so.
func TestAMalformedDateFailsClosed(t *testing.T) {
	pages := map[string]any{
		"bad": doc(map[string]any{Expires: "next tuesday"}),
		"ok":  doc(map[string]any{"title": "fine"}),
	}
	vis := Visible(pages, at("2026-08-16T12:00:00Z"))
	if _, served := vis["bad"]; served {
		t.Error("a page with an unreadable date was served; a typo must not " +
			"silently remove an embargo")
	}
	if _, served := vis["ok"]; !served {
		t.Error("one bad date hid an unrelated page")
	}
}

// A date is refused rather than guessed at.
func TestBadDatesAreRefusedWithAnExplanation(t *testing.T) {
	for _, bad := range []string{
		"next tuesday", "16/08/2026", "1786866119000", "2026-13-45", "soon",
	} {
		_, err := WindowOf(doc(map[string]any{Expires: bad}))
		if err == nil {
			t.Errorf("accepted %q as a date", bad)
		}
	}
	// A plain date is accepted and means midnight UTC.
	w, err := WindowOf(doc(map[string]any{Expires: "2026-12-31"}))
	if err != nil {
		t.Fatalf("refused a plain date: %v", err)
	}
	if w.Expires.Hour() != 0 || w.Expires.Location() != time.UTC {
		t.Errorf("a plain date became %s; it should be midnight UTC so the "+
			"same content expires at the same moment on every machine",
			w.Expires)
	}
}

// The two mistakes that actually happen.
func TestAbsurdDatesAreCaught(t *testing.T) {
	for _, bad := range []string{
		"20226-01-01",           // a year with an extra digit
		"58386-07-11T00:00:00Z", // milliseconds parsed as seconds
	} {
		if _, err := WindowOf(doc(map[string]any{Expires: bad})); err == nil {
			t.Errorf("accepted %q, which is centuries away", bad)
		}
	}
}

// A window that is never open is a mistake, not a configuration.
func TestAWindowThatNeverOpensIsRefused(t *testing.T) {
	_, err := WindowOf(doc(map[string]any{
		Starts: "2027-01-01", Expires: "2026-01-01",
	}))
	if err == nil {
		t.Fatal("accepted a page that expires before it starts")
	}
	if !strings.Contains(err.Error(), "never") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// Publishing something already expired is refused.
func TestPublishingAnAlreadyExpiredPageIsRefused(t *testing.T) {
	now := at("2026-08-16T12:00:00Z")
	got := AlreadyExpired(map[string]any{
		"stale": doc(map[string]any{Expires: "2026-01-01"}),
		"fine":  doc(map[string]any{Expires: "2027-01-01"}),
		"plain": doc(map[string]any{"title": "no window"}),
	}, now)

	if len(got) != 1 {
		t.Fatalf("expected one problem, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "stale") {
		t.Errorf("named the wrong page: %s", got[0])
	}
}

// The state a screen shows.
func TestStateNamesWhyAPageIsHidden(t *testing.T) {
	now := at("2026-08-16T12:00:00Z")
	for _, tc := range []struct{ field, value, want string }{
		{Expires, "2026-01-01", "expired"},
		{Expires, "2027-01-01", "expiring"},
		{Starts, "2027-01-01", "embargoed"},
	} {
		w, err := WindowOf(doc(map[string]any{tc.field: tc.value}))
		if err != nil {
			t.Fatal(err)
		}
		if got := w.State(now); got != tc.want {
			t.Errorf("%s=%s is %q, expected %q", tc.field, tc.value, got, tc.want)
		}
	}
	w, _ := WindowOf(doc(map[string]any{"title": "x"}))
	if got := w.State(now); got != "public" {
		t.Errorf("a page with no window is %q", got)
	}
}

// A non-string date is refused rather than coerced.
func TestADateThatIsNotTextIsRefused(t *testing.T) {
	if _, err := WindowOf(doc(map[string]any{Expires: 1786866119})); err == nil {
		t.Error("accepted a number as a date; a unix timestamp in this field " +
			"is somebody's automation getting the format wrong")
	}
}
