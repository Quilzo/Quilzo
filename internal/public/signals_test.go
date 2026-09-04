package public

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The terms in the file every crawler already reads.
//
// This site publishes its terms three times — RSL at /license.xml, llms.txt,
// and a 402 with the terms attached. All three are read by software that went
// looking. robots.txt is read by software that did not.
func TestRobotsCarriesTheLicencesTermsAsSignals(t *testing.T) {
	st := &Site{Licence: &Licence{
		Permits:   []string{"search"},
		Prohibits: []string{"train", "ai-summarize"},
	}}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/robots.txt", nil))

	body := rec.Body.String()
	for _, want := range []string{"search=yes", "ai-train=no", "ai-input=no"} {
		if !strings.Contains(body, want) {
			t.Errorf("robots.txt does not say %q:\n%s", want, body)
		}
	}
	// The directives are defined by the policy text, and a bare "ai-train=no"
	// without it is three words with no agreed reading.
	if !strings.Contains(body, "Content-Signal:") {
		t.Error("no Content-Signal line")
	}
	if !strings.Contains(body, "may be used, not") {
		t.Error("the directives are emitted without the text that defines them")
	}
}

// A purpose nobody decided about produces no signal.
//
// "No preference stated" and "not permitted" are different answers, and a site
// that has not decided must not be made to look as though it has.
func TestAnUndecidedPurposeSignalsNothing(t *testing.T) {
	st := &Site{Licence: &Licence{Permits: []string{"search"}}}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/robots.txt", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "search=yes") {
		t.Fatalf("the decided purpose is missing:\n%s", body)
	}
	for _, unwanted := range []string{"ai-train=", "ai-input="} {
		if strings.Contains(body, unwanted) {
			t.Errorf("robots.txt states %q about a purpose the licence does "+
				"not mention:\n%s", unwanted, body)
		}
	}
}

// The signals cannot disagree with the licence, because they are the licence.
//
// A second place to write the same policy is a second place for it to be
// wrong, and the failure is silent in the worst direction: robots.txt saying
// training is allowed while the licence refuses it invites the thing the site
// then charges for.
func TestTheSignalsCannotContradictTheLicence(t *testing.T) {
	st := &Site{Licence: &Licence{
		Permits:   []string{"train"},
		Prohibits: []string{"search"},
	}}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/robots.txt", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "ai-train=yes") || !strings.Contains(body, "search=no") {
		t.Errorf("the signals do not follow the licence:\n%s", body)
	}
}

// A site with no licence says nothing, rather than guessing a default.
func TestNoLicenceMeansNoSignals(t *testing.T) {
	st := &Site{}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/robots.txt", nil))

	if strings.Contains(rec.Body.String(), "Content-Signal") {
		t.Errorf("a site with no licence states a preference:\n%s",
			rec.Body.String())
	}
}

// -- security.txt -------------------------------------------------------------

// A finder with a working exploit and nowhere to send it gives up, posts it,
// or sells it. Two of those are worse for the site than being told.
func TestSecurityTxtIsServedWhereAFinderLooks(t *testing.T) {
	st := &Site{
		BaseURL: "https://example.test",
		Security: &SecurityContact{
			Contact: []string{"mailto:security@example.test"},
			Expires: time.Unix(1800000000, 0),
			Policy:  "https://example.test/security",
		},
	}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec,
		httptest.NewRequest("GET", SecurityTxtPath, nil))

	if rec.Code != 200 {
		t.Fatalf("security.txt answered %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("served as %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Contact: mailto:security@example.test",
		"Expires: ",
		"Policy: https://example.test/security",
		"Canonical: https://example.test/.well-known/security.txt",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("security.txt is missing %q:\n%s", want, body)
		}
	}
}

// An operator who has published no contact gets no file.
//
// A security.txt with nothing in it answers 200 to the scanner that went
// looking and tells the person nothing, which is worse than not being there.
func TestAnEmptySecurityContactPublishesNothing(t *testing.T) {
	for name, st := range map[string]*Site{
		"none at all": {},
		"no contact": {Security: &SecurityContact{
			Expires: time.Unix(1800000000, 0)}},
		"no expiry": {Security: &SecurityContact{
			Contact: []string{"mailto:x@example.test"}}},
	} {
		rec := httptest.NewRecorder()
		st.Handler().ServeHTTP(rec,
			httptest.NewRequest("GET", SecurityTxtPath, nil))
		if rec.Code != 404 {
			t.Errorf("%s: answered %d, want 404", name, rec.Code)
		}
	}
}
