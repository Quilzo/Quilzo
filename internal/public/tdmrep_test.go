package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A licence that refuses training reserves mining; one that does not, does not.
//
// Read from Prohibits only. An absent permission is not a refusal — a licence
// listing "search" and saying nothing about training has reserved nothing, and
// inferring a reservation from silence would publish one the operator never
// made.
func TestMiningIsReservedOnlyWhenTheLicenceRefusesIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		lic  *Licence
		want bool
	}{
		{"no licence at all", nil, false},
		{"prohibits training", &Licence{Prohibits: []string{"train"}}, true},
		{"prohibits tdm", &Licence{Prohibits: []string{"text-and-data-mining"}}, true},
		{"case and space", &Licence{Prohibits: []string{"  Train  "}}, true},
		{"permits search, silent on training",
			&Licence{Permits: []string{"search"}}, false},
		{"prohibits something else",
			&Licence{Prohibits: []string{"ai-summarize"}}, false},
	} {
		if got := reservesMining(tc.lic); got != tc.want {
			t.Errorf("%s: reservesMining = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The header travels with the page, so a crawler that took the content has
// already been told.
func TestThePageCarriesTheReservationHeader(t *testing.T) {
	st := &Site{Licence: &Licence{Prohibits: []string{"train"}}}
	w := httptest.NewRecorder()
	st.tdmHeaders(w)

	if got := w.Header().Get("tdm-reservation"); got != "1" {
		t.Errorf("tdm-reservation is %q, want 1", got)
	}
	// The detail stays in one place rather than being restated in a second
	// grammar that can disagree with the first.
	if got := w.Header().Get("tdm-policy"); got != "/license.xml" {
		t.Errorf("tdm-policy is %q, want /license.xml", got)
	}
}

// A site that permits mining says so rather than staying silent.
//
// Silence is what an unconfigured site looks like, and "we never objected" is a
// weaker position afterwards than "we said yes".
func TestPermittingMiningIsStatedNotImplied(t *testing.T) {
	st := &Site{Licence: &Licence{Permits: []string{"train"}}}
	w := httptest.NewRecorder()
	st.tdmHeaders(w)
	if got := w.Header().Get("tdm-reservation"); got != "0" {
		t.Errorf("tdm-reservation is %q, want 0", got)
	}
	if w.Header().Get("tdm-policy") != "" {
		t.Error("a permissive site pointed at a policy it is not asserting")
	}
}

// Nothing is emitted when nothing was configured.
//
// A reservation nobody chose is worse than none: a crawler will honour it and
// the operator never agreed to it. Same reasoning that makes /license.xml a 404
// rather than an invention.
func TestNoLicenceMeansNoReservation(t *testing.T) {
	st := &Site{}
	w := httptest.NewRecorder()
	st.tdmHeaders(w)
	if w.Header().Get("tdm-reservation") != "" {
		t.Error("an unconfigured site asserted a reservation nobody chose")
	}

	rec := httptest.NewRecorder()
	st.tdmRep(rec, httptest.NewRequest("GET", "/.well-known/tdmrep.json", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("the well-known file answered %d with no licence", rec.Code)
	}
}

// The well-known file says the same thing as the header.
//
// Two places stating one intention is two places for them to disagree, so this
// checks they agree rather than only that each parses.
func TestTheWellKnownFileAgreesWithTheHeader(t *testing.T) {
	st := &Site{Licence: &Licence{Prohibits: []string{"train"}}}

	rec := httptest.NewRecorder()
	st.tdmRep(rec, httptest.NewRequest("GET", "/.well-known/tdmrep.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content type is %q", ct)
	}

	var got []struct {
		Location    string `json:"location"`
		Reservation int    `json:"tdm-reservation"`
		Policy      string `json:"tdm-policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the file is not valid JSON: %v\n%s", err, rec.Body.String())
	}
	if len(got) != 1 {
		t.Fatalf("%d entries, want 1", len(got))
	}

	hdr := httptest.NewRecorder()
	st.tdmHeaders(hdr)
	if want := hdr.Header().Get("tdm-reservation"); want != "1" || got[0].Reservation != 1 {
		t.Errorf("the file says %d and the header says %q; they have to agree",
			got[0].Reservation, want)
	}
	if got[0].Policy != hdr.Header().Get("tdm-policy") {
		t.Errorf("the file points at %q and the header at %q",
			got[0].Policy, hdr.Header().Get("tdm-policy"))
	}
}
