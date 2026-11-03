// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quilzo/quilzo/internal/a2a"
)

// A card that would not validate is not served, and a static copy goes out
// without it.
//
// # What this found
//
// The card's own documentation says a deployment that would publish an
// invalid card serves nothing instead: a 404, a site with no card, which is
// true and harmless. The handler did not check; the command line's builder
// did, and handed the failure back as an error, which the handler answered
// with 500. The static copy treats a 404 from an optional address as absent
// and anything else but 200 as a hole, so one card that did not validate —
// a site with no https address yet, say — failed every `quilzo ipfs id`,
// `ipfs write` and `content_id`.
func TestAnInvalidAgentCardIsNotServedAndDoesNotStopACopy(t *testing.T) {
	st := bundleSite(t)
	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		st.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/agent-card.json", nil))
		return rec
	}

	// A card for a site with no address: its url is relative, which A2A
	// does not allow.
	invalid := a2a.From(nil, nil, a2a.Options{SiteName: st.Name})
	if invalid.Validate() == nil {
		t.Fatal("the fixture card validates, so this tests nothing")
	}
	st.AgentCard = func() (a2a.Card, error) { return invalid, nil }
	if rec := get(); rec.Code != http.StatusNotFound {
		t.Errorf("a card that does not validate answered %d: %s. It is "+
			"documented as serving nothing, a 404", rec.Code, rec.Body)
	}
	files, err := st.Bundle()
	if err != nil {
		t.Fatalf("one card that does not validate stopped the static copy: %v", err)
	}
	if _, ok := files[".well-known/agent-card.json"]; ok {
		t.Error("a card that does not validate went into the static copy")
	}

	// A valid one is served, and copied.
	valid := a2a.From(nil, nil, a2a.Options{SiteName: st.Name, BaseURL: st.BaseURL})
	if err := valid.Validate(); err != nil {
		t.Fatalf("the fixture's valid card does not validate: %v", err)
	}
	st.AgentCard = func() (a2a.Card, error) { return valid, nil }
	if rec := get(); rec.Code != http.StatusOK {
		t.Errorf("a valid card answered %d", rec.Code)
	}
	if files, err = st.Bundle(); err != nil {
		t.Fatal(err)
	}
	if _, ok := files[".well-known/agent-card.json"]; !ok {
		t.Error("a valid card is missing from the static copy")
	}

	// A card that could not be built at all is a fault, answered as one,
	// rather than passed off as a deliberate absence.
	st.AgentCard = func() (a2a.Card, error) { return a2a.Card{}, errors.New("the agents could not be read") }
	if rec := get(); rec.Code != http.StatusInternalServerError {
		t.Errorf("a card that could not be built answered %d", rec.Code)
	}
}
