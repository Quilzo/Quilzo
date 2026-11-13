// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/personalise"
)

func TestARuleServesItsPageAndTakesPrecedence(t *testing.T) {
	st, c := experimentSite(t)
	set := &personalise.Set{}
	if err := set.Put(personalise.Rule{Name: "news", Page: "pricing", Variant: "thanks",
		Enabled: true, When: []personalise.Condition{{Field: personalise.Campaign, Values: []string{"newsletter"}}}}); err != nil {
		t.Fatal(err)
	}
	st.Personalise = func() (*personalise.Set, error) { return set, nil }

	r := httptest.NewRequest("GET", "/pricing?utm_source=newsletter", nil)
	r.RemoteAddr = "203.0.113.5:1"
	r.Header.Set("User-Agent", browser)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "Thanks") || !strings.HasPrefix(w.Header().Get("Cache-Control"), "private") {
		t.Fatalf("the rule's page was not served privately: %q", w.Header().Get("Cache-Control"))
	}
	d := c.Today()
	if d.Goals[personalise.SeenKey("news")] != 1 {
		t.Fatal("the rule's exposure was not counted")
	}
	// The experiment on the same page did not also count this visitor.
	if d.Goals["exp/price/a/seen"]+d.Goals["exp/price/b/seen"] != 0 {
		t.Fatal("a personalised visitor was counted in the experiment")
	}
	// Without the campaign, the experiment runs as before.
	if body := visitAs(st, "/pricing", "203.0.113.6").Body.String(); strings.Contains(body, "Thanks") {
		t.Fatal("the rule applied without its condition")
	}
}

// A page a rule may change is never stored by a shared cache as one answer
// for everybody.
//
// A visitor no rule matched was answered "public", with nothing saying the
// answer depended on their language, their device, where they came from or
// the hour. A CDN or proxy in front of the site keeps the first such answer
// and hands it to every later visitor to the address, so the French, the
// phone and the out-of-hours versions were never seen by anybody behind it.
func TestAPersonalisedPageIsNotSharedFromACache(t *testing.T) {
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About us"}, "about-fr": map[string]any{"title": "À propos"}})
	set := &personalise.Set{}
	if err := set.Put(personalise.Rule{Name: "fr", Page: "about", Variant: "about-fr", Enabled: true,
		When: []personalise.Condition{{Field: personalise.Language, Values: []string{"fr"}}}}); err != nil {
		t.Fatal(err)
	}
	st.Personalise = func() (*personalise.Set, error) { return set, nil }
	for _, lang := range []string{"", "en-GB", "fr-FR"} {
		w := get(st, "/about", map[string]string{"User-Agent": browser, "Accept-Language": lang})
		if w.Code != 200 {
			t.Fatalf("%q: %d", lang, w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); !strings.HasPrefix(cc, "private") {
			t.Errorf("Accept-Language %q was answered %q", lang, cc)
		}
	}
	// A page no rule is about is still anybody's.
	if cc := get(st, "/", map[string]string{"User-Agent": browser}).Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public") {
		t.Errorf("the home page was answered %q", cc)
	}
	// Nor is a rule that is turned off.
	set.Rules[0].Enabled = false
	if cc := get(st, "/about", map[string]string{"User-Agent": browser}).Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public") {
		t.Errorf("a page whose only rule is off was answered %q", cc)
	}
}
