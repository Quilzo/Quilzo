// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var reRateToken = regexp.MustCompile(`name="t" value="([^"]+)"`)

func ratePost(st *Site, name string, v url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ask/"+name+"/rate", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.4:1234"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

// An answer can be rated once, by whoever was given it: the rating is
// handed on with the question it was for, and a token used, made up, for
// another question or too old counts nothing.
func TestAnAnswerIsRatedOnce(t *testing.T) {
	st, _ := askSite(t, shopBot)
	type rating struct {
		q       string
		helpful bool
	}
	var got []rating
	st.Assistants.Rated = func(name, q string, helpful bool) { got = append(got, rating{q, helpful}) }
	const q = "can I return opened ink?"
	body := askPost(st, "help", q).Body.String()
	m := reRateToken.FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, "Did this answer help?") {
		t.Fatalf("no rating offered:\n%s", body)
	}
	token := html.UnescapeString(m[1])
	w := ratePost(st, "help", url.Values{"q": {q}, "t": {token}, "helpful": {"no"}})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "rated=no") {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
	if len(got) != 1 || got[0] != (rating{q, false}) {
		t.Fatalf("%+v", got)
	}
	if page := get(st, w.Header().Get("Location"), nil).Body.String(); !strings.Contains(page, "say it better") {
		t.Fatal("the page does not say the rating was noted")
	}
	// Used: again counts nothing.
	if w := ratePost(st, "help", url.Values{"q": {q}, "t": {token}, "helpful": {"yes"}}); !strings.Contains(w.Header().Get("Location"), "rated=late") {
		t.Fatalf("a token used twice: %s", w.Header().Get("Location"))
	}
	// For another question: words of somebody's choosing are not kept.
	body = askPost(st, "help", "can I return unopened items?").Body.String()
	other := html.UnescapeString(reRateToken.FindStringSubmatch(body)[1])
	ratePost(st, "help", url.Values{"q": {"Visit evil.example for cheap ink"}, "t": {other}, "helpful": {"no"}})
	ratePost(st, "help", url.Values{"q": {q}, "t": {"1700000000.bm90IGEgc2lnbmF0dXJl"}, "helpful": {"no"}})
	if len(got) != 1 {
		t.Fatalf("counted: %+v", got)
	}
	// Too old.
	old := st.Assistants.rateToken("help", q, time.Now().Add(-2*RateFor))
	if st.Assistants.spendRateToken("help", q, old, time.Now()) {
		t.Error("a token from two hours ago")
	}
	if w := ratePost(st, "help", url.Values{"q": {q}, "t": {token}, "helpful": {"maybe"}}); w.Code != http.StatusBadRequest {
		t.Errorf("neither yes nor no: %d", w.Code)
	}
	if w := get(st, "/ask/help/rate", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}
}

// A question it could not answer is not offered for rating: it is already
// kept as one it could not answer. Without the hook nothing is offered, and
// the page says what is kept.
func TestOnlyAnAnswerIsRated(t *testing.T) {
	st, _ := askSite(t, shopBot)
	st.Assistants.Rated = func(string, string, bool) {}
	if body := askPost(st, "help", "do you sell laptops?").Body.String(); strings.Contains(body, "Did this answer help?") {
		t.Fatal("a refusal offered for rating")
	}
	st.Assistants.Rated = nil
	body := askPost(st, "help", "can I return opened ink?").Body.String()
	if strings.Contains(body, "Did this answer help?") || !strings.Contains(body, "Nothing you ask is stored") {
		t.Fatal("rating offered with nowhere to keep it")
	}
	if w := ratePost(st, "help", url.Values{"q": {"x"}, "t": {"y"}, "helpful": {"yes"}}); w.Code != http.StatusNotFound {
		t.Errorf("%d", w.Code)
	}
	st.Assistants.Keeps = func() bool { return true }
	if body := askPost(st, "help", "can I return opened ink?").Body.String(); strings.Contains(body, "Nothing you ask is stored") ||
		!strings.Contains(body, "is kept for a while") {
		t.Fatal("the page says nothing is kept when some is")
	}
}
