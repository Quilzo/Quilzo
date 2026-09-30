// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/indicator"
)

// wireIndicators keeps a set in memory, built the way the store builds it.
func wireIndicators(srv *Server) *indicator.Set {
	now := time.Now().UTC()
	set := indicator.NewSet(nil)
	mk := func(k indicator.Kind, v, src, note string, until time.Time) indicator.Indicator {
		i, err := indicator.New(k, v, src, note, time.Time{}, until, now)
		if err != nil {
			panic(err)
		}
		set.Add(i)
		return i
	}
	found := mk(indicator.IP, "203.0.113.9", "cert", "Qakbot C2", time.Time{})
	doubted := mk(indicator.Domain, "cdn.example", "blog", "", time.Time{})
	mk(indicator.Domain, "quiet.example", "cert", `<script>alert(1)</script>`, time.Time{})
	old := mk(indicator.IP, "198.51.100.77", "cert", "", now.Add(time.Hour))
	old.Until = now.Add(-24 * time.Hour)
	set.Remove(old.ID)
	set.Add(old)
	hits := map[string]IndicatorHits{
		found.ID:   {Findings: 2, Real: 1, Last: now.Add(-3 * time.Hour)},
		doubted.ID: {Findings: 4, False: 4, Last: now.Add(-48 * time.Hour)},
	}
	srv.Indicators = &Indicators{
		List: func(time.Time) ([]indicator.Indicator, map[string]IndicatorHits, error) {
			return set.All(), hits, nil
		},
		Add: func(kind, value, source, note, until, by string) (int, int, bool, error) {
			k := indicator.Kind(kind)
			if k == "" {
				g, ok := indicator.Guess(value)
				if !ok {
					return 0, 0, false, fmt.Errorf("not anything")
				}
				k = g
			}
			i, err := indicator.New(k, value, source, note, time.Time{},
				time.Time{}, time.Now().UTC())
			if err != nil {
				return 0, 0, false, err
			}
			if !set.Add(i) {
				return 0, 0, true, nil
			}
			return 3, 1, false, nil
		},
		Remove: func(id, by string) error {
			if !set.Remove(id) {
				return fmt.Errorf("no indicator %s", id)
			}
			return nil
		},
	}
	return set
}

func TestTheIndicatorsScreenLeadsWithWhatFoundSomethingAndSaysWhatLapsed(t *testing.T) {
	srv, token := setup(t)
	wireIndicators(srv)
	body := get(t, srv, "/security/indicators", token).Body.String()
	whole(t, body)
	for _, want := range []string{"203.0.113.9", "Qakbot C2", "1 real",
		"4 ruled false", "lapsed", "Only ever ruled false"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("a feed's note reached the page as markup")
	}
	// A value is text. Nothing on the page links to it.
	if strings.Contains(body, `href="http://203.0.113.9`) ||
		strings.Contains(body, `href="//cdn.example`) ||
		strings.Contains(body, `href="https://cdn.example`) {
		t.Error("an indicator is a link")
	}
	at := func(s string) int { return strings.Index(body, "<code>"+s+"</code>") }
	if !(at("203.0.113.9") < at("198.51.100.77") && at("cdn.example") < at("198.51.100.77") &&
		at("198.51.100.77") < at("quiet.example")) {
		t.Error("the order is not: found something, then lapsed, then the rest")
	}
	narrowed := get(t, srv, "/security/indicators?q=QUIET", token).Body.String()
	if !strings.Contains(narrowed, "quiet.example") || strings.Contains(narrowed, "<code>203.0.113.9</code>") {
		t.Error("finding by value did not narrow the list")
	}
}

func TestAddingAndRemovingOnTheScreenSayWhatHappened(t *testing.T) {
	srv, token := setup(t)
	set := wireIndicators(srv)
	act := func(v url.Values) (int, string) {
		w := postForm(t, srv, "/security/indicators/act", token, v.Encode())
		return w.Code, w.Header().Get("Location")
	}
	before := set.Len()
	_, loc := act(url.Values{"do": {"add"}, "value": {"evil[.]example"},
		"source": {"isac"}})
	if !strings.Contains(loc, "m=") || !strings.Contains(loc, "3+stored+event") ||
		set.Len() != before+1 {
		t.Fatalf("add: %s", loc)
	}
	if _, loc := act(url.Values{"do": {"add"}, "value": {"evil.example"},
		"source": {"cert"}}); !strings.Contains(loc, "Already+held") {
		t.Errorf("a second source: %s", loc)
	}
	for name, v := range map[string]url.Values{
		"a private address": {"do": {"add"}, "value": {"10.1.2.3"}, "source": {"x"}},
		"a shared domain":   {"do": {"add"}, "value": {"github.io"}, "source": {"x"}},
		"nobody's claim":    {"do": {"add"}, "value": {"203.0.113.10"}},
	} {
		n := set.Len()
		if _, loc := act(v); !strings.Contains(loc, "e=") || set.Len() != n {
			t.Errorf("%s was added (%s)", name, loc)
		}
	}
	var id string
	for _, i := range set.All() {
		if i.Value == "evil.example" {
			id = i.ID
		}
	}
	if _, loc := act(url.Values{"do": {"remove"}, "id": {id}}); !strings.Contains(loc, "m=") || set.Len() != before {
		t.Errorf("remove: %s", loc)
	}
	if code, _ := act(url.Values{"do": {"purge"}}); code != http.StatusBadRequest {
		t.Errorf("an unknown action answered %d", code)
	}
	if w := get(t, srv, "/security/indicators/act", token); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET to the action answered %d", w.Code)
	}
}

func TestOnlyAnAdministratorSeesOrChangesTheIndicators(t *testing.T) {
	srv, _ := setup(t)
	set := wireIndicators(srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	w := get(t, srv, "/security/indicators", secret)
	if w.Code == 200 || strings.Contains(w.Body.String(), "203.0.113.9") {
		t.Errorf("an author read the indicators: %d", w.Code)
	}
	before := set.Len()
	p := postForm(t, srv, "/security/indicators/act", secret, url.Values{
		"do": {"add"}, "value": {"evil.example"}, "source": {"x"}}.Encode())
	if set.Len() != before || strings.HasPrefix(p.Header().Get("Location"), "/security/indicators") {
		t.Error("an author added an indicator")
	}
}
