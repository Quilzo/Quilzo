// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package personalise

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func req(url string, headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", url, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// A Tuesday, 20:30 UTC.
var tuesday = time.Date(2026, 9, 29, 20, 30, 0, 0, time.UTC)

func rule(c ...Condition) Rule {
	return Rule{Name: "r", Page: "home", Variant: "home-b", When: c, Enabled: true}
}

func TestEachConditionReadsTheRequest(t *testing.T) {
	cases := []struct {
		name string
		c    Condition
		r    *http.Request
		want bool
	}{
		{"campaign", Condition{Field: Campaign, Values: []string{"newsletter"}}, req("/?utm_source=Newsletter", nil), true},
		{"campaign other", Condition{Field: Campaign, Values: []string{"newsletter"}}, req("/?utm_source=ads", nil), false},
		{"referrer subdomain", Condition{Field: Referrer, Values: []string{"partner.example"}}, req("/", map[string]string{"Referer": "https://shop.partner.example/x"}), true},
		{"referrer lookalike", Condition{Field: Referrer, Values: []string{"partner.example"}}, req("/", map[string]string{"Referer": "https://evilpartner.example/"}), false},
		{"language family", Condition{Field: Language, Values: []string{"de"}}, req("/", map[string]string{"Accept-Language": "de-AT,de;q=0.9,en;q=0.5"}), true},
		{"language not first", Condition{Field: Language, Values: []string{"en"}}, req("/", map[string]string{"Accept-Language": "de-AT,en;q=0.5"}), false},
		{"phone by hint", Condition{Field: Device, Values: []string{"phone"}}, req("/", map[string]string{"Sec-CH-UA-Mobile": "?1"}), true},
		{"desktop hint beats UA", Condition{Field: Device, Values: []string{"phone"}}, req("/", map[string]string{"Sec-CH-UA-Mobile": "?0", "User-Agent": "Android Mobile"}), false},
		{"weekday", Condition{Field: Weekday, Values: []string{"tue"}}, req("/", nil), true},
		{"hours", Condition{Field: Hour, Values: []string{"9-17"}}, req("/", nil), false},
		{"param", Condition{Field: Param, Name: "ref", Values: []string{"spring"}}, req("/?ref=SPRING", nil), true},
		{"missing campaign", Condition{Field: Campaign, Values: []string{"x"}}, req("/", nil), false},
	}
	for _, c := range cases {
		if got := rule(c.c).Matches(c.r, tuesday); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestATimezoneMovesTheHour(t *testing.T) {
	r := rule(Condition{Field: Hour, Values: []string{"0-6"}}, Condition{Field: Weekday, Values: []string{"wed"}})
	r.Timezone = "Asia/Kathmandu" // 20:30 UTC Tuesday is 02:15 Wednesday
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if !r.Matches(req("/", nil), tuesday) {
		t.Fatal("the rule's timezone was not applied")
	}
}

func TestTheFirstMatchingRuleWins(t *testing.T) {
	s := &Set{}
	a := rule(Condition{Field: Campaign, Values: []string{"newsletter"}})
	a.Name, a.Variant = "news", "home-news"
	b := rule(Condition{Field: Device, Values: []string{"phone", "desktop"}})
	b.Name, b.Variant = "all", "home-any"
	off := rule(Condition{Field: Campaign, Values: []string{"newsletter"}})
	off.Name, off.Enabled = "off", false
	for _, x := range []Rule{off, a, b} {
		if err := s.Put(x); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.For("home", req("/?utm_source=newsletter", nil), tuesday); got.Name != "news" {
		t.Fatalf("got %s", got.Name)
	}
	if got, _ := s.For("home", req("/", nil), tuesday); got.Name != "all" {
		t.Fatalf("got %s", got.Name)
	}
	if _, ok := s.For("about", req("/", nil), tuesday); ok {
		t.Fatal("a rule applied to another page")
	}
}

func TestRulesAreChecked(t *testing.T) {
	for name, r := range map[string]Rule{
		"no conditions": {Name: "r", Page: "a", Variant: "b"},
		"same page":     rule(Condition{Field: Campaign, Values: []string{"x"}}),
		"bad day":       rule(Condition{Field: Weekday, Values: []string{"funday"}}),
		"bad hours":     rule(Condition{Field: Hour, Values: []string{"17-9"}}),
		"bad device":    rule(Condition{Field: Device, Values: []string{"tablet"}}),
		"bad field":     rule(Condition{Field: "cookie", Values: []string{"x"}}),
		"bad tz":        {Name: "r", Page: "a", Variant: "b", Timezone: "Mars/Olympus", When: []Condition{{Field: Campaign, Values: []string{"x"}}}},
		"param no name": rule(Condition{Field: Param, Values: []string{"x"}}),
	} {
		if name == "same page" {
			r.Variant = r.Page
		}
		if r.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
