// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package personalise serves a different version of a page to visitors who
// match declared conditions, using only what the request itself says.
//
// # What it looks at, and what it refuses to
//
// dotCMS's rules engine and every marketing suite personalise on a profile:
// what this visitor did last week, what segment a tracker put them in, where
// a geolocation database thinks they are. All of it needs either a cookie
// and a consent banner or a database of people. This uses what arrives with
// the request and nothing else: the campaign in the link, the site that sent
// them, the language their browser asks for, whether it is a phone, the day
// and the hour. That covers the cases people actually build — the newsletter
// landing page, the partner's referral page, the page in the visitor's own
// language, the out-of-hours contact page — without knowing who anybody is.
//
// A rule is data: conditions and a page. The first rule whose conditions all
// hold is used; with none, the page is itself. A rule's page is another
// published page, the same mechanism experiments use, so a personalised
// version is edited, reviewed and published like any page.
package personalise

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // rule timezones resolve the same on every host

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Field is what a condition reads from the request.
type Field string

const (
	Campaign Field = "campaign" // utm_source
	Referrer Field = "referrer" // the referring site's host
	Language Field = "language" // the browser's first preferred language
	Device   Field = "device"   // "phone" or "desktop"
	Weekday  Field = "weekday"  // "mon" … "sun", in the rule's timezone
	Hour     Field = "hour"     // 0–23, in the rule's timezone
	Param    Field = "param"    // a query parameter, named by Name
)

// Condition is one test. Values are alternatives: any one matching is a
// match. For Hour, values are ranges like "9-17".
type Condition struct {
	Field  Field    `json:"field"`
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values"`
}

// Rule serves Variant at Page when every condition holds.
type Rule struct {
	Name     string      `json:"name"`
	Page     string      `json:"page"`
	Variant  string      `json:"variant"`
	When     []Condition `json:"when"`
	Timezone string      `json:"timezone,omitempty"`
	Enabled  bool        `json:"enabled"`
}

var (
	reName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	rePage  = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{0,200}$`)
	reParam = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	reHour  = regexp.MustCompile(`^(\d{1,2})-(\d{1,2})$`)
	days    = map[string]time.Weekday{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
)

// Validate refuses a rule that could not be evaluated.
func (r Rule) Validate() error {
	if !reName.MatchString(r.Name) {
		return fmt.Errorf("%q is not a usable rule name", r.Name)
	}
	if !rePage.MatchString(r.Page) || !rePage.MatchString(r.Variant) || r.Page == r.Variant {
		return fmt.Errorf("rule %s needs a page and a different page to serve there", r.Name)
	}
	if len(r.When) == 0 || len(r.When) > 6 {
		return fmt.Errorf("rule %s has %d conditions; between 1 and 6 — a rule "+
			"with none would serve the variant to everybody, which is an edit", r.Name, len(r.When))
	}
	if r.Timezone != "" {
		if _, err := time.LoadLocation(r.Timezone); err != nil {
			return fmt.Errorf("rule %s: %q is not a timezone", r.Name, r.Timezone)
		}
	}
	for _, c := range r.When {
		if len(c.Values) == 0 || len(c.Values) > 20 {
			return fmt.Errorf("rule %s: a %s condition needs between 1 and 20 values", r.Name, c.Field)
		}
		for _, v := range c.Values {
			if strings.TrimSpace(v) == "" || len(v) > 100 {
				return fmt.Errorf("rule %s: a %s value is empty or too long", r.Name, c.Field)
			}
		}
		switch c.Field {
		case Campaign, Referrer, Language:
		case Device:
			for _, v := range c.Values {
				if v != "phone" && v != "desktop" {
					return fmt.Errorf("rule %s: device is phone or desktop", r.Name)
				}
			}
		case Weekday:
			for _, v := range c.Values {
				if _, ok := days[v]; !ok {
					return fmt.Errorf("rule %s: %q is not a day (mon … sun)", r.Name, v)
				}
			}
		case Hour:
			for _, v := range c.Values {
				m := reHour.FindStringSubmatch(v)
				if m == nil {
					return fmt.Errorf("rule %s: hours are ranges like 9-17", r.Name)
				}
				a, _ := strconv.Atoi(m[1])
				b, _ := strconv.Atoi(m[2])
				if a > 23 || b > 24 || a >= b {
					return fmt.Errorf("rule %s: %q is not a range of hours", r.Name, v)
				}
			}
		case Param:
			if !reParam.MatchString(c.Name) {
				return fmt.Errorf("rule %s: a param condition names the parameter", r.Name)
			}
		default:
			return fmt.Errorf("rule %s: %q is not something a rule can look at", r.Name, c.Field)
		}
	}
	return nil
}

// Matches reports whether a request meets every condition.
func (r Rule) Matches(req *http.Request, now time.Time) bool {
	loc := time.UTC
	if r.Timezone != "" {
		if l, err := time.LoadLocation(r.Timezone); err == nil {
			loc = l
		}
	}
	local := now.In(loc)
	for _, c := range r.When {
		if !c.holds(req, local) {
			return false
		}
	}
	return true
}

func (c Condition) holds(req *http.Request, local time.Time) bool {
	var got string
	switch c.Field {
	case Campaign:
		got = strings.ToLower(req.URL.Query().Get("utm_source"))
	case Referrer:
		if u, err := url.Parse(req.Referer()); err == nil {
			got = strings.ToLower(u.Hostname())
		}
		// A value matches the host or any subdomain of it.
		for _, v := range c.Values {
			v = strings.ToLower(v)
			if got != "" && (got == v || strings.HasSuffix(got, "."+v)) {
				return true
			}
		}
		return false
	case Language:
		got = firstLanguage(req.Header.Get("Accept-Language"))
		for _, v := range c.Values {
			v = strings.ToLower(v)
			// "en" matches en-GB; "en-gb" matches only en-GB.
			if got == v || strings.HasPrefix(got, v+"-") {
				return true
			}
		}
		return false
	case Device:
		got = "desktop"
		if phone(req) {
			got = "phone"
		}
	case Weekday:
		for _, v := range c.Values {
			if days[v] == local.Weekday() {
				return true
			}
		}
		return false
	case Hour:
		for _, v := range c.Values {
			m := reHour.FindStringSubmatch(v)
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			if h := local.Hour(); h >= a && h < b {
				return true
			}
		}
		return false
	case Param:
		got = strings.ToLower(req.URL.Query().Get(c.Name))
	}
	for _, v := range c.Values {
		if got != "" && got == strings.ToLower(v) {
			return true
		}
	}
	return false
}

func firstLanguage(h string) string {
	first, _, _ := strings.Cut(h, ",")
	first, _, _ = strings.Cut(first, ";")
	return strings.ToLower(strings.TrimSpace(first))
}

// phone is the User-Agent Client Hint when the browser sends one — Chromium
// sends Sec-CH-UA-Mobile on every request — and the user agent's own word
// for it otherwise.
func phone(req *http.Request) bool {
	switch req.Header.Get("Sec-CH-UA-Mobile") {
	case "?1":
		return true
	case "?0":
		return false
	}
	ua := req.UserAgent()
	return strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") ||
		strings.Contains(ua, "iPhone")
}

// Set is every rule a site declares, in the order they are tried.
type Set struct {
	Rules []Rule `json:"rules"`
}

// For returns the first enabled rule on a page that the request matches.
func (s *Set) For(page string, req *http.Request, now time.Time) (Rule, bool) {
	for _, r := range s.Rules {
		if r.Enabled && r.Page == page && r.Matches(req, now) {
			return r, true
		}
	}
	return Rule{}, false
}

// Put adds or replaces a rule, keeping its place in the order.
func (s *Set) Put(r Rule) error {
	if err := r.Validate(); err != nil {
		return err
	}
	for i := range s.Rules {
		if s.Rules[i].Name == r.Name {
			s.Rules[i] = r
			return nil
		}
	}
	s.Rules = append(s.Rules, r)
	return nil
}

// Remove deletes a rule.
func (s *Set) Remove(name string) bool {
	for i := range s.Rules {
		if s.Rules[i].Name == name {
			s.Rules = append(s.Rules[:i], s.Rules[i+1:]...)
			return true
		}
	}
	return false
}

// Get finds a rule.
func (s *Set) Get(name string) (Rule, bool) {
	for _, r := range s.Rules {
		if r.Name == name {
			return r, true
		}
	}
	return Rule{}, false
}

// Load reads a set; missing is empty.
func Load(path string) (*Set, error) {
	s := &Set{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s is not a set of rules: %w", path, err)
	}
	for _, r := range s.Rules {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return s, nil
}

// Save writes a set.
func Save(path string, s *Set) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// SeenKey is the analytics goal a rule's exposures are counted under.
func SeenKey(rule string) string { return "rule/" + rule + "/seen" }
