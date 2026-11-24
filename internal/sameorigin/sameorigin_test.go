// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sameorigin

import (
	"net/http/httptest"
	"testing"
)

// An origin is this site's when its scheme, its host in any case and its
// port are, and nothing else about it counts.
func TestAnOriginIsTheSitesWhenItsSchemeHostAndPortAre(t *testing.T) {
	for _, c := range []struct {
		origin, own string
		same        bool
	}{
		{"https://site.example", "https://site.example", true},
		{"https://SITE.example", "https://site.example", true},
		{"HTTPS://site.example", "https://site.example", true},
		{"https://site.example:443", "https://site.example", true},
		{"http://site.example", "http://site.example:80", true},
		{"https://site.example", "https://site.example/blog/", true},
		{"http://localhost:19056", "http://localhost:19056", true},
		{"http://LOCALHOST:19056", "http://localhost:19056", true},
		{"https://site.example", "http://site.example", false},
		{"https://site.example:8443", "https://site.example", false},
		{"https://evil.example", "https://site.example", false},
		{"https://site.example.evil.example", "https://site.example", false},
		{"http://evil.example//site.example", "http://site.example", false},
		{"https://site.example/path", "https://site.example", false},
		{"https://user@site.example", "https://site.example", false},
		{"null", "https://site.example", false},
		{"", "https://site.example", false},
		{"https://site.example", "", false},
		{"ftp://site.example", "ftp://site.example", false},
	} {
		if got := Same(c.origin, c.own); got != c.same {
			t.Errorf("Same(%q, %q) = %v", c.origin, c.own, got)
		}
	}
}

// Every door's policy, as a table: what Sec-Fetch-Site and Origin together
// say, and what each policy makes of it.
func TestEachPolicySaysWhatItAdmits(t *testing.T) {
	const own = "http://h"
	admin := Policy{None: true, Missing: true}
	members := Policy{}
	tool := Policy{OriginOnly: true, Missing: true, Also: []string{"https://issuer.example"}}
	for _, c := range []struct {
		name, fetch, origin  string
		admin, members, tool bool
	}{
		{"same-origin, odd Origin", "same-origin", "null", true, true, false},
		{"same-origin, no Origin", "same-origin", "", true, true, true},
		{"a person typed it", "none", "", true, false, true},
		{"cross-site", "cross-site", "http://h", false, false, true},
		{"same-site", "same-site", "", false, false, true},
		{"a value no browser sends", "sideways", "http://h", false, false, true},
		{"no fetch metadata, own Origin", "", "http://h", true, true, true},
		{"no fetch metadata, own Origin in capitals", "", "http://H", true, true, true},
		{"no fetch metadata, another scheme", "", "https://h", false, false, false},
		{"no fetch metadata, foreign Origin", "", "https://evil.example", false, false, false},
		{"no fetch metadata, the issuer", "", "https://issuer.example", false, false, true},
		{"nothing said at all", "", "", true, false, true},
		{"a rebound page: same-origin to its browser", "same-origin", "http://evil.example", true, true, false},
	} {
		r := httptest.NewRequest("POST", "http://h/x", nil)
		if c.fetch != "" {
			r.Header.Set("Sec-Fetch-Site", c.fetch)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		for _, p := range []struct {
			name string
			pol  Policy
			want bool
		}{{"admin", admin, c.admin}, {"members", members, c.members}, {"tool", tool, c.tool}} {
			if got := Check(r, own, p.pol); got != p.want {
				t.Errorf("%s, under the %s policy: %v", c.name, p.name, got)
			}
		}
	}
}
