// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package config

import (
	"strings"
	"testing"
)

// A crawl term is checked when it is set, not when the server starts.
//
// `quilzo config set licence.permits ai-training-with-attribution` used to
// report success, write the value, and leave a site whose public server refused
// to start — the vocabulary was enforced at boot and nowhere else. A command
// that says it worked and produces a server that will not run is worse than a
// refusal, which is the same reasoning that put the brand-colour check here.
func TestALicenceTermIsRefusedWhereItIsSet(t *testing.T) {
	for _, key := range []string{"licence.permits", "licence.prohibits"} {
		s, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s is not a setting", key)
		}
		if err := s.Validate("ai-training-with-attribution"); err == nil {
			t.Errorf("%s accepted a use outside the vocabulary; the public "+
				"server will refuse to start on this value", key)
		}
		for _, good := range []string{"search", "search,train", "none",
			"search, ai-summarize", ""} {
			if err := s.Validate(good); err != nil {
				t.Errorf("%s refused %q, which is in the vocabulary: %v",
					key, good, err)
			}
		}
	}
}

// A security contact is a URI, checked when it is set. A bare address was
// accepted, published as a security.txt Contact line nothing can use, and
// skipped by the automations that mail the security team.
func TestASecurityContactIsAURI(t *testing.T) {
	s, ok := Lookup("security.contact")
	if !ok {
		t.Fatal("security.contact is not a setting")
	}
	for _, bad := range []string{"security@example.com", "mailto:",
		"mailto:sec@example.com, sec2@example.com", "ftp://example.com",
		"javascript:alert(1)"} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%q was accepted as a security contact", bad)
		}
	}
	for _, good := range []string{"", "mailto:security@example.com",
		"MAILTO:security@example.com", "https://example.com/report",
		"mailto:a@example.com, https://example.com/report, tel:+44-20-7946-0000"} {
		if err := s.Validate(good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

// The origin trial token is sent as a response header, so nothing but a
// token's own characters may be set: a line break would start a header of
// whoever set it's choosing.
func TestAnOriginTrialTokenCannotCarryAHeader(t *testing.T) {
	s, ok := Lookup("site.webmcp_trial")
	if !ok {
		t.Fatal("site.webmcp_trial is not a setting")
	}
	for _, bad := range []string{"abc\r\nSet-Cookie: x=1", "abc def", "abc;", strings.Repeat("a", 2049)} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if err := s.Validate("AqZ1abcDEF+/="); err != nil {
		t.Errorf("a token was refused: %v", err)
	}
}
