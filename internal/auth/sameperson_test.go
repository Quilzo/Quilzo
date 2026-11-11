// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import "testing"

// The proposer is recognised whatever the case of their name, the spaces
// around it or a mailto: in front, and a name that is nobody's is nobody
// in particular.
func TestTheProposerIsRecognisedWhateverTheCaseOfTheirName(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"dana", "dana", true},
		{"Dana", "dana", true},
		{" Dana ", "mailto:dana", true},
		{"MAILTO:Dana@Example.com", "dana@example.com", true},
		{"dana", "lee", false},
		{"dana", "dana2", false},
		{"", "", false},
		{"dana", "", false},
	} {
		if got := SamePerson(c.a, c.b); got != c.same {
			t.Errorf("SamePerson(%q, %q) = %v", c.a, c.b, got)
		}
		if got := SamePerson(c.b, c.a); got != c.same {
			t.Errorf("SamePerson(%q, %q) = %v", c.b, c.a, got)
		}
	}
}
