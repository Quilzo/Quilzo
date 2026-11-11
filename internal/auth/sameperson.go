// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import "strings"

// SamePerson reports whether two names are one person's: the rule every
// second-person check asks, wherever it is.
//
// Policy decisions compare names exactly and people do not: "Dana" and
// "dana " are two principals to Evaluate and one person to anybody asked,
// which is what a single sign-on subject or an email address arriving in
// another case is. The checks that a second pair of eyes is somebody else
// each had a rule of their own. A privileged request compared without case
// (internal/dual), a shield playbook change, a policy proposal and a
// content review compared exactly, and the access review trimmed and
// folded, so "dana" approved "Dana"'s playbook change and her review as
// the second person while her grant was refused. The comparison here is
// the loose one, which can only refuse more. A name that is nobody's is
// nobody in particular.
func SamePerson(a, b string) bool {
	a = PersonKey(a)
	return a != "" && a == PersonKey(b)
}

// PersonKey is a name as SamePerson compares it: without the spaces around
// it, its case or a mailto: in front. For keying one person's things
// together, as counting one approval each does.
func PersonKey(s string) string {
	s, _ = strings.CutPrefix(strings.ToLower(strings.TrimSpace(s)), "mailto:")
	return s
}
