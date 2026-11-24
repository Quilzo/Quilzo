// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/standing"
)

// The manual names the standing authority a situational power rests on, and
// it is the one the register names.
//
// The passage on the two kinds of authority said that a power which
// survives its situation "lands on publish". That was true of the room's
// moderator, who took down somebody else's words. Rooms have left Quilzo,
// and the one role left that reaches outside its situation is an enrolment
// link, which rests on grant: so the sentence named an authority no
// situational role here asks for, next to an example that asks for another.
//
// The passage sets the name of an authority in bold. Those names are
// compared with what the register's own escalations need, both ways: every
// authority one of them needs is named, and none is named that nothing
// needs.
func TestTheManualNamesTheAuthorityASituationalPowerRestsOn(t *testing.T) {
	manual := read(t, "docs/cms.md")
	start := strings.Index(manual, "**Two kinds of authority")
	if start < 0 {
		t.Fatal("docs/cms.md has no passage on the two kinds of authority")
	}
	passage := manual[start:]
	// The passage runs to the next one, which opens a paragraph in bold as
	// this one does.
	if end := strings.Index(passage[2:], "\n\n**"); end > 0 {
		passage = passage[:end+2]
	}

	needed := map[string]bool{}
	for _, role := range standing.Escalations() {
		for _, p := range role.Powers {
			if p.Outside {
				needed[string(p.Needs)] = true
			}
		}
	}
	if len(needed) == 0 {
		t.Skip("no situational role reaches outside its situation, so the manual has no authority to name")
	}

	// One word in bold, in lower case, is the name of an authority; a
	// sentence in bold is emphasis and is not looked at.
	named := map[string]bool{}
	for _, m := range regexp.MustCompile(`\*\*([a-z][a-z-]*)\*\*`).FindAllStringSubmatch(passage, -1) {
		named[m[1]] = true
	}
	for _, action := range sorted(needed) {
		if !named[action] {
			t.Errorf("a situational role here rests on %q, and the manual's passage on "+
				"situational authority does not name it (it names %s)",
				action, strings.Join(sorted(named), ", "))
		}
	}
	for _, action := range sorted(named) {
		if !needed[action] {
			t.Errorf("the manual says a power that outlives its situation rests on %q, "+
				"and no situational role in the register asks for it (they ask for %s)",
				action, strings.Join(sorted(needed), ", "))
		}
	}
}

// sorted is the keys of a set in order, so that a failure reads the same
// way twice.
func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
