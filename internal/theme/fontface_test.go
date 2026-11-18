// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"strings"
	"testing"
)

// A WOFF 1.0 face is announced as one.
//
// Every @font-face said format("woff2"), which was true while WOFF2 was all a
// site could serve. A browser told woff2 about a WOFF file skips the source
// as one it cannot read, and the page falls back without a word.
func TestAFaceIsAnnouncedInItsOwnFormat(t *testing.T) {
	th, problems := New(map[string]string{"font-body": "Aster"}, []Family{
		{Name: "Aster", Href: "/fonts/Aster-400-700.woff", Weight: "400 700", Style: "normal"},
		{Name: "Aster", Href: "/fonts/Aster-italic.woff2", Weight: "100 900", Style: "italic"},
	})
	if Blocks(problems) {
		t.Fatalf("%v", problems)
	}
	css := th.CSS()
	for _, want := range []string{
		`src: url("/fonts/Aster-400-700.woff") format("woff");`,
		`src: url("/fonts/Aster-italic.woff2") format("woff2");`,
		"font-weight: 400 700;",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("the stylesheet does not say %s", want)
		}
	}
}

// The same faces make the same stylesheet, whatever order they were found
// in, so a reload that compares stylesheets sees no change where there is
// none.
func TestTheSameFacesMakeTheSameStylesheet(t *testing.T) {
	faces := []Family{
		{Name: "Aster", Href: "/fonts/Aster-700.woff2", Weight: "700", Style: "normal"},
		{Name: "Aster", Href: "/fonts/Aster-300.woff2", Weight: "300", Style: "normal"},
		{Name: "Aster", Href: "/fonts/Aster-500.woff2", Weight: "500", Style: "normal"},
	}
	a, _ := New(nil, faces)
	reversed := []Family{faces[2], faces[1], faces[0]}
	b, _ := New(nil, reversed)
	if a.CSS() != b.CSS() {
		t.Error("the order the faces were found in changed the stylesheet")
	}
}
