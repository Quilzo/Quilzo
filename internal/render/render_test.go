// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package render

import "testing"

// An icon that is the name's first letter is set in its place.
func TestAnInitialIconTakesTheFirstLettersPlace(t *testing.T) {
	site := func(s Sources) map[string]any {
		ctx, err := s.For("index", map[string]any{"title": "Home"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return ctx["site"].(map[string]any)
	}
	got := site(Sources{Name: "Quilzo", Icon: "/media/x", IconInitial: true})
	if got["icon_initial"] != true || got["name_rest"] != "uilzo" || got["name_whole"] != false {
		t.Errorf("with the icon as the initial: %v", got)
	}
	// Not asked, no icon, or a name of one letter: the name is whole.
	for _, s := range []Sources{
		{Name: "Quilzo", Icon: "/media/x"},
		{Name: "Quilzo", IconInitial: true},
		{Name: "Q", Icon: "/media/x", IconInitial: true},
	} {
		if got := site(s); got["name_whole"] != true || got["icon_initial"] != nil {
			t.Errorf("%+v gave %v", s, got)
		}
	}
	// A name that does not start with an ASCII letter is cut at a whole
	// character, not a byte.
	if got := site(Sources{Name: "Ölwerk", Icon: "/media/x", IconInitial: true}); got["name_rest"] != "lwerk" {
		t.Errorf("name_rest is %q", got["name_rest"])
	}
}
