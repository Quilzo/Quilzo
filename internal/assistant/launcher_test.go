// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"strings"
	"testing"
)

func withLauncher(l Launcher) Assistant {
	return Assistant{Name: "help", Title: "Help", Public: true, Launcher: &l}
}

func TestALauncherIsCheckedLikeEverythingElse(t *testing.T) {
	if err := withLauncher(Launcher{Style: "pill", Side: "left", Panel: "side", Label: "Ask us",
		Suggestions: []string{"Shipping?", "Returns?"}, Nudge: "Questions about pricing?", NudgeAfter: 30,
		Pages: []string{"/docs"}, NudgePages: []string{"/pricing"}}).Validate(); err != nil {
		t.Fatalf("a good launcher: %v", err)
	}
	for name, l := range map[string]Launcher{
		"a style":         {Style: "popup"},
		"a side":          {Side: "top"},
		"a panel":         {Panel: "modal"},
		"a long label":    {Label: strings.Repeat("a", MaxLauncherLabel+1)},
		"five questions":  {Suggestions: []string{"a", "b", "c", "d", "e"}},
		"a long question": {Suggestions: []string{strings.Repeat("q", MaxSuggestionLen+1)}},
		"an empty one":    {Suggestions: []string{"  "}},
		"a long nudge":    {Nudge: strings.Repeat("n", MaxNudgeLen+1)},
		"an instant one":  {Nudge: "hi", NudgeAfter: 1},
		"a relative page": {Pages: []string{"docs"}},
		"a page climbing": {Pages: []string{"/docs/../admin"}},
	} {
		if err := withLauncher(l).Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	private := withLauncher(Launcher{})
	private.Public = false
	if err := private.Validate(); err == nil {
		t.Error("a launcher for an assistant the site does not serve was accepted")
	}
}

func TestALauncherKeepsToItsPagesAndTheNudgeToItsOwn(t *testing.T) {
	l := Launcher{Pages: []string{"/docs"}, Nudge: "Stuck?", NudgePages: []string{"/docs/start"}}
	for path, want := range map[string][2]bool{
		"/docs": {true, false}, "/docs/start": {true, true}, "/docs/start/install": {true, true},
		"/docsearch": {false, false}, "/": {false, false},
	} {
		if l.On(path) != want[0] || l.NudgeOn(path) != want[1] {
			t.Errorf("%s: on %v nudge %v, want %v", path, l.On(path), l.NudgeOn(path), want)
		}
	}
	if (Launcher{}).NudgeOn("/") {
		t.Error("a launcher with no nudge written nudges")
	}
	if n := (Launcher{}).Normalised(); n.Style != "bubble" || n.Side != "right" || n.Panel != "float" || n.Label != "Ask" || n.NudgeAfter != 20 {
		t.Errorf("defaults %+v", n)
	}
}

// One button per site: two would compete for the same corner.
func TestASiteHasOneLauncher(t *testing.T) {
	s := &Set{}
	if err := s.Put(withLauncher(Launcher{})); err != nil {
		t.Fatal(err)
	}
	other := withLauncher(Launcher{})
	other.Name = "sales"
	if err := s.Put(other); err == nil {
		t.Error("a second launcher was accepted")
	}
	// The same assistant changing its own is fine.
	if err := s.Put(withLauncher(Launcher{Style: "tab"})); err != nil {
		t.Errorf("an assistant could not change its own launcher: %v", err)
	}
	if a, ok := s.Launcher(); !ok || a.Name != "help" || a.Launcher.Style != "tab" {
		t.Errorf("the launcher is %+v", a)
	}
}
