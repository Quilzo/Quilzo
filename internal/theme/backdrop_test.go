// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"strings"
	"testing"
)

// The worst case is the veil over the picture least like it: over black for
// a light veil under dark text, over white for a dark veil under light text.
func TestTheWorstPictureUnderAVeilIsComputed(t *testing.T) {
	// A full veil is the veil.
	if got, want := WorstOver("#000000", "#ffffff", 1), Contrast("#000000", "#ffffff"); got < want-0.01 || got > want+0.01 {
		t.Errorf("a full veil: %.2f, want %.2f", got, want)
	}
	// No veil at all: some picture is the text's own colour.
	if got := WorstOver("#000000", "#ffffff", 0); got != 1 {
		t.Errorf("no veil: %.2f, want 1", got)
	}
	// A light veil at 82% under near-black text: the worst is over black.
	worst := WorstOver("#1a1c1d", "#f8f9fa", 0.82)
	overBlack := Contrast("#1a1c1d", mixHex("#000000", "#f8f9fa", 0.82))
	if worst > overBlack+0.05 || worst < overBlack-0.05 {
		t.Errorf("worst %.2f, over black %.2f", worst, overBlack)
	}
}

// The shipped palette is readable over any backdrop in both schemes, and a
// weak veil is refused with the setting that fixes it named.
func TestAWeakVeilIsRefused(t *testing.T) {
	th, _ := New(nil, nil)
	if f := th.CheckBackdrop(); Blocks(f) {
		t.Fatalf("the shipped veil fails: %v", f)
	}
	weak, problems := New(map[string]string{"scrim-strength": "30%"}, nil)
	if Blocks(problems) {
		t.Fatal(problems)
	}
	f := weak.CheckBackdrop()
	if !Blocks(f) || !strings.Contains(f[0].Detail, "scrim-strength") {
		t.Errorf("a 30%% veil passed: %v", f)
	}
	// It does not touch the ordinary check: a site with no backdrop is not
	// refused over a veil it never draws.
	if Blocks(weak.Check()) {
		t.Error("a weak veil failed the ordinary check")
	}
}

// The veil is the page background until somebody chooses another, and it
// follows the background when that changes.
func TestTheVeilFollowsTheBackground(t *testing.T) {
	th, _ := New(map[string]string{"surface.dark": "#07050d"}, nil)
	if v, set := th.Value("scrim", true); v != "#07050d" || set {
		t.Errorf("the dark veil is %q (set %v)", v, set)
	}
	own, _ := New(map[string]string{"scrim": "#000000"}, nil)
	if v, _ := own.Value("scrim", false); v != "#000000" {
		t.Errorf("a chosen veil is %q", v)
	}
	for _, bad := range []string{"82", "120%", "-1%", "1rem"} {
		if _, problems := New(map[string]string{"scrim-strength": bad}, nil); !Blocks(problems) {
			t.Errorf("scrim-strength %q was accepted", bad)
		}
	}
	for _, bad := range []string{"10%", "5ch", "-2px", "100px", "5rem"} {
		if _, problems := New(map[string]string{"glow": bad}, nil); !Blocks(problems) {
			t.Errorf("glow %q was accepted", bad)
		}
	}
}

// The opt-in tokens are written only when set, so a site that set none of
// them is served the token block it had before they existed.
func TestOptInTokensAreWrittenOnlyWhenSet(t *testing.T) {
	th, _ := New(map[string]string{"primary": "#0b4f6c"}, nil)
	for name := range optIn {
		if strings.Contains(th.CSS(), "--"+name+":") {
			t.Errorf("--%s was written for a site that never set it", name)
		}
	}
	set, _ := New(map[string]string{"scrim": "#101010", "scrim-strength": "90%"}, nil)
	css := set.CSS()
	if !strings.Contains(css, "--scrim: #101010;") || !strings.Contains(css, "--scrim-strength: 90%;") {
		t.Errorf("a set opt-in token was not written:\n%s", css)
	}
}

// Everything a page sets on its background is judged over the veil, not only
// the body text.
//
// A section drawn over a backdrop keeps its standfirst, its captions and its
// quotes in the secondary text colour and its eyebrow in the accent, straight
// on the veil. Only the body text was judged there, so a mid-grey secondary
// colour — 5.56:1 on the page, which every check passes, and 3.65:1 over the
// shipped veil laid on black — published a standfirst nobody could read,
// with the check saying the words over the picture were fine.
func TestSecondaryTextOverAVeilIsJudged(t *testing.T) {
	th, problems := New(map[string]string{"on-surface-variant.light": "#5e666a"}, nil)
	if Blocks(problems) || Blocks(th.Check()) {
		t.Fatalf("the palette is meant to pass on the page: %v %v", problems, th.Check())
	}
	veil, _ := th.Value("scrim", false)
	body, _ := th.Value("on-surface", false)
	if WorstOver(body, veil, 0.82) < 4.5 || WorstOver("#5e666a", veil, 0.82) >= 4.5 {
		t.Fatalf("the fixture no longer separates the two: body %.2f, secondary %.2f",
			WorstOver(body, veil, 0.82), WorstOver("#5e666a", veil, 0.82))
	}
	f := th.CheckBackdrop()
	named := false
	for _, x := range f {
		if x.Blocking && strings.Contains(x.Detail, "on-surface-variant") {
			named = true
		}
	}
	if !named {
		t.Errorf("secondary text below 4.5:1 over the veil passed: %v", f)
	}
}
