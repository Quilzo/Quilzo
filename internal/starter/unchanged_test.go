// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package starter

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/theme"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// What existing sites are served does not move unless they ask.
//
// Backdrops, card pictures, the neon style, the corner and scheme choices
// and the style layer were all added to the layouts and the stylesheet every
// site is already served. Each is opt-in, and the promise to the sites that
// do not opt in is that nothing about them changes: not the markup of a page,
// not a byte of the token block, not the style layers they chose. These are
// the hashes of what this release's predecessor produced for every shipped
// starter, every sample, every section stub and every style and motion, and
// they are the same now.
//
// A failure here means a page somebody published renders differently after
// an upgrade they did not ask anything of. If the change is deliberate — a
// fix, as the centred eyebrow was — it is named in its own test and taken out
// of what is compared here, as that one is below, rather than the hash being
// updated to whatever it has become.

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// pagesBefore are the rendered pages: each starter with its sample as written
// and as the renderer decorates it, and each section stub with its id pinned
// (an id is random, and would make the hash of a page that reads it random).
var pagesBefore = map[string]string{
	"decorated article":   "c6aba2260184b38b",
	"decorated catalogue": "e6c8d1351e741ccd",
	"decorated dashboard": "291d41695cc1b3a1",
	"decorated docs":      "9c4abb161604d571",
	"decorated landing":   "9da0e11367e4b7d1",
	"decorated portfolio": "d48f8328d02f38b2",
	"decorated sections":  "89a9f76ca439596c",
	"starter article":     "60d1cf0bc7956c46",
	"starter catalogue":   "c9507047b507b8a0",
	"starter dashboard":   "3defab89574d5996",
	"starter docs":        "5ed2b9c52285a22a",
	"starter landing":     "0b829e07fd9ac78d",
	"starter portfolio":   "3023edccde936d40",
	"starter sections":    "a3553ba688a9c276",
	"stub ask":            "3db1fd765b6f68a2",
	"stub bars":           "daf8d7c12562f63f",
	"stub booking":        "4f764441555e65b2",
	"stub carousel":       "1e034fdea140e6b8",
	"stub comments":       "2a180eb6903574ed",
	"stub cta":            "81521a98ad6a2d9b",
	"stub donuts":         "dbd78acb3a2bb9f8",
	"stub events":         "819d8ce5e6586153",
	"stub faq":            "78661cf0e06a3115",
	"stub features":       "5b4a2374238ae8ee",
	"stub gallery":        "f36104042a51406b",
	"stub listing":        "9e43fabacd12574d",
	"stub logos":          "e5eba8a62bef55e6",
	"stub metrics":        "a3e0dc0eb0109407",
	"stub newsletter":     "3905e8264fb3f487",
	"stub notice":         "ff5301f484aedd17",
	"stub people":         "2983ee77d8b2f228",
	"stub posts":          "271bb5d9cde128c7",
	"stub pricing":        "61d90f5f4f49fa57",
	"stub prose":          "5a4e1d12c79cd5ca",
	"stub quote":          "77d383b0f20e46f7",
	"stub quotes":         "4178381c8e65b132",
	"stub split":          "2aadf7ea89ba25c4",
	"stub steps":          "b0fcb600c579bd7b",
	"stub table":          "3d4403f6f89d5695",
	"stub tabs":           "70756a791cd3fb0c",
	"stub timeline":       "bd2e3655992eb00c",
	"stub video":          "c668a113b4522a85",
}

// cssBefore is the generated part of the stylesheet — tokens, the style's
// layer and the arrangement — for every style and motion a site could have
// chosen, and for each starter's own theme.
var cssBefore = map[string]string{
	"starter article":       "56b011664b14995d",
	"starter catalogue":     "ccf3434c8503c41a",
	"starter dashboard":     "f5d6a113b6fbfddd",
	"starter docs":          "1e425bd0664d8570",
	"starter landing":       "0b6e470a4764975c",
	"starter portfolio":     "e8a29f57932f6d0c",
	"starter sections":      "5834ef2473c572e7",
	"bold expressive":       "487a0a5739cd2004",
	"bold none":             "cf713decb5dc18f1",
	"bold subtle":           "4a02055a29de2311",
	"business expressive":   "df4dfd24c69adb6b",
	"business none":         "9bbc71e8e105c9b7",
	"business subtle":       "9bad304a841dbda9",
	"classic expressive":    "607d3ef9c8c88b6e",
	"classic none":          "24411a0c17bb6db7",
	"classic subtle":        "f057433ff6de87c2",
	"editorial expressive":  "0a1438c6d09a7a37",
	"editorial none":        "cc32676bbe541650",
	"editorial subtle":      "789bb77d24c6b50c",
	"expressive expressive": "ed9fbc24a9987bee",
	"expressive none":       "1e78a130042c490c",
	"expressive subtle":     "5834ef2473c572e7",
	"glass expressive":      "1987c7264fb1b4e1",
	"glass none":            "149b6da8ee39607a",
	"glass subtle":          "5587e168681a4344",
	"soft expressive":       "00b8c9a286947c75",
	"soft none":             "2e4e892a2fcfc1c1",
	"soft subtle":           "08f23fa95c1bd38c",
}

// componentsBefore is the shared component sheet as it was.
const componentsBefore = "a268ba1c2932eeac"

// centredEyebrow is the one deliberate change to it: the centred hero's chip.
const centredEyebrow = `/* The eyebrow of a centred hero is centred too. The rule above that keeps a
   chip from stretching into a bar sets align-self: start on every chip in a
   hero, and it beat the hero's own align-items, so a centred heading sat
   under a chip pinned to the left edge. */
.hero.hero-center > .chip { align-self: center; }
`

func TestExistingPagesRenderAsTheyDid(t *testing.T) {
	got := map[string]string{}
	for _, st := range All() {
		got["starter "+st.Name] = sum(render(t, st))
		src, err := st.HTML()
		if err != nil {
			t.Fatal(err)
		}
		out, err := tmpl.Render(src, map[string]any{"page": decorated(st.Sample), "site": siteContext()})
		if err != nil {
			t.Fatal(err)
		}
		got["decorated "+st.Name] = sum(out)
	}
	st, _ := Get("sections")
	layout, _ := st.HTML()
	for _, k := range section.Kinds() {
		body, err := section.Insert(map[string]any{"title": "A page"}, k.Name, 0)
		if err != nil {
			t.Fatal(err)
		}
		body[section.Field].([]any)[0].(map[string]any)[section.IDField] = "s1"
		out, err := tmpl.Render(layout, map[string]any{"page": decorated(body), "site": siteContext()})
		if err != nil {
			t.Fatal(err)
		}
		got["stub "+k.Name] = sum(out)
	}
	for name, want := range pagesBefore {
		if got[name] != want {
			t.Errorf("%s renders differently from before: %s, was %s", name, got[name], want)
		}
	}
	if len(got) < len(pagesBefore) {
		t.Errorf("only %d pages rendered against %d recorded", len(got), len(pagesBefore))
	}
}

// The other deliberate changes: motion none stops page transitions, and the
// components carry one page transition and one reduced-motion block where
// they carried two of each, the second transition after the block that
// switched it off (TestNothingMovesWhenMotionIsNone). And the meter's fill
// is scaled rather than sized (TestTheMeterMovesWithoutLayingThePageOut).
// Each is put back as it was before the hash is compared, so nothing else
// can have moved with them.
const (
	stilledNavigation = "@view-transition { navigation: none; }\n"
	transitionsNow    = `/* Page transitions, on a site that runs no script.

   The View Transitions API is usually reached by calling
   document.startViewTransition. This site sends script-src 'none', so that
   call never happens — but the cross-document form needs no call at all: two
   same-origin pages that both carry this at-rule transition between
   themselves, and the trigger is the navigation itself.

   Which makes it the rare case where the constraint costs nothing. Paired
   with the speculation rules this site already sends, a link followed on a
   static page behaves like one in an application, and neither half is a
   script.

   Chromium and Safari 18.2 do this today; a browser that does not simply
   navigates, which is what it did before.

   One rule, with only the reduced-motion block below and a site's motion
   setting after it. There were two, the second after that block, and the
   last @view-transition is the one a browser uses: a visitor who had asked
   for less motion was given navigation: auto again. */
@view-transition { navigation: auto; }

/* The header and footer stay put while the content changes, rather than
   cross-fading with it. Naming them is what makes the transition read as one
   page changing instead of two pages dissolving. */
.site-header { view-transition-name: site-header; }
.site-footer { view-transition-name: site-footer; }

/* Somebody who has asked for less motion is asking about all of it, and a
   page transition is animation: the setting is not advisory. The transition
   is switched off, and its pseudo-elements, which the universal selector
   does not reach, are stilled for a browser that starts one anyway. */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
  @view-transition { navigation: none; }
  ::view-transition-group(*),
  ::view-transition-old(*),
  ::view-transition-new(*) {
    animation: none !important;
  }
}

`
	transitionsBefore = `/* Cross-document transitions: same-origin navigation crossfades with no script
   at all. Browsers without it navigate normally. */
@view-transition { navigation: auto; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
  @view-transition { navigation: none; }
}

`
	// answerAnchor is where the second copy of the page transition was.
	answerAnchor     = "/* -- an answer above the search results"
	transitionsMoved = `/* Page transitions, on a site that runs no script.

   The View Transitions API is usually reached by calling
   document.startViewTransition. This site sends script-src 'none', so that
   call never happens — but the cross-document form needs no call at all: two
   same-origin pages that both carry this at-rule transition between
   themselves, and the trigger is the navigation itself.

   Which makes it the rare case where the constraint costs nothing. Paired
   with the speculation rules this site already sends, a link followed on a
   static page behaves like one in an application, and neither half is a
   script.

   Chromium and Safari 18.2 do this today; a browser that does not simply
   navigates, which is what it did before. */
@view-transition {
  navigation: auto;
}

/* The header and footer stay put while the content changes, rather than
   cross-fading with it. Naming them is what makes the transition read as one
   page changing instead of two pages dissolving. */
.site-header { view-transition-name: site-header; }
.site-footer { view-transition-name: site-footer; }

/* Somebody who has asked for less motion is asking about this.
   A transition is animation, and the setting is not advisory. */
@media (prefers-reduced-motion: reduce) {
  ::view-transition-group(*),
  ::view-transition-old(*),
  ::view-transition-new(*) {
    animation: none !important;
  }
}

`
	meterNote = `

   The fill is the bar's whole width, scaled from the start of the line: a
   change moves on the compositor, where animating width laid the page out
   again on every frame of it.`
	meterFillNow = `.bar > span {
  display: block; height: 100%;
  transform: scaleX(calc(clamp(0, var(--pct), 100) / 100));
  transform-origin: left;
  border-radius: inherit;
  background: var(--primary);
  transition: transform var(--dur) var(--ease);
}
.bar > span:dir(rtl) { transform-origin: right; }
`
	meterFillBefore = `.bar > span {
  display: block; height: 100%;
  width: calc(clamp(0, var(--pct), 100) * 1%);
  border-radius: inherit;
  background: var(--primary);
  transition: width var(--dur) var(--ease);
}
`
)

func TestExistingStylesAreGeneratedAsTheyWere(t *testing.T) {
	for _, style := range []string{"expressive", "classic", "glass", "editorial", "bold", "soft", "business"} {
		for _, motion := range theme.Motions {
			th, _ := theme.New(map[string]string{"style": style, "motion": motion}, nil)
			key := style + " " + motion
			css := strings.Replace(th.CSS()+th.Preset()+th.Responsive(), stilledNavigation, "", 1)
			if got := sum(css); got != cssBefore[key] {
				t.Errorf("the %s style with %s motion generates differently: %s, was %s", style, motion, got, cssBefore[key])
			}
		}
	}
	for _, st := range All() {
		th, _ := st.Theme()
		css := strings.Replace(th.CSS()+th.Preset()+th.Responsive(), stilledNavigation, "", 1)
		if got := sum(css); got != cssBefore["starter "+st.Name] {
			t.Errorf("the %s starter's theme generates differently: %s", st.Name, got)
		}
	}
}

// The components are what they were, with the opt-in rules after them and
// the centred eyebrow, the page transitions and the meter as the changes.
func TestTheComponentsOnlyGrew(t *testing.T) {
	c := Components()
	added := Backdrops()
	if !strings.HasSuffix(c, added) {
		t.Fatal("the opt-in rules are not appended after the components")
	}
	before := strings.TrimSuffix(c, added)
	for name, now := range map[string]string{"the centred eyebrow's rule": centredEyebrow,
		"the page transition": transitionsNow, "the meter's note": meterNote, "the meter's fill": meterFillNow} {
		if strings.Count(before, now) != 1 {
			t.Fatalf("%s is not where this test expects it", name)
		}
	}
	before = strings.Replace(before, centredEyebrow, "", 1)
	before = strings.Replace(before, transitionsNow, transitionsBefore, 1)
	before = strings.Replace(before, answerAnchor, transitionsMoved+answerAnchor, 1)
	before = strings.Replace(before, meterNote, "", 1)
	before = strings.Replace(before, meterFillNow, meterFillBefore, 1)
	if got := sum(before); got != componentsBefore {
		t.Errorf("the shared components changed beyond the centred eyebrow, the page transitions and the meter: %s", got)
	}
}

// Every rule the opt-in sheet adds selects a class only a page that asked
// for a backdrop or a card picture carries, so no other page is restyled.
func TestTheOptInRulesTouchOnlyWhatOptsIn(t *testing.T) {
	optIn := regexp.MustCompile(`\.(has-backdrop|surface-media|backdrop|backdrop-stop|backdrop-stop-label|card-media)\b`)
	css := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(Backdrops(), "")
	for _, sel := range regexp.MustCompile(`([^{}]+)\{[^{}]*\}`).FindAllStringSubmatch(css, -1) {
		head := strings.TrimSpace(sel[1])
		if strings.HasPrefix(head, "@") {
			continue
		}
		for _, one := range strings.Split(head, ",") {
			if one = strings.TrimSpace(one); one != "" && !optIn.MatchString(one) {
				t.Errorf("%q in the opt-in rules selects something every page has", one)
			}
		}
	}
}

// The veil's fallbacks are the tokens' own defaults: a site that never set
// them is not written them, and gets what the contrast check assumed.
func TestTheVeilFallsBackToTheDefaultsTheCheckUses(t *testing.T) {
	strength, _ := theme.Lookup("scrim-strength")
	b := Backdrops()
	if !strings.Contains(b, "var(--scrim-strength, "+strength.Light+")") {
		t.Errorf("the veil's strength falls back to something other than %s", strength.Light)
	}
	if !strings.Contains(b, "var(--scrim, var(--surface))") || strings.Contains(b, "var(--scrim)") {
		t.Error("the veil's colour does not fall back to the page background, which is what it follows")
	}
}

// B2: in a centred hero the eyebrow is centred with everything else.
func TestACentredHerosEyebrowIsCentred(t *testing.T) {
	c := Components()
	at := strings.Index(c, ".hero.hero-center > .chip { align-self: center; }")
	pinned := strings.Index(c, ".hero > .chip, .stack > .chip { align-self: start; }")
	if pinned < 0 {
		pinned = strings.Index(c, ".hero > .chip")
	}
	if at < 0 || pinned < 0 || at < pinned {
		t.Fatalf("the centred hero's chip is not centred after the rule that pins chips: %d, %d", at, pinned)
	}
}
