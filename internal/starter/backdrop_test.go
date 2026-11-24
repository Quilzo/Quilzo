// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package starter

import (
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
	renderpkg "github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/tmpl"
)

var (
	halo  = strings.Repeat("a", 64)
	loop  = strings.Repeat("b", 64)
	still = strings.Repeat("c", 64)
	talk  = strings.Repeat("d", 64)
)

// library answers as the media library would: a picture, a silent loop with
// a still, and a talk with sound.
func library() renderpkg.Sources {
	return renderpkg.Sources{
		Name: "Nyxvale",
		Media: func(id string) (renderpkg.MediaInfo, bool) {
			switch id {
			case halo, still:
				return renderpkg.MediaInfo{Kind: "image", Alt: "A neon halo"}, true
			case loop:
				return renderpkg.MediaInfo{Kind: "video", SoundKnown: true, Alt: "Violet light drifting over a neon grid"}, true
			case talk:
				return renderpkg.MediaInfo{Kind: "video", Sound: true, SoundKnown: true, Alt: "A talk"}, true
			}
			return renderpkg.MediaInfo{}, false
		},
		Poster: func(id string) string {
			if id == loop || id == talk {
				return "/media/" + still
			}
			return ""
		},
		SrcSet: func(id string) string {
			if id == halo || id == still {
				return "/media/" + id + "-960 960w"
			}
			return ""
		},
	}
}

func silent(src string) (bool, bool) {
	switch strings.TrimPrefix(src, "/media/") {
	case loop:
		return false, true
	case talk:
		return true, true
	}
	return false, false
}

func renderThrough(t *testing.T, body map[string]any) string {
	t.Helper()
	st, _ := Get("sections")
	layout, err := st.HTML()
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := library().For("index", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tmpl.Render(layout, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// G2: a moving backdrop behind the hero carries every safeguard the spec
// names, in the markup a reader is served — and the gate, told the loop is
// silent, passes it.
func TestAMovingBackdropCarriesItsSafeguards(t *testing.T) {
	out := renderThrough(t, map[string]any{"title": "Games for after dark",
		"hero": map[string]any{"lead": "Three games, one night.", "backdrop_url": "/media/" + loop}})
	video := regexp.MustCompile(`<video[^>]*>`).FindString(out)
	for _, want := range []string{" muted", " loop", " playsinline", " autoplay", `aria-hidden="true"`, `poster="/media/` + still} {
		if !strings.Contains(video, want) {
			t.Errorf("the backdrop video lacks %q: %s", want, video)
		}
	}
	if strings.Contains(video, "controls") {
		t.Error("a backdrop has player controls, so it is not decoration")
	}
	if !strings.Contains(out, `media="(prefers-reduced-motion: no-preference)"`) {
		t.Error("the recording is fetched for a reader who asked for reduced motion")
	}
	// Poster first: the still is a picture under the video, so a reader who
	// stopped it, or asked for less motion, sees the still and not nothing.
	poster := strings.Index(out, `<img src="/media/`+still)
	if poster < 0 || poster > strings.Index(out, "<video") {
		t.Error("the still is not drawn underneath the recording")
	}
	if !strings.Contains(out, `data-stop-motion`) || !strings.Contains(out, "Stop the moving background") {
		t.Error("nothing stops the moving backdrop")
	}
	if !strings.Contains(out, " has-backdrop\"") {
		t.Error("the hero is not marked as drawn over its backdrop")
	}
	r := a11y.CheckWith("index", out, a11y.Options{Sound: silent})
	for _, f := range r.Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("the gate refuses the shipped backdrop: %s", f)
		}
	}
}

// A picture backdrop is decoration with its narrower copies; a section asks
// for one with its surface; a features card carries its own picture.
func TestAPictureBackdropAndACardPicture(t *testing.T) {
	out := renderThrough(t, map[string]any{"title": "Home", "sections": []any{
		map[string]any{"features": map[string]any{"title": "Three worlds", "surface": "media",
			"backdrop_url": "/media/" + halo, "items": []any{
				map[string]any{"title": "Nightglass Rally", "body": "Racing on glass.", "image": "/media/" + halo, "alt": "A car of light"},
				map[string]any{"title": "Vexalume", "body": "A quiet puzzle."},
			}}},
	}})
	if !strings.Contains(out, "surface-media") || strings.Contains(out, "data-stop-motion") {
		t.Error("a still picture behind a section is drawn wrongly")
	}
	backdrop := regexp.MustCompile(`<div class="backdrop" aria-hidden="true"><img[^>]*>`).FindString(out)
	if !strings.Contains(backdrop, `alt=""`) || !strings.Contains(backdrop, "srcset=") {
		t.Errorf("the backdrop picture is not decoration with its narrower copies: %s", backdrop)
	}
	card := regexp.MustCompile(`<div class="card-media"><img[^>]*>`).FindString(out)
	if !strings.Contains(card, `alt="A car of light"`) || !strings.Contains(card, "srcset=") {
		t.Errorf("the card picture: %s", card)
	}
	if strings.Count(out, `class="card-media"`) != 1 {
		t.Error("a card with no picture was given one")
	}
	if r := a11y.CheckWith("index", out, a11y.Options{Sound: silent}); r.Blocks() {
		t.Errorf("refused: %v", r.Findings)
	}
}

// G3: a silent recording in a video section is labelled with its
// description and passes without captions; a talk with sound does not.
func TestASilentVideoSectionIsLabelledByItsDescription(t *testing.T) {
	video := func(id string) string {
		return renderThrough(t, map[string]any{"title": "Watch", "sections": []any{
			map[string]any{"video": map[string]any{"title": "The loop", "src": "/media/" + id}}}})
	}
	quiet := video(loop)
	if !strings.Contains(quiet, `aria-label="Violet light drifting over a neon grid"`) {
		t.Error("the silent video is not labelled with its description")
	}
	if r := a11y.CheckWith("watch", quiet, a11y.Options{Sound: silent}); r.Blocks() {
		t.Errorf("a described silent video is refused: %v", r.Findings)
	}
	loud := video(talk)
	if strings.Contains(loud, "aria-label=") {
		t.Error("a video with sound was given its description in place of captions")
	}
	if r := a11y.CheckWith("watch", loud, a11y.Options{Sound: silent}); !r.Blocks() {
		t.Error("a talk with sound published without captions")
	}
}

// The words over a backdrop are the colour the veil was checked against,
// whatever hero style or section tone the content also asks for: no rule
// the sheet has for those out-ranks the backdrop's.
func TestTheWordsOverABackdropKeepTheirCheckedColour(t *testing.T) {
	b := Backdrops()
	if !strings.Contains(b, ".hero.has-backdrop, .section.surface-media { color: var(--on-surface);") {
		t.Fatal("the backdrop's text colour is not set at a specificity that beats a hero style or a tone")
	}
	// .hero.hero-bold is the strongest rule that colours a hero, and it
	// comes before the opt-in rules, so the same specificity later wins.
	if !strings.Contains(Components(), ".hero.hero-bold { background: var(--primary); color: var(--on-primary); }") {
		t.Fatal("the bold hero's rule changed; check the backdrop still out-ranks it")
	}
	if strings.Index(Components(), ".hero.hero-bold") > strings.Index(Components(), ".hero.has-backdrop") {
		t.Error("the backdrop's colour comes before the bold hero's, so the bold one wins")
	}
}
