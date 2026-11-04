// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"testing"
)

var (
	picture   = strings.Repeat("a", 64)
	recording = strings.Repeat("b", 64)
	quiet     = strings.Repeat("c", 64)
	unheard   = strings.Repeat("d", 64)
	still     = strings.Repeat("e", 64)
)

// library answers the way the media library would for five files: a
// picture, a recording with sound, a silent one, one nothing listened to,
// and a still with narrower copies.
func library() Sources {
	return Sources{
		Media: func(id string) (MediaInfo, bool) {
			switch id {
			case picture, still:
				return MediaInfo{Kind: "image", Alt: "a picture"}, true
			case recording:
				return MediaInfo{Kind: "video", Sound: true, SoundKnown: true, Alt: "a loud clip"}, true
			case quiet:
				return MediaInfo{Kind: "video", SoundKnown: true, Alt: "Violet light drifting over a grid"}, true
			case unheard:
				return MediaInfo{Kind: "video", Alt: "a clip nobody probed"}, true
			}
			return MediaInfo{}, false
		},
		Poster: func(id string) string {
			if id == recording || id == quiet {
				return "/media/" + still
			}
			return ""
		},
		SrcSet: func(id string) string {
			if id == still || id == picture {
				return "/media/" + id + "-480 480w"
			}
			return ""
		},
	}
}

func pageOf(t *testing.T, src Sources, body map[string]any) map[string]any {
	t.Helper()
	ctx, err := src.For("index", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ctx["page"].(map[string]any)
}

// A hero names a backdrop and is drawn over it; the layout is told whether
// it is a picture or a recording, and gets the recording's still with its
// narrower copies.
func TestAHeroIsDrawnOverItsBackdrop(t *testing.T) {
	page := pageOf(t, library(), map[string]any{"title": "Home",
		"hero": map[string]any{"backdrop_url": "/media/" + recording}})
	hero := page["hero"].(map[string]any)
	if hero["backdrop_on"] != true || hero["backdrop_video"] != true || hero["backdrop_image"] != nil {
		t.Errorf("hero: %v", hero)
	}
	if hero["backdrop_poster"] != "/media/"+still || hero["backdrop_poster_srcset"] == nil {
		t.Errorf("the recording's still is not offered with its narrower copies: %v", hero)
	}
	page = pageOf(t, library(), map[string]any{"title": "Home",
		"hero": map[string]any{"backdrop_url": "/media/" + picture}})
	hero = page["hero"].(map[string]any)
	if hero["backdrop_image"] != true || hero["backdrop_on"] != true || hero["backdrop_url_srcset"] == nil {
		t.Errorf("a picture backdrop: %v", hero)
	}
}

// A section is drawn over its backdrop only when its surface says media: a
// section has other surfaces, and naming a file is not choosing one.
func TestASectionAsksForItsMediaSurface(t *testing.T) {
	body := map[string]any{"title": "Home", "sections": []any{
		map[string]any{"features": map[string]any{"surface": "media", "backdrop_url": "/media/" + picture}},
		map[string]any{"features": map[string]any{"backdrop_url": "/media/" + picture}},
	}}
	sections := pageOf(t, library(), body)["sections"].([]any)
	first := sections[0].(map[string]any)["features"].(map[string]any)
	second := sections[1].(map[string]any)["features"].(map[string]any)
	if first["backdrop_on"] != true {
		t.Errorf("a media surface is not drawn over its backdrop: %v", first)
	}
	if second["backdrop_on"] != nil {
		t.Errorf("a section that did not ask is drawn over a backdrop: %v", second)
	}
}

// Only this library's files: a URL from anywhere else draws nothing, and so
// does a site whose renderer cannot ask the library.
func TestOnlyALibraryFileIsABackdrop(t *testing.T) {
	for _, src := range []Sources{library(), {}} {
		hero := pageOf(t, src, map[string]any{"title": "Home",
			"hero": map[string]any{"backdrop_url": "https://example.com/loop.mp4"}})["hero"].(map[string]any)
		if hero["backdrop_on"] != nil || hero["backdrop_video"] != nil {
			t.Errorf("a remote address became a backdrop: %v", hero)
		}
	}
	hero := pageOf(t, Sources{}, map[string]any{"title": "Home",
		"hero": map[string]any{"backdrop_url": "/media/" + picture}})["hero"].(map[string]any)
	if hero["backdrop_on"] != nil {
		t.Error("a backdrop was drawn by a renderer that could not ask what it is")
	}
}

// A silent recording's description is its text alternative. One with sound,
// and one nothing listened to, keep the captions rule and get none.
func TestASilentVideoGetsItsDescription(t *testing.T) {
	for id, want := range map[string]any{
		quiet: "Violet light drifting over a grid", recording: nil, unheard: nil,
	} {
		body := map[string]any{"title": "Home", "sections": []any{
			map[string]any{"video": map[string]any{"src": "/media/" + id}}}}
		v := pageOf(t, library(), body)["sections"].([]any)[0].(map[string]any)["video"].(map[string]any)
		if v["src_alt"] != want {
			t.Errorf("%s…: src_alt is %v, want %v", id[:1], v["src_alt"], want)
		}
	}
}

// The gate can tell which pages have a backdrop, hero or section.
func TestAPageWithABackdropIsKnownToHaveOne(t *testing.T) {
	plain := pageOf(t, library(), map[string]any{"title": "Home", "hero": map[string]any{"lead": "x"}})
	hero := pageOf(t, library(), map[string]any{"title": "Home", "hero": map[string]any{"backdrop_url": "/media/" + picture}})
	section := pageOf(t, library(), map[string]any{"title": "Home", "sections": []any{
		map[string]any{"prose": map[string]any{"surface": "media", "backdrop_url": "/media/" + quiet}}}})
	if HasBackdrop(plain) || !HasBackdrop(hero) || !HasBackdrop(section) {
		t.Errorf("plain %v, hero %v, section %v", HasBackdrop(plain), HasBackdrop(hero), HasBackdrop(section))
	}
}
