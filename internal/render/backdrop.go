// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package render

import "strings"

// A backdrop: a picture or a recording behind a hero or a section.
//
// The layout cannot ask the library which of the two a file is, and the
// markup differs completely — an <img> for a picture, a muted looping <video>
// with its poster underneath for a recording — so the answer is a companion,
// computed here like the srcset is. Only a file this library holds becomes a
// backdrop: a URL from anywhere else draws nothing, which is also what the
// site's policy would make of it.
//
// It is decoration by construction, and the safeguards that make that true
// are in the layout and the stylesheet: hidden from assistive technology,
// under a veil the contrast check can reason about, still for a reader who
// asked for reduced motion, and stoppable by anybody. Whether a recording may
// be decoration at all — it may not, if it has sound, because muting it
// throws away what somebody needed to hear — is the accessibility gate's
// question, asked of the rendered page (internal/a11y).

// BackdropField is the key a hero or a section names its backdrop under.
// The _url suffix is deliberate: the chatbot reads a page's words and skips
// wiring, and it recognises wiring by that suffix.
const BackdropField = "backdrop_url"

// MediaSurface is the value of a section's "surface" that draws it over its
// backdrop.
const MediaSurface = "media"

// deriveBackdrop writes what a layout needs to draw an object's backdrop.
func deriveBackdrop(m map[string]any, ask asks) {
	if ask.media == nil {
		return
	}
	text, ok := m[BackdropField].(string)
	if !ok {
		return
	}
	match := reAssetPath.FindStringSubmatch(strings.TrimSpace(text))
	if match == nil {
		return
	}
	info, found := ask.media(match[1])
	if !found {
		return
	}
	switch info.Kind {
	case "image":
		setIfAbsent(m, "backdrop_image", true)
	case "video":
		setIfAbsent(m, "backdrop_video", true)
		if ask.poster != nil {
			if at := ask.poster(match[1]); at != "" {
				setIfAbsent(m, "backdrop_poster", at)
			}
		}
	default:
		return
	}
	if surface, _ := m["surface"].(string); surface == MediaSurface {
		setIfAbsent(m, "backdrop_on", true)
	}
}

// deriveSilentAlt gives a silent recording its text alternative.
//
// A video with no sound owes a reader who cannot see it a description of what
// it shows (WCAG 1.2.1), not a captions track, and its description is already
// in the library: it is what was written when it was added. Only when the
// probe recorded no sound — a recording nothing listened to keeps the
// captions rule, because unknown is not silent — so a page with a video
// stored before anybody asked renders exactly as it did.
func deriveSilentAlt(m map[string]any, media func(string) (MediaInfo, bool)) {
	if media == nil {
		return
	}
	text, ok := m["src"].(string)
	if !ok {
		return
	}
	match := reAssetPath.FindStringSubmatch(strings.TrimSpace(text))
	if match == nil {
		return
	}
	info, found := media(match[1])
	if !found || info.Kind != "video" || !info.SoundKnown || info.Sound {
		return
	}
	if alt := strings.TrimSpace(info.Alt); alt != "" {
		setIfAbsent(m, "src_alt", alt)
	}
}

// HasBackdrop reports whether a decorated page draws anything over a
// backdrop: its hero, or any of its sections.
//
// The publish gate asks, because the words over a backdrop are judged
// against the worst picture the veil could cover (theme.CheckBackdrop), and
// that judgement applies to a page that has one and to no other: a site
// whose veil is too weak is refused only where it is used.
func HasBackdrop(page any) bool {
	m, ok := page.(map[string]any)
	if !ok {
		return false
	}
	if hero, ok := m["hero"].(map[string]any); ok && hero["backdrop_on"] == true {
		return true
	}
	list, _ := m["sections"].([]any)
	for _, entry := range list {
		e, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		for _, inner := range e {
			if fields, ok := inner.(map[string]any); ok && fields["backdrop_on"] == true {
				return true
			}
		}
	}
	return false
}
