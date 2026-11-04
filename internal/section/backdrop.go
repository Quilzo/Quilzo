// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package section

import (
	"fmt"
	"regexp"
	"strings"
)

// A backdrop behind a section or the hero, as an operation of its own.
//
// Editing a section writes only the fields it already has (fields.go), which
// is what keeps a form somebody posts from inventing structure — and it means
// no edit can give a section a backdrop it did not start with. So putting
// one there is a named operation with its own check: the surface becomes
// "media", the address names a file in this library or is empty for a
// picker to fill, and nothing else about the section changes.

// HeroAt is the position that means the page's hero rather than a section.
const HeroAt = -1

// BackdropField and MediaSurface are the keys a backdrop is written under;
// internal/render reads the same two.
const (
	BackdropField = "backdrop_url"
	MediaSurface  = "media"
)

var reBackdrop = regexp.MustCompile(`^/media/[0-9a-f]{64}$`)

// SetBackdrop puts a backdrop behind a section, or behind the hero at
// HeroAt. media is a /media/ address from the library, or "" to leave the
// field for a picker to fill.
func SetBackdrop(body any, at int, media string) (map[string]any, error) {
	media = strings.TrimSpace(media)
	if media != "" && !reBackdrop.MatchString(media) {
		return nil, fmt.Errorf("%q is not a file in the media library; a backdrop is "+
			"/media/ and the 64-character id `quilzo media list` prints", media)
	}
	return changeBackdrop(body, at, func(inner map[string]any, hero bool) {
		inner[BackdropField] = media
		if !hero {
			inner["surface"] = MediaSurface
		}
	})
}

// ClearBackdrop takes a section's backdrop away, or the hero's at HeroAt.
// A surface somebody chose for another reason is left as it was.
func ClearBackdrop(body any, at int) (map[string]any, error) {
	return changeBackdrop(body, at, func(inner map[string]any, hero bool) {
		delete(inner, BackdropField)
		if surface, _ := inner["surface"].(string); !hero && surface == MediaSurface {
			delete(inner, "surface")
		}
	})
}

func changeBackdrop(body any, at int, change func(map[string]any, bool)) (map[string]any, error) {
	page, list := copyOf(body)
	if at == HeroAt {
		hero, ok := page["hero"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("this page has no hero to put a backdrop behind")
		}
		updated := cloneValue(hero).(map[string]any)
		change(updated, true)
		page["hero"] = updated
		return page, nil
	}
	if at < 0 || at >= len(list) {
		return nil, fmt.Errorf("there is no section %d; this page has %d", at, len(list))
	}
	entry, ok := list[at].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("section %d is not one a backdrop can go behind", at)
	}
	kind, inner := discriminator(entry)
	if inner == nil {
		return nil, fmt.Errorf("section %d carries nothing to put a backdrop behind", at)
	}
	if kind == "notice" {
		return nil, fmt.Errorf("a notice is a banner in a tone of its own, and has no backdrop")
	}
	updated := cloneValue(inner).(map[string]any)
	change(updated, false)
	next := make([]any, len(list))
	copy(next, list)
	replacement := map[string]any{kind: updated}
	for k, v := range entry {
		if k != kind {
			replacement[k] = v
		}
	}
	next[at] = replacement
	page[Field] = next
	return page, nil
}

// hasBackdrop is a section drawn over a backdrop.
func hasBackdrop(inner map[string]any) bool {
	surface, _ := inner["surface"].(string)
	return surface == MediaSurface
}
