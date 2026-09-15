// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"regexp"
	"strings"
)

// Recognising a reference to a stored file.
//
// # Why the value and not the field name
//
// A media reference is not a typed field. Content says whatever it says, and
// an image lives in "image" on one type, "avatar" on another and "poster" on a
// third. What is invariant is the value: a file is addressed by the SHA-256 of
// its bytes. Matching on the value is what makes this work on content types
// nobody has written yet.
//
// # Why more than one spelling
//
// Because more than one spelling is written, by this program, today. The
// picker and the chat editor store "/media/<id>", which is what a template
// needs; an importer and a record store the bare id. A reader that accepted
// only one of them would be blind to half the pictures on the site — which is
// exactly what happened: the image-rights gate matched bare ids only, so a
// licence expiring on a hero image did not stop a publish.
//
// Kept here rather than in each reader, because two readers that disagree
// about what a reference looks like are two readers that check different
// halves of the same site.

var reStoredID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// IDIn reads a stored file's id out of a field value, in any spelling this
// program writes.
//
// Returns false for anything else, including an external URL that happens to
// end in something hexadecimal: the prefix has to be this site's media path or
// nothing at all.
func IDIn(value string) (string, bool) {
	v := strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(v, "/media/"):
		v = v[len("/media/"):]
	case strings.HasPrefix(v, "media/"):
		v = v[len("media/"):]
	}
	if !reStoredID.MatchString(v) {
		return "", false
	}
	return v, true
}

// maxReferenceDepth bounds a walk over decoded content.
//
// Content is nested by authors and by importers, and a walk without a limit is
// a way to spend the process's stack on a page somebody wrote. The same bound
// internal/render puts on its own walk, for the same reason.
const maxReferenceDepth = 10

// IDsIn finds every stored file a piece of decoded content refers to.
//
// It recurses, which the first version did not: it read the top level of a map
// and the direct members of a list, so a record — a flat map — was checked and
// a page was not. Every shipped layout puts its pictures inside sections, at
// page.sections[3].split.image, three levels down. So the gate that refuses to
// publish an expired licence had never examined a single image on a page.
//
// Returned sorted and deduplicated: one file used twice on a page is one
// licence, and a caller counting uses would otherwise count it twice.
func IDsIn(v any) []string {
	seen := map[string]bool{}
	collect(v, 0, seen)
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sortStrings(out)
	return out
}

func collect(v any, depth int, into map[string]bool) {
	if depth > maxReferenceDepth {
		return
	}
	switch t := v.(type) {
	case string:
		if id, ok := IDIn(t); ok {
			into[id] = true
		}
	case map[string]any:
		for _, vv := range t {
			collect(vv, depth+1, into)
		}
	case []any:
		for _, item := range t {
			collect(item, depth+1, into)
		}
	}
}
