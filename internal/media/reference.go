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

// Rewriting a reference, which is the other half of recognising one.
//
// IDsIn exists because two readers that disagree about what a reference looks
// like are two readers that check different halves of the same site. A writer
// that disagreed with the reader would be worse: it would rewrite the
// references the reader can see and leave the ones it cannot, so a picture
// replaced everywhere the gate looks would still be on the page.
//
// So this walks the same structure, to the same depth, and decides by the same
// IDIn — and it keeps the spelling it found. A field holding "/media/<id>" is
// a field a template reads as a path; rewriting it to a bare id would replace
// the picture and break the page it is on.

// ReplaceID rewrites every reference to one stored file with another.
//
// Returns the rewritten content and how many references changed. The input is
// not modified: content here comes out of a content-addressed object, and a
// walk that edited it in place would be editing bytes something else may still
// be holding under their own hash.
func ReplaceID(v any, old, with string) (any, int) {
	n := 0
	out := replace(v, old, with, 0, &n)
	return out, n
}

func replace(v any, old, with string, depth int, n *int) any {
	if depth > maxReferenceDepth {
		return v
	}
	switch t := v.(type) {
	case string:
		id, ok := IDIn(t)
		if !ok || id != old {
			return t
		}
		*n++
		// The spelling is kept. A template reads "/media/<id>" as a path, so
		// a rewrite that returned a bare id would replace the picture and
		// break the page carrying it.
		return strings.Replace(t, old, with, 1)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = replace(vv, old, with, depth+1, n)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = replace(item, old, with, depth+1, n)
		}
		return out
	}
	return v
}
