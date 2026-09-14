// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package section

import (
	"crypto/rand"
	"encoding/hex"
)

// A name for a section that survives the one above it being removed.
//
// # What a position cannot carry
//
// A section was its position and nothing else: Placed held an Index, and
// Insert, Remove and Move were index arithmetic. That is fine while one person
// is looking at one screen and wrong the moment two are, because the Sections
// screen posts `at=3` and the handler removes whatever is third *now*:
//
//	somebody opens Sections, sees six sections, and decides to remove the
//	fifth. A colleague adds a banner at the top. The first person presses
//	Remove and the fourth section goes instead — the one they were keeping.
//
// The editor already has the answer for a whole page: the form carries the
// draft commit it was rendered from and the save is refused if the draft has
// moved. Doing that here would refuse every arrangement whenever anybody
// touched anything, which is worse than the bug for a screen whose whole
// purpose is small repeated edits. Naming the section instead refuses exactly
// the case that is wrong and lets the rest through.
//
// # And it is what a block needs to be pointed at
//
// internal/note anchors a remark to a *field name* rather than a position,
// and says why: "a position moves when a paragraph is added above it". That
// reasoning is right and it left notes unable to attach to a section at all.
// internal/menu solved the same problem years ago — Item.ID is "stable across
// relabelling, so a saved arrangement survives an edit". This is that, for the
// thing a page is actually made of.
//
// # Beside the kind, not inside it
//
// A section is {"prose": {...}}, and the id goes next to the kind rather than
// among its fields: {"id": "8f3c1a90", "prose": {...}}. Inside, it would be a
// field of every kind, reported by unknownFields on every page, and readable
// by a layout that has no business rendering it. Outside, discriminator still
// finds the kind — it looks for a key from the catalogue and "id" is not one —
// and the only rule that had to learn about it is the one that refuses two
// kinds on one entry.

// IDField is where a section's name lives.
const IDField = "id"

// idBytes is four, which is eight hex characters.
//
// Long enough that a collision inside one page is not a thing that happens,
// short enough to read out in a bug report, and this is not a secret: it
// names a block on a page anybody with access can already see.
const idBytes = 4

// newID is the generator, replaceable in tests.
//
// A seam rather than a parameter, because Insert is called from four places
// that have nothing to say about identifiers and would each have to grow an
// argument to pass one through.
var newID = randomID

func randomID() string {
	b := make([]byte, idBytes)
	if _, err := rand.Read(b); err != nil {
		// Unreachable in practice, and a section with no id is better than a
		// refused edit: the next write assigns one.
		return ""
	}
	return hex.EncodeToString(b)
}

// IDOf reads a section entry's id, empty if it has none.
func IDOf(entry any) string {
	m, ok := entry.(map[string]any)
	if !ok {
		return ""
	}
	id, _ := m[IDField].(string)
	return id
}

// EnsureIDs gives every section on a page one, and says whether it changed
// anything.
//
// Lazily rather than by migration. A page gains ids the first time somebody
// arranges it, which is the first time they can matter — and a migration over
// a content-addressed store would rewrite every page's hash to add a field
// nothing was using yet.
func EnsureIDs(body any) (map[string]any, bool) {
	page, list := copyOf(body)
	taken := map[string]bool{}
	for _, entry := range list {
		if id := IDOf(entry); id != "" {
			taken[id] = true
		}
	}

	changed := false
	next := make([]any, 0, len(list))
	for _, entry := range list {
		m, ok := entry.(map[string]any)
		if !ok || IDOf(entry) != "" {
			next = append(next, entry)
			continue
		}
		copied := make(map[string]any, len(m)+1)
		for k, v := range m {
			copied[k] = v
		}
		copied[IDField] = freshID(taken)
		next = append(next, copied)
		changed = true
	}
	if !changed {
		return page, false
	}
	page[Field] = next
	return page, true
}

// freshID draws one that is not already on this page.
func freshID(taken map[string]bool) string {
	for i := 0; i < 8; i++ {
		id := newID()
		if id != "" && !taken[id] {
			taken[id] = true
			return id
		}
	}
	return ""
}

// IndexOf finds a section by its id.
//
// The index is what every operation here takes, and resolving it at the last
// moment — against the page as it is now, rather than as it was when a screen
// was drawn — is the whole point of having an id.
func IndexOf(body any, id string) (int, bool) {
	if id == "" {
		return 0, false
	}
	_, list := copyOf(body)
	for i, entry := range list {
		if IDOf(entry) == id {
			return i, true
		}
	}
	return 0, false
}
