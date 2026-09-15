// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package section

import "strings"

// Which fields name a stored file, and what kind of file.
//
// # Why this is here rather than in each interface
//
// Because the answer has to be the same everywhere, and it was not. The
// Telegram editor knew that "image" and "poster" want a picture and that "src"
// wants a video, so it offered a picker; the browser did not know, so it
// offered a text box and somebody attaching a photograph typed a
// sixty-four-character hash by hand. One interface had the table and the other
// had the gap, which is the shape of drift this project keeps finding: two
// halves of one capability, each correct on its own.
//
// It belongs in this package because a section is where the field lives. The
// catalogue already says what fields a kind has; this says what two of them
// mean.
//
// # Why a name and not a declaration
//
// A kind could declare "this field is a picture" in its catalogue entry, and
// that would be more precise. It would also mean every existing stub grows a
// parallel structure describing itself, and the four names below cover every
// file-valued field in the catalogue. When a fifth arrives that the names do
// not cover, that is the moment to pay for the declaration.

// FileKind reports the kind of stored file a field names, and whether it names
// one at all.
//
// The path may be dotted — "items.2.image" — because that is how a field is
// addressed inside a section, and it is the last segment that says what the
// value means. An index in the middle changes which entry, never what the
// field is.
func FileKind(path string) (string, bool) {
	leaf := path
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}
	switch leaf {
	case "image", "poster":
		// A poster is the still a player shows before anybody presses play, so
		// it is a picture even though it sits on a video section.
		return "image", true
	case "src":
		return "video", true
	case "audio":
		return "audio", true
	}
	return "", false
}
