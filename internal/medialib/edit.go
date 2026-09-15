// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package medialib

import (
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/media"
)

// Deriving an edited copy, in the one place every interface passes through.
//
// The same argument Put makes about renditions: three interfaces edit pictures
// — the command line, the browser and whatever comes next — and each carrying
// its own copy of "what an edited file inherits" would be three
// implementations of one rule. On past form two of them would drift, and the
// one that drifted would be the one that dropped the origin, which is a way to
// launder generated content into an undeclared file.
//
// So the rule is here. What travels, and why:
//
//	the licence   an edit neither renews permission nor ends it. A crop of a
//	              photograph licensed until October is licensed until October,
//	              and the rights gate has to see that.
//	the origin    a crop of a picture a model made is still a picture a model
//	              made, and the media provenance gate is watching for exactly
//	              the page that carries one.
//	the source    where the file came from is still where it came from.
//	the alt text  required before an image may be used at all, so a derivative
//	              without one is a file nobody can put on a page. Overridable,
//	              because a crop sometimes shows something different.
//
// And what does not: the focal point. It named a point in the original, and
// after a crop or a turn it names a different part of the picture — carrying
// it across would silently move somebody's subject.

// Edit derives a new asset from one already stored, and stores it.
//
// The original is untouched. It keeps its own id, stays in the library, and
// stays on any page already using it.
func (l *Library) Edit(parentID string, e media.Edit, opt media.Options,
	alt, by string) (media.File, error) {

	if err := e.Validate(); err != nil {
		return media.File{}, err
	}
	parent, body, err := l.Get(parentID)
	if err != nil {
		return media.File{}, err
	}
	if parent.Kind != media.Image {
		return media.File{}, fmt.Errorf(
			"%s is a %s, and this edits pictures", ShortID(parent.ID), parent.Kind)
	}

	derived, err := media.Derive(parent.Format, body, e, parent.Focus, opt)
	if err != nil {
		return media.File{}, err
	}
	f, err := media.Accept(EditedName(parent, e), derived.Body, time.Now())
	if err != nil {
		return media.File{}, fmt.Errorf(
			"the edited picture does not validate, so it has not been "+
				"stored: %w", err)
	}

	f.Alt = strings.TrimSpace(alt)
	if f.Alt == "" {
		f.Alt = parent.Alt
	}
	f.Rights = parent.Rights
	f.Origin = parent.Origin
	f.Source = parent.Source
	f.EditOf = parent.ID
	f.Edit = &e
	f.UploadedBy = by

	if err := l.Put(f, derived.Body); err != nil {
		return media.File{}, err
	}
	// Re-read, so the caller is handed the record as stored — with the
	// renditions Put generated on it. Returning the one built above would
	// describe a file with no narrower copies, which is not the file on disk.
	return l.Stat(f.ID)
}

// Preview derives an edited copy and does not store it.
//
// For a screen that shows what a crop would do before anybody commits to it.
// Bounded to a width somebody can look at rather than the full stored size:
// this runs per page view, and resampling six million pixels to answer "is the
// face still in frame" is work nobody asked for.
func (l *Library) Preview(parentID string, e media.Edit, width int) (
	media.File, []byte, error) {

	if err := e.Validate(); err != nil {
		return media.File{}, nil, err
	}
	parent, body, err := l.Get(parentID)
	if err != nil {
		return media.File{}, nil, err
	}
	if parent.Kind != media.Image {
		return media.File{}, nil, fmt.Errorf("%s is not a picture",
			ShortID(parent.ID))
	}
	if width <= 0 {
		width = PreviewWidth
	}
	derived, err := media.Derive(parent.Format, body, e, parent.Focus,
		media.Options{MaxWidth: width, MaxHeight: width})
	if err != nil {
		return media.File{}, nil, err
	}
	return parent, derived.Body, nil
}

// PreviewWidth bounds a preview.
//
// Large enough to judge a crop on, small enough that producing one is not a
// way to spend the server's time from a form somebody is typing into.
const PreviewWidth = 900

// EditedName gives a derivative a name somebody can recognise in a list.
//
// The stored name is display only — the address is the hash — so this is
// allowed to be prose. A library of files all called the same thing is a
// library where the picker is useless, and the picker is the screen this
// feature most obviously feeds.
func EditedName(parent media.File, e media.Edit) string {
	base := parent.Name
	if base == "" {
		base = ShortID(parent.ID)
	}
	if i := strings.LastIndex(base, "."); i > 0 {
		base = base[:i]
	}
	var tag string
	switch {
	case e.Crop != nil:
		tag = "cropped"
	case strings.TrimSpace(e.Aspect) != "":
		tag = strings.ReplaceAll(strings.TrimSpace(e.Aspect), ":", "-")
	case e.Turn != 0:
		tag = "turned"
	case strings.TrimSpace(e.Flip) != "":
		tag = "flipped"
	case e.Grey:
		tag = "grey"
	}
	if e.Grey && tag != "grey" {
		tag += "-grey"
	}
	// Extension already carries the dot, which is how the format table spells
	// it — adding another produces "name-16-9..png".
	return base + "-" + tag + parent.Extension()
}

// ShortID is an id as every screen and message prints one.
func ShortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
