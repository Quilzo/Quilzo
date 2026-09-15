// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// What the pictures on a page say about how it was made.
//
// The walk is assetUses, which the image-rights gate already uses: a media
// reference is any field holding sixty-four hexadecimal characters the library
// also holds, so it finds pictures on content types nobody has written yet.
// See internal/provenance/media.go for what is done with the answer and why
// only one of the two possible findings refuses a publish.

// mediaClaims lists the assets each page uses and what their origins declare.
//
// Pages only. assetUses covers records too — a product photograph lives on a
// record, and the rights gate is right to check it — but a record carries no
// provenance of its own, so there is no claim for its media to contradict.
// Filtered by membership in the page set rather than by looking for a slash,
// because "blog/first" is a page and "products/brass-pen" is not, and nothing
// in the name says which.
func mediaClaims(s *store.Store, lib *medialib.Library, ref string) (
	[]provenance.MediaClaim, error) {

	pages, err := site.PagesAt(s, ref)
	if err != nil {
		return nil, err
	}
	uses, err := assetUses(s, lib, ref)
	if err != nil {
		return nil, err
	}
	var out []provenance.MediaClaim
	for _, u := range uses {
		name := u.File.Name
		if name == "" {
			name = shortID(u.File.ID)
		}
		for _, where := range u.Where {
			if _, isPage := pages[where]; !isPage {
				continue
			}
			out = append(out, provenance.MediaClaim{
				Page: where, Asset: name,
				SourceType: u.File.Origin.SourceType,
			})
		}
	}
	return out, nil
}

// mediaConflictsAt is the gate's question, answered for one commit.
//
// A missing library is not a failed check, the same as the rights gate: a
// store with no media has no picture that could contradict anything. A
// missing provenance file is not one either — every page is then unrecorded,
// which the page-level gate already refuses and which this must not report a
// second time in different words.
func mediaConflictsAt(root string, s *store.Store, ref string) (
	[]provenance.Conflict, error) {

	lib, err := openMedia(root)
	if err != nil {
		return nil, nil
	}
	claims, err := mediaClaims(s, lib, ref)
	if err != nil {
		return nil, err
	}
	if len(claims) == 0 {
		return nil, nil
	}
	idx, err := loadProvenance(root)
	if err != nil {
		return nil, fmt.Errorf(
			"the provenance records could not be read, so no page's pictures "+
				"were checked against what it claims: %w", err)
	}
	return provenance.Conflicts(idx, claims), nil
}
