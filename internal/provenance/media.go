// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package provenance

import "sort"

// When a page's mark and its pictures disagree.
//
// # The hole this closes
//
// The publish gate refused a page that declared no provenance, and nothing
// looked at the pictures on it. So a page could say humanEdits — a person
// wrote this — carry an image declared trainedAlgorithmicMedia, and publish
// with a meta tag asserting human authorship over a document containing
// generated content. The mark was not missing. It was wrong.
//
// This package's opening argument is that "the dangerous failure is not a
// missing mark — it is a missing mark that reads as 'a person wrote this'." A
// mark that says so explicitly, over content it does not cover, is the same
// failure with a signature on it.
//
// # Why this refuses rather than warns
//
// Because there is always a correct answer and it is one command away.
// compositeWithTrainedAlgorithmicMedia is the IPTC term for exactly this
// situation — human content with generated elements — and it is one of the
// four this program supports. A gate with a one-command fix and no legitimate
// exception is a gate that should refuse, which is why this belongs with the
// unwaivable content checks rather than beside the override the page-level
// mark carries.
//
// # What it deliberately does not check
//
// An image whose origin nobody has declared. Almost every library is in that
// state — nothing used to be able to set the field at all — so a gate on it
// would refuse the first publish of every existing site, which is the mistake
// the page-level gate made once and had to undo. Undeclared media is a thing
// to survey with `quilzo provenance check`, not a thing to stop a publish.
//
// And a picture on a record rather than a page. A record carries no provenance
// of its own, so there is no claim for its media to contradict; which page
// would be accountable for a record surfaced by a listing is not a question
// the content answers. That is a real gap and it is the same one records have
// generally, rather than a new one introduced here.

// A MediaClaim is one asset and what its origin says about how it was made.
//
// A plain string for the source type, because that is how internal/media
// stores it and this package must not depend on the asset library to judge a
// vocabulary it owns.
type MediaClaim struct {
	// Page is the page using it.
	Page string
	// Asset is how to name the file to somebody who has to go and look at it.
	Asset string
	// SourceType is the asset's declared origin, empty when nobody has said.
	SourceType string
}

// A Conflict is a page whose own record claims less than its media requires.
type Conflict struct {
	Page string
	// Says is what the page's record declares.
	Says SourceType
	// Asset and Carries are the picture that disagrees with it.
	Asset   string
	Carries SourceType
}

// Detail is the refusal, written so the fix is in it.
func (c Conflict) Detail() string {
	return "the page is recorded as " + string(c.Says) + " and carries " +
		c.Asset + ", which is declared " + string(c.Carries) + ". " +
		"Record the page as " + string(CompositeWithTrainedAlgorithmicMedia) +
		", which is the term for human content with generated elements"
}

// Conflicts finds every page making a claim its media contradicts.
//
// idx supplies what each page says about itself; claims are the assets used by
// those pages. A page with no record at all is not reported here — that is the
// existing gap and the existing refusal, and saying it twice in two vocabu-
// laries would send somebody to fix the wrong thing first.
func Conflicts(idx *Index, claims []MediaClaim) []Conflict {
	if idx == nil {
		return nil
	}
	var out []Conflict
	for _, c := range claims {
		carries := SourceType(c.SourceType)
		if !carries.RequiresDisclosure() {
			// Undeclared, or declared as something that carries no obligation.
			// algorithmicMedia is deliberately in this half: calling a
			// database import AI-generated devalues the mark that matters.
			continue
		}
		r, ok := idx.Get(c.Page)
		if !ok {
			continue
		}
		if r.SourceType.RequiresDisclosure() {
			continue
		}
		out = append(out, Conflict{
			Page: c.Page, Says: r.SourceType,
			Asset: c.Asset, Carries: carries,
		})
	}
	// Stable, because this list is read on a screen and printed in a refusal,
	// and an order that changes between two runs of the same check reads as
	// the content having changed.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Page != out[j].Page {
			return out[i].Page < out[j].Page
		}
		return out[i].Asset < out[j].Asset
	})
	return out
}

// MediaSurvey counts what a library's origins say, for a report rather than a
// gate.
type MediaSurvey struct {
	// Declared is assets whose origin somebody has recorded.
	Declared int
	// Generated is the subset that carries an Article 50 obligation.
	Generated int
	// Undeclared is assets nobody has said anything about. Not a failure: it
	// is the state every library starts in, and the honest reading is "nobody
	// has said" rather than "a person made this".
	Undeclared int
	// Pages naming generated media, sorted, so a survey can say where to look.
	Pages []string
}

// Survey summarises the origins of the media in use.
func Survey(claims []MediaClaim) MediaSurvey {
	var s MediaSurvey
	seen := map[string]bool{}
	for _, c := range claims {
		if c.SourceType == "" {
			s.Undeclared++
			continue
		}
		s.Declared++
		if SourceType(c.SourceType).RequiresDisclosure() {
			s.Generated++
			if c.Page != "" && !seen[c.Page] {
				seen[c.Page] = true
				s.Pages = append(s.Pages, c.Page)
			}
		}
	}
	sort.Strings(s.Pages)
	return s
}
