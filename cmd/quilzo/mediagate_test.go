// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// siteWithSectionImage builds a store holding one page whose picture is inside
// a section, which is where every shipped layout puts one.
func siteWithSectionImage(t *testing.T, spelling func(id string) string) (
	string, *store.Store, string) {

	t.Helper()
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}

	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	f, err := media.Accept("hero.png", buf.Bytes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "a hero image"
	if err := lib.Put(f, buf.Bytes()); err != nil {
		t.Fatal(err)
	}

	if _, err := site.SaveDraft(s, map[string]any{
		"about": map[string]any{
			"title": "About",
			"sections": []any{
				map[string]any{"prose": map[string]any{"title": "Words"}},
				map[string]any{"split": map[string]any{
					"title": "Beside", "image": spelling(f.ID), "alt": "a hero image",
				}},
			},
		},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	return root, s, f.ID
}

// An expired licence on a picture inside a section stops a publish.
//
// It did not. assetIDsIn read the top level of the map and the direct members
// of a list, so a record — a flat map — was checked and a page was not. Every
// shipped layout puts its pictures at page.sections[3].split.image, so the
// gate that refuses to publish an image whose permission has ended had never
// examined a single image on a page.
func TestAnExpiredLicenceInsideASectionRefusesThePublish(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spelling func(string) string
	}{
		{"the bare id, as an importer writes it",
			func(id string) string { return id }},
		{"/media/<id>, as the picker and the chat editor write it",
			func(id string) string { return "/media/" + id }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, s, id := siteWithSectionImage(t, tc.spelling)

			lib, err := openMedia(root)
			if err != nil {
				t.Fatal(err)
			}
			f, err := lib.Stat(id)
			if err != nil {
				t.Fatal(err)
			}
			f.Rights = media.Rights{
				Licence: "cc-by-4.0", Holder: "somebody",
				Until: time.Now().Add(-48 * time.Hour).Unix(),
			}
			_, raw, err := lib.Get(id)
			if err != nil {
				t.Fatal(err)
			}
			if err := lib.Put(f, raw); err != nil {
				t.Fatal(err)
			}

			refused, _, gerr := contentGates(root, s, "").Run()
			if gerr != nil {
				t.Fatalf("the gates could not run: %v", gerr)
			}
			if refused == nil {
				t.Fatal("a picture whose permission ended two days ago " +
					"published, because it was inside a section")
			}
			if refused.Check.Name != "image rights" {
				t.Errorf("refused by %q, want the image rights gate",
					refused.Check.Name)
			}
		})
	}
}

// A page claiming human authorship over a generated picture is refused.
func TestThePageMarkHasToCoverItsPictures(t *testing.T) {
	root, s, id := siteWithSectionImage(t,
		func(id string) string { return "/media/" + id })

	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	f, err := lib.Stat(id)
	if err != nil {
		t.Fatal(err)
	}
	f.Origin = media.Origin{
		SourceType: string(provenance.TrainedAlgorithmicMedia),
		Model:      "a-model", Author: "somebody",
	}
	_, raw, err := lib.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(f, raw); err != nil {
		t.Fatal(err)
	}

	// The page says a person wrote it.
	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := pageHashes(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if err := idx.Set("about", provenance.Record{
		ContentHash: hashes["about"], SourceType: provenance.HumanEdits,
		Author: "somebody",
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(provPath(root), idx); err != nil {
		t.Fatal(err)
	}

	refused, _, gerr := contentGates(root, s, "").Run()
	if gerr != nil {
		t.Fatalf("the gates could not run: %v", gerr)
	}
	if refused == nil {
		t.Fatal("a page recorded as written by a person published with a " +
			"generated picture on it, asserting human authorship over " +
			"content a model made")
	}
	if refused.Check.Name != "media provenance" {
		t.Fatalf("refused by %q, want the media provenance gate",
			refused.Check.Name)
	}
	// The refusal carries the fix, because this gate has no override.
	detail := refused.Findings[0].Detail
	if !strings.Contains(detail, "compositeWithTrainedAlgorithmicMedia") {
		t.Errorf("the refusal does not name the term that fixes it: %s", detail)
	}

	// And the term for human content with generated elements clears it.
	if err := idx.Set("about", provenance.Record{
		ContentHash: hashes["about"],
		SourceType:  provenance.CompositeWithTrainedAlgorithmicMedia,
		Author:      "somebody",
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(provPath(root), idx); err != nil {
		t.Fatal(err)
	}
	refused, _, gerr = contentGates(root, s, "").Run()
	if gerr != nil {
		t.Fatalf("the gates could not run: %v", gerr)
	}
	if refused != nil {
		t.Errorf("recording the page as composite did not clear it: %s",
			refused.Error())
	}
}

// A site whose media nobody has declared still publishes.
//
// Every library is in that state, because nothing could set the field until
// recently. A gate on undeclared origins would refuse the first publish of
// every existing site, which is the mistake the page-level gate made once and
// had to undo.
func TestUndeclaredMediaDoesNotStopAPublish(t *testing.T) {
	root, s, _ := siteWithSectionImage(t,
		func(id string) string { return "/media/" + id })

	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := pageHashes(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if err := idx.Set("about", provenance.Record{
		ContentHash: hashes["about"], SourceType: provenance.HumanEdits,
		Author: "somebody",
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(provPath(root), idx); err != nil {
		t.Fatal(err)
	}

	refused, _, gerr := contentGates(root, s, "").Run()
	if gerr != nil {
		t.Fatalf("the gates could not run: %v", gerr)
	}
	if refused != nil {
		t.Errorf("a picture nobody has declared stopped a publish: %s",
			refused.Error())
	}
}
