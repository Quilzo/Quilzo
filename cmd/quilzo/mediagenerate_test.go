// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
)

// painterServing stands in for an image endpoint, answering with one picture.
func painterServing(t *testing.T, body []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []any{map[string]any{
					"b64_json": base64.StdEncoding.EncodeToString(body),
				}},
			})
		}))
	t.Cleanup(srv.Close)
	t.Setenv("QUILZO_MODEL_URL", srv.URL+"/v1")
	t.Setenv("QUILZO_IMAGE_MODEL", "a-painter")
	return srv.URL
}

func smallPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 4), G: uint8(y * 4), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// There is no code path that stores a generated picture undeclared.
//
// The whole design is that sentence. The page side settled the argument twice
// already: "leaving this to the caller would mean the one interface built for
// agents is the one that forgets." A picture is the same case, so the origin
// is not a flag, not a default and not a reminder — the function that stores
// the bytes is the function that writes the mark.
func TestAGeneratedPictureIsAlwaysMarked(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	painterServing(t, smallPNG(t))

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	if err := mediaGenerate(root, []string{"a brass pen on a walnut desk",
		"--alt", "a slim brass pen", "--author", "rashik"}); err != nil {
		t.Fatal(err)
	}

	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("nothing was stored")
	}
	for _, f := range files {
		if f.Origin.SourceType != string(provenance.TrainedAlgorithmicMedia) {
			t.Errorf("%s declares %q; every copy of a generated picture "+
				"carries the mark, including the narrower ones",
				f.Name, f.Origin.SourceType)
		}
		if f.Origin.Author != "rashik" {
			t.Errorf("%s names %q as accountable; Article 50 places the "+
				"obligation on a person, never on the tool",
				f.Name, f.Origin.Author)
		}
		if f.Origin.Model != "a-painter" {
			t.Errorf("%s does not say which model made it", f.Name)
		}
	}
	// The instruction is the other half of "why does this picture show that".
	parent := files[0]
	for _, f := range files {
		if f.RenditionOf == "" {
			parent = f
		}
	}
	if !strings.Contains(parent.Origin.Instruction, "brass pen") {
		t.Errorf("the record does not carry what was asked for: %q",
			parent.Origin.Instruction)
	}
	if parent.Alt != "a slim brass pen" {
		t.Errorf("the description is %q", parent.Alt)
	}
}

// The description is required, and the prompt is not offered as one.
//
// The prompt is what somebody asked for; the picture may not show it, which is
// the ordinary case with these models. Using it as the alt text would be the
// accessible-looking version of describing an image nobody has looked at.
func TestGeneratingNeedsADescriptionAndWillNotUseThePrompt(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	painterServing(t, smallPNG(t))

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	err := mediaGenerate(root, []string{"a brass pen", "--author", "rashik"})
	if err == nil {
		t.Fatal("a picture was generated with no description")
	}
	if !strings.Contains(err.Error(), "not a description") {
		t.Errorf("the refusal does not explain why the prompt will not do: %v",
			err)
	}
	// And nothing was stored on the way to refusing.
	lib, _ := openMedia(root)
	if files, _ := lib.List(); len(files) != 0 {
		t.Errorf("%d file(s) were stored by a refused request", len(files))
	}
}

// Somebody has to be accountable.
func TestGeneratingNeedsAnAuthor(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	painterServing(t, smallPNG(t))

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	if err := mediaGenerate(root,
		[]string{"a brass pen", "--alt", "a pen"}); err == nil {
		t.Fatal("a picture was generated with nobody accountable for it")
	}
}

// A reply that is not a picture is refused rather than stored.
//
// A model's output is untrusted input: the format is decided by the bytes, and
// a reply that is not an image this library accepts is refused here rather
// than served to somebody.
func TestAReplyThatIsNotAPictureIsRefused(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	painterServing(t, []byte("<html><script>alert(1)</script></html>"))

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	if err := mediaGenerate(root, []string{"anything",
		"--alt", "x", "--author", "r"}); err == nil {
		t.Fatal("a model returned markup and it was stored as a picture")
	}
	lib, _ := openMedia(root)
	if files, _ := lib.List(); len(files) != 0 {
		t.Errorf("%d file(s) were stored", len(files))
	}
}

// The gate refuses a page that carries one and claims a person wrote it.
//
// The two halves were built in this order on purpose: the gate first, so the
// feature that creates the obligation arrived after the thing that enforces
// it. This is the join.
func TestAGeneratedPictureOnAHumanPageWillNotPublish(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	painterServing(t, smallPNG(t))

	w = out.New(true)
	t.Cleanup(func() { w = nil })
	if err := mediaGenerate(root, []string{"a brass pen",
		"--alt", "a pen", "--author", "r"}); err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, f := range files {
		if f.RenditionOf == "" {
			id = f.ID
		}
	}

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"about": map[string]any{"title": "About", "sections": []any{
			map[string]any{"split": map[string]any{
				"title": "Us", "image": "/media/" + id, "alt": "a pen"}},
		}},
	}, "a page with a generated picture", "test"); err != nil {
		t.Fatal(err)
	}
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
			"generated picture on it")
	}
	if refused.Check.Name != "media provenance" {
		t.Errorf("refused by %q", refused.Check.Name)
	}
}
