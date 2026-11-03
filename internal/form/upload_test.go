// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package form

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pngBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 3))
	img.Set(1, 1, color.RGBA{200, 10, 10, 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

const aPDF = "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"

func claimForm() *Form {
	return &Form{Name: "claim", Notice: "Kept 30 days to settle the claim.", Fields: []Field{
		{Name: "name", Label: "Name", Kind: Line, Required: true},
		{Name: "photo", Label: "A photograph of the damage", Kind: File, Required: true, Accept: []string{"image"}},
		{Name: "receipt", Label: "The receipt", Kind: File},
	}}
}

// A file is taken by what it is, in the kinds its field takes, kept with
// the submission and given back unchanged; a file that is not what its
// field takes, or not what it claims to be, is refused.
func TestAFileIsTakenByWhatItIs(t *testing.T) {
	f := claimForm()
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	vals := sent(map[string]string{"name": "Ana"})
	if _, err := AcceptWithFiles(f, vals, nil, "", now); err == nil || !strings.Contains(err.Error(), "photograph") {
		t.Fatalf("a required file missing: %v", err)
	}
	if _, err := AcceptWithFiles(f, vals, map[string]Upload{"photo": {Name: "receipt.pdf", Data: []byte(aPDF)}}, "", now); err == nil {
		t.Fatal("a PDF taken where only images are")
	}
	if _, err := AcceptWithFiles(f, vals, map[string]Upload{"photo": {Name: "photo.png", Data: []byte("MZ\x90\x00 not a picture")}}, "", now); err == nil {
		t.Fatal("a program called photo.png taken")
	}
	if _, err := AcceptWithFiles(f, vals, map[string]Upload{"photo": {Name: "x.png", Data: pngBytes(t)},
		"receipt": {Name: "r.pdf", Data: []byte("%PDF-1.4 /JavaScript (app.alert(1)) %%EOF")}}, "", now); err == nil {
		t.Fatal("a PDF that runs script taken")
	}
	pic := pngBytes(t)
	s, err := AcceptWithFiles(f, vals, map[string]Upload{"photo": {Name: "../../etc/damage.png", Data: pic},
		"receipt": {Name: "receipt.pdf", Data: []byte(aPDF)}}, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Files) != 2 || s.Files[0].Format != "png" || strings.Contains(s.Files[0].Name, "/") {
		t.Fatalf("%+v", s.Files)
	}
	dir := t.TempDir()
	st, _ := Open(dir)
	if err := st.Put(s); err != nil {
		t.Fatal(err)
	}
	ref, data, err := st.File("claim", s.ID, "photo")
	if err != nil || !bytes.Equal(data, pic) || ref.MIME() != "image/png" || strings.Contains(ref.DownloadName(s.ID), "etc") {
		t.Fatalf("%+v %v %s", ref, err, ref.DownloadName(s.ID))
	}
	// Changed on disk: not given back as what was sent.
	files, _ := st.filesDir("claim", s.ID)
	if err := os.WriteFile(filepath.Join(files, "photo"), []byte("swapped"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.File("claim", s.ID, "photo"); err == nil {
		t.Fatal("a changed file was given back")
	}
	if _, _, err := st.File("claim", s.ID, "../photo"); err == nil {
		t.Fatal("a path for a field")
	}
	// Deleted with it.
	if err := st.Delete("claim", s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files); !os.IsNotExist(err) {
		t.Fatal("a deleted submission's files stayed")
	}
}

// Too much is refused, and a field may take only kinds there are.
func TestUploadsAreBounded(t *testing.T) {
	f := claimForm()
	big := append(pngBytes(t), make([]byte, MaxFileBytes)...)
	if _, err := AcceptWithFiles(f, sent(map[string]string{"name": "Ana"}),
		map[string]Upload{"photo": {Name: "x.png", Data: big}}, "", time.Now()); err == nil {
		t.Fatal("a file over the limit")
	}
	f.Fields[1].Accept = []string{"executable"}
	if err := f.Validate(); err == nil {
		t.Fatal("a kind that is not one")
	}
	if !claimForm().HasFiles() || !strings.Contains(Embed(claimForm()), `enctype="multipart/form-data"`) {
		t.Fatal("a form taking files is not sent as one")
	}
	if got := claimForm().Fields[1].AcceptTypes(); got != "image/*" {
		t.Fatalf("%q", got)
	}
}

// The files kept for every form together have a ceiling. Nothing bounded
// them: one address sending pictures at the rate the throttle allows kept
// 338 MB an hour, on the disk the content store is on, for the whole
// retention period, and a few hundred addresses would fill it.
func TestTheFilesKeptHaveACeiling(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pic := pngBytes(t)
	st.FileCeiling = int64(2*len(pic) + len(pic)/2)
	f := claimForm()
	put := func() error {
		t.Helper()
		sub, err := AcceptWithFiles(f, sent(map[string]string{"name": "Ana"}),
			map[string]Upload{"photo": {Name: "x.png", Data: pic}}, "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return st.Put(sub)
	}
	for i := 0; i < 2; i++ {
		if err := put(); err != nil {
			t.Fatalf("picture %d, under the ceiling: %v", i+1, err)
		}
	}
	if err := put(); !errors.Is(err, ErrFilesFull) {
		t.Fatalf("a third picture past the ceiling: %v", err)
	}
	subs, _ := st.List("claim")
	if len(subs) != 2 {
		t.Fatalf("%d submissions kept, not two", len(subs))
	}
	if kept, _ := filepath.Glob(filepath.Join(st.dir, "claim", "*.files")); len(kept) != 2 {
		t.Fatalf("the refused submission left files behind: %v", kept)
	}
	// What carries no file is not held up by the files.
	note := &Form{Name: "note", Notice: "Kept 30 days.", Fields: []Field{{Name: "text", Label: "Text", Kind: Para}}}
	sub, err := Accept(note, sent(map[string]string{"text": "Hello"}), "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(sub); err != nil {
		t.Fatalf("a submission with no file, at the ceiling: %v", err)
	}
	// Deleting one makes room for one.
	if err := st.Delete("claim", subs[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := put(); err != nil {
		t.Fatalf("a picture after one was deleted: %v", err)
	}
	if (&Store{}).fileCeiling() != MaxKeptFileBytes {
		t.Fatal("a store that says nothing has no ceiling")
	}
}
