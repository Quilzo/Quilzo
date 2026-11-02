// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/form"
)

func submittedPhoto(t *testing.T, srv *Server) (form.Submission, []byte) {
	t.Helper()
	set := &form.Set{Forms: []form.Form{{Name: "claim", Notice: "Kept 30 days.", Fields: []form.Field{
		{Name: "name", Label: "Name", Kind: form.Line},
		{Name: "photo", Label: "Photo", Kind: form.File, Accept: []string{"image"}},
	}}}}
	srv.Forms = wiredForms(t, set)
	var pic bytes.Buffer
	_ = png.Encode(&pic, image.NewRGBA(image.Rect(0, 0, 3, 3)))
	f, _ := set.Get("claim")
	sub, err := form.AcceptWithFiles(f, map[string]string{"name": "Ana",
		form.StampField: fmt.Sprint(time.Now().Add(-10 * time.Second).Unix())},
		map[string]form.Upload{"photo": {Name: "<script>.png", Data: pic.Bytes()}}, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Forms.Store.Put(sub); err != nil {
		t.Fatal(err)
	}
	return sub, pic.Bytes()
}

// Staff download a file a submission carries: as an attachment, typed by
// what it is, named afresh, under a policy that runs nothing; the listing
// links it. Somebody who may only read the site cannot.
func TestStaffDownloadASubmittedFile(t *testing.T) {
	srv, token := setup(t)
	sub, pic := submittedPhoto(t, srv)
	if body := get(t, srv, "/forms?form=claim", token).Body.String(); !strings.Contains(body, "/forms/file?form=claim&amp;id="+sub.ID) {
		t.Fatal("the listing does not link the file")
	}
	w := get(t, srv, "/forms/file?form=claim&id="+sub.ID+"&field=photo", token)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), pic) {
		t.Fatalf("%d", w.Code)
	}
	h := w.Header()
	if h.Get("Content-Type") != "image/png" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment;") ||
		strings.Contains(h.Get("Content-Disposition"), "script") || !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") ||
		h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%v", h)
	}
	if w := get(t, srv, "/forms/file?form=claim&id="+sub.ID+"&field=name", token); w.Code != http.StatusNotFound {
		t.Errorf("a field with no file: %d", w.Code)
	}

	reader, rtoken := asRole(t, auth.RoleReader)
	reader.Forms = srv.Forms
	if w := get(t, reader, "/forms/file?form=claim&id="+sub.ID+"&field=photo", rtoken); w.Code == http.StatusOK {
		t.Fatal("a reader downloaded what the public sent")
	}
}
