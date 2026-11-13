// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// postUpload sends a file to the media library as its form does.
func postUpload(t *testing.T, srv *Server, token string, body []byte, fields map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "shot.png")
	_, _ = fw.Write(body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/media/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("upload answered %d: %s", w.Code, w.Body.String())
	}
	loc, _ := url.QueryUnescape(w.Header().Get("Location"))
	return loc
}

// Uploading a picture the library already holds keeps the description it
// has. The library is content-addressed, so a second upload of the same logo
// is the same file, and it silently replaced the first person's description
// (or, ticked decorative, erased it) on every page using it, while saying
// only "stored". It now says the file was there and what it is described
// as, and changing that is asked for, not a side effect.
func TestUploadingAPictureAgainKeepsItsDescription(t *testing.T) {
	srv, token := setup(t)
	id := withPicture(t, srv)
	lib, _ := srv.Media.Library()
	_, body, err := lib.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	stat := func() media.File {
		// A library of its own, so what is read is what is on disk.
		fresh, err := medialib.Open(lib.Dir())
		if err != nil {
			t.Fatal(err)
		}
		f, err := fresh.Stat(id)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	alt := func() string { return stat().Alt }

	said := postUpload(t, srv, token, body, map[string]string{"alt": "Somebody else's words"})
	if alt() != "a test photograph" {
		t.Errorf("a second upload replaced the description with %q", alt())
	}
	if !strings.Contains(said, "already in the library") || !strings.Contains(said, "a test photograph") {
		t.Errorf("the upload did not say the file was there: %s", said)
	}
	postUpload(t, srv, token, body, map[string]string{"decorative": "1"})
	if alt() != "a test photograph" {
		t.Errorf("a decorative upload erased the description: %q", alt())
	}
	if f := stat(); f.Rights.Holder != "a photographer" {
		t.Errorf("a second upload lost the file's rights: %+v", f.Rights)
	}

	postUpload(t, srv, token, body, map[string]string{"alt": "A new description", "replace_alt": "1"})
	if alt() != "A new description" {
		t.Errorf("asking to replace the description did not: %q", alt())
	}
}
