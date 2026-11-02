// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/form"
)

func multipartPost(t *testing.T, st *Site, path string, fields map[string]string, files map[string][]byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	for k, data := range files {
		fw, err := mw.CreateFormFile(k, k+".bin")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write(data)
	}
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.RemoteAddr = "203.0.113.9:1234"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

// A form that takes a file is offered as one, takes a picture sent with
// it, keeps it with the submission, and refuses what is not one.
func TestAFormTakesAFileOnThePublicSite(t *testing.T) {
	st, fs := withForm(t)
	set := &form.Set{Forms: []form.Form{{Name: "contact", Notice: "Kept 30 days.", Fields: []form.Field{
		{Name: "name", Label: "Name", Kind: form.Line, Required: true},
		{Name: "photo", Label: "Photo", Kind: form.File, Required: true, Accept: []string{"image"}},
	}}}}
	st.Forms.Set = func() (*form.Set, error) { return set, nil }
	data := st.formData("contact")
	if data["multipart"] != true || data["fields"].([]any)[1].(map[string]any)["file"] != true {
		t.Fatalf("%v", data)
	}
	var pic bytes.Buffer
	_ = png.Encode(&pic, image.NewRGBA(image.Rect(0, 0, 2, 2)))
	stamp := fmt.Sprint(time.Now().Add(-5 * time.Second).Unix())
	if w := multipartPost(t, st, "/form/contact", map[string]string{"name": "Ana", form.StampField: stamp},
		map[string][]byte{"photo": []byte("#!/bin/sh\nrm -rf /\n")}); w.Code < 400 {
		t.Fatalf("a script taken as a photo: %d", w.Code)
	}
	w := multipartPost(t, st, "/form/contact", map[string]string{"name": "Ana", form.StampField: stamp},
		map[string][]byte{"photo": pic.Bytes()})
	if w.Code >= 400 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	subs, _ := fs.List("contact")
	if len(subs) != 1 || len(subs[0].Files) != 1 {
		t.Fatalf("%+v", subs)
	}
	if _, got, err := fs.File("contact", subs[0].ID, "photo"); err != nil || !bytes.Equal(got, pic.Bytes()) {
		t.Fatalf("%v", err)
	}
	// Without the file, as a plain post: required, so refused.
	if w := post(t, st, "/form/contact", map[string][]string{"name": {"Ana"}, form.StampField: {stamp}}); w.Code < 400 {
		t.Fatalf("taken without its file: %d", w.Code)
	}
	if !strings.Contains(fmt.Sprint(data["fields"]), "image/*") {
		t.Fatal("the picker is not told what it takes")
	}
}
