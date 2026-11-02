// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/provenance"
)

// A video's captions are drafted by a model through a route that
// transcribes, stored marked as a model's and never attached: attaching
// them is a person saying they are right. A route not allowed personal
// data is never sent a recording.
func TestAVideosCaptionsAreDraftedNotAttached(t *testing.T) {
	root := demoStore(t)
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		if r.URL.Path != "/v1/audio/transcriptions" || r.FormValue("response_format") != "vtt" || r.FormValue("language") != "en" {
			t.Errorf("%s %v", r.URL.Path, r.Form)
		}
		w.Write([]byte("WEBVTT\n\n00:00.000 --> 00:02.000\nOpened ink cannot be returned.\n"))
	}))
	defer srv.Close()
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	clip := append([]byte{0, 0, 0, 0x18}, []byte("ftypisom")...)
	clip = append(clip, bytes.Repeat([]byte{0}, 64)...)
	video, err := media.Accept("returns-explained.mp4", clip, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(video, clip); err != nil {
		t.Fatal(err)
	}

	// No route transcribes, then one that may not be sent a recording.
	if err := cmdMedia(root, []string{"transcribe", video.ID, "--lang", "en", "--author", "dana"}); err == nil {
		t.Fatal("transcribed with no route")
	}
	if err := cmdGateway(root, []string{"route", "add", "hosted", "--url", srv.URL + "/v1", "--model", "whisper",
		"--transcribes"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdMedia(root, []string{"transcribe", video.ID, "--lang", "en", "--author", "dana"}); err == nil ||
		!strings.Contains(err.Error(), "personal data") || atomic.LoadInt64(&calls) != 0 {
		t.Fatalf("a recording went to a route not allowed personal data: %v", err)
	}
	if err := cmdMedia(root, []string{"transcribe", video.ID, "--lang", "en"}); err == nil {
		t.Fatal("drafted with nobody accountable")
	}

	if err := cmdGateway(root, []string{"route", "add", "here", "--url", srv.URL + "/v1", "--model", "whisper-local",
		"--transcribes", "--personal"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdMedia(root, []string{"transcribe", video.ID, "--lang", "en", "--author", "dana"}); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&calls) != 1 {
		t.Fatalf("%d calls", calls)
	}
	files, err := lib.List()
	if err != nil {
		t.Fatal(err)
	}
	var draft media.File
	for _, f := range files {
		if f.Kind == media.Caption && strings.Contains(f.Name, "returns-explained-captions-draft") {
			draft = f
		}
	}
	if draft.ID == "" || draft.Origin.SourceType != string(provenance.TrainedAlgorithmicMedia) ||
		draft.Origin.Model != "whisper-local" || draft.Origin.Author != "dana" {
		t.Fatalf("the draft is not stored, marked: %+v", draft)
	}
	if v, _ := lib.Stat(video.ID); len(v.Tracks) != 0 {
		t.Fatal("a model's captions were attached without a person")
	}
	// A person attaches them, once read.
	if err := cmdMedia(root, []string{"captions", video.ID, draft.ID, "--lang", "en"}); err != nil {
		t.Fatal(err)
	}
	if v, _ := lib.Stat(video.ID); !v.Captions() {
		t.Fatal("attached captions do not count")
	}
}
