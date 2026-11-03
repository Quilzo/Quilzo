// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
)

// Text read aloud is stored marked as a synthetic voice, with the person
// accountable, and with its words as its transcript.
func TestTextReadAloudIsMarkedAsASyntheticVoice(t *testing.T) {
	root := demoStore(t)
	frame := append([]byte{0xFF, 0xFB, 0x90, 0x64}, make([]byte, 400)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(frame)
	}))
	defer srv.Close()
	if err := cmdMedia(root, []string{"speak", "Welcome to Marginalia.", "--author", "dana"}); err == nil {
		t.Fatal("spoke with no route")
	}
	if err := cmdGateway(root, []string{"route", "add", "voice", "--url", srv.URL + "/v1", "--model", "kokoro", "--speaks"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdMedia(root, []string{"speak", "Welcome to Marginalia."}); err == nil {
		t.Fatal("spoke with nobody accountable")
	}
	if err := cmdMedia(root, []string{"speak", "Welcome to Marginalia, where ink is mixed by hand.",
		"--voice", "af_bella", "--author", "dana"}); err != nil {
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
	var spoken media.File
	for _, f := range files {
		if f.Kind == media.Audio && strings.HasPrefix(f.Name, "welcome-to-marginalia") {
			spoken = f
		}
	}
	if spoken.ID == "" || spoken.Origin.SourceType != string(provenance.TrainedAlgorithmicMedia) ||
		spoken.Origin.Model != "kokoro" || spoken.Origin.Author != "dana" ||
		spoken.Alt != "Welcome to Marginalia, where ink is mixed by hand." {
		t.Fatalf("not stored, marked, with its words: %+v", spoken)
	}
}

// What speak and transcribe say after making a recording's words is what a
// person has to do, not a player and a transcript a page would show by
// itself: no section plays a recording, and nothing shows a recording's
// words for it. Speak said "in a page: /media/ID, with its words beside it
// as its transcript", and transcribing a recording said to put its words
// "on the page that plays it", and there is no such page.
func TestARecordingsHintSaysItIsPlacedByHand(t *testing.T) {
	root := demoStore(t)
	frame := append([]byte{0xFF, 0xFB, 0x90, 0x64}, make([]byte, 400)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/audio/transcriptions" {
			w.Write([]byte("WEBVTT\n\n00:00.000 --> 00:02.000\nWelcome to Marginalia.\n"))
			return
		}
		w.Write(frame)
	}))
	defer srv.Close()
	if err := cmdGateway(root, []string{"route", "add", "voice", "--url", srv.URL + "/v1", "--model", "kokoro",
		"--speaks", "--personal"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdGateway(root, []string{"route", "add", "ears", "--url", srv.URL + "/v1", "--model", "whisper",
		"--transcribes", "--personal"}); err != nil {
		t.Fatal(err)
	}
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	if err := cmdMedia(root, []string{"speak", "Welcome to Marginalia.", "--author", "dana"}); err != nil {
		t.Fatal(err)
	}
	said := buf.String()
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := lib.List()
	var spoken media.File
	for _, f := range files {
		if f.Kind == media.Audio {
			spoken = f
		}
	}
	if spoken.ID == "" {
		t.Fatal("nothing was spoken")
	}
	buf.Reset()
	if err := cmdMedia(root, []string{"transcribe", spoken.ID, "--lang", "en", "--author", "dana"}); err != nil {
		t.Fatal(err)
	}
	heard := buf.String()
	for name, hint := range map[string]string{"speak": said, "transcribe": heard} {
		for _, promise := range []string{"with its words beside it as its transcript", "the page that plays it"} {
			if strings.Contains(hint, promise) {
				t.Errorf("%s promises what no page does (%q):\n%s", name, promise, hint)
			}
		}
		if !strings.Contains(hint, "no section plays a recording") || !strings.Contains(hint, "by hand") {
			t.Errorf("%s does not say the recording and its words are placed by hand:\n%s", name, hint)
		}
	}
	if !strings.Contains(said, "/media/"+spoken.ID) {
		t.Errorf("speak does not say where the recording is served:\n%s", said)
	}
}
