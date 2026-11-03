// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
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

// A recording over the 25 MB a transcription endpoint takes is sent as its
// sound alone, which for an hour of video is a fraction of that. The
// library takes a video of 512 MB, and captions could be drafted only for
// one of a few minutes: anything longer was refused with "send its sound
// alone, smaller", which said neither why nor how. With no ffmpeg to take
// the sound out, the refusal says what the limit is, why, and how to get
// under it by hand.
func TestALongVideosCaptionsAreDraftedFromItsSound(t *testing.T) {
	root := demoStore(t)
	var sent struct {
		name string
		size int
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, h, err := r.FormFile("file")
		if err != nil {
			t.Errorf("no file: %v", err)
			return
		}
		b, _ := io.ReadAll(f)
		sent.name, sent.size = h.Filename, len(b)
		w.Write([]byte("WEBVTT\n\n00:00.000 --> 00:02.000\nA tone.\n"))
	}))
	defer srv.Close()
	if err := cmdGateway(root, []string{"route", "add", "here", "--url", srv.URL + "/v1", "--model", "whisper-local",
		"--transcribes", "--personal"}); err != nil {
		t.Fatal(err)
	}
	lib, err := openMedia(root)
	if err != nil {
		t.Fatal(err)
	}
	store := func(name string, body []byte) media.File {
		t.Helper()
		f, err := media.Accept(name, body, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := lib.Put(f, body); err != nil {
			t.Fatal(err)
		}
		return f
	}

	// With nothing to take the sound out with, the refusal says what to do.
	path := os.Getenv("PATH")
	t.Setenv("PATH", "/nonexistent")
	padded := append(append([]byte{0, 0, 0, 0x18}, []byte("ftypisom")...), bytes.Repeat([]byte{0}, 26<<20)...)
	big := store("all-hands.mp4", padded)
	err = cmdMedia(root, []string{"transcribe", big.ID, "--lang", "en", "--author", "dana"})
	for _, want := range []string{"at most 25 MB", "the most the transcription endpoints take", "ffmpeg",
		"ffmpeg -i", "quilzo media add", "quilzo media captions " + shortID(big.ID)} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if sent.size != 0 {
		t.Fatal("a recording over the limit was sent")
	}
	t.Setenv("PATH", path)

	// With ffmpeg, the sound is taken out and sent, and the draft is the
	// video's to attach.
	bin, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("no ffmpeg here, so the sound cannot be taken out; the refusal above is what this machine gets")
	}
	out := filepath.Join(t.TempDir(), "long.mp4")
	if err := exec.Command(bin, "-v", "error", "-f", "lavfi", "-i", "testsrc=size=640x480:rate=25:duration=5,noise=alls=100:allf=t",
		"-f", "lavfi", "-i", "sine=frequency=440:duration=5", "-c:v", "mpeg4", "-q:v", "1", "-c:a", "aac", "-shortest", "-y", out).Run(); err != nil {
		t.Skipf("this ffmpeg cannot make the fixture: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= assist.MaxTranscribeBytes {
		t.Fatalf("the fixture is %d bytes, under the limit, so this checks nothing", len(body))
	}
	long := store("long.mp4", body)
	if err := cmdMedia(root, []string{"transcribe", long.ID, "--lang", "en", "--author", "dana"}); err != nil {
		t.Fatalf("a video over the limit was not heard: %v", err)
	}
	if sent.name != "recording.m4a" || sent.size == 0 || sent.size > assist.MaxTranscribeBytes {
		t.Errorf("sent %q, %d bytes, not the sound alone", sent.name, sent.size)
	}
}
