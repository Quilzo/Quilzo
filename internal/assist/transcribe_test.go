// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const draftVTT = "WEBVTT\n\n00:00.000 --> 00:02.000\nOpened ink cannot be returned.\n"

// A recording goes as a form, with the model, the language and a request
// for WebVTT; the timed text comes back as it was written.
func TestARecordingIsTranscribedAsWebVTT(t *testing.T) {
	type form struct{ model, format, lang, file, body string }
	seen := make(chan form, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audio/transcriptions" {
			t.Errorf("%s", r.URL.Path)
		}
		f, h, err := r.FormFile("file")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(f)
		seen <- form{r.FormValue("model"), r.FormValue("response_format"), r.FormValue("language"), h.Filename, string(b)}
		w.Write([]byte("\uFEFF" + draftVTT))
	}))
	defer srv.Close()
	m := &HTTPModel{BaseURL: srv.URL + "/v1", APIKey: "k", Model: "whisper", Client: srv.Client()}
	vtt, _, err := m.Transcribe(context.Background(), []byte("RIFF....WAVE"), "recording.wav", "en")
	if err != nil || vtt != draftVTT {
		t.Fatalf("%q %v", vtt, err)
	}
	if f := <-seen; f != (form{"whisper", "vtt", "en", "recording.wav", "RIFF....WAVE"}) {
		t.Errorf("%+v", f)
	}
}

// What is not a recording to send, or not WebVTT back, is refused.
func TestWhatIsNotARecordingOrNotCaptionsIsRefused(t *testing.T) {
	reply := "plain text, no timings"
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(reply))
	}))
	defer srv.Close()
	m := &HTTPModel{BaseURL: srv.URL, APIKey: "k", Model: "whisper", Client: srv.Client()}
	if _, _, err := m.Transcribe(context.Background(), []byte("x"), "recording.wav", ""); err == nil {
		t.Error("text without timings was taken for captions")
	}
	for name, c := range map[string]struct {
		audio []byte
		file  string
		lang  string
	}{
		"empty":         {nil, "a.wav", ""},
		"too big":       {make([]byte, MaxTranscribeBytes+1), "a.wav", ""},
		"not a sound":   {[]byte("x"), "a.exe", ""},
		"a path":        {[]byte("x"), "../a.wav", ""},
		"long language": {[]byte("x"), "a.wav", "english"},
	} {
		if _, _, err := m.Transcribe(context.Background(), c.audio, c.file, c.lang); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if calls != 1 {
		t.Errorf("a refused recording was sent: %d calls", calls)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
	}))
	defer srv2.Close()
	m.BaseURL, m.Client = srv2.URL, srv2.Client()
	var se *StatusError
	if _, _, err := m.Transcribe(context.Background(), []byte("x"), "a.wav", ""); !errors.As(err, &se) || se.Code != 413 {
		t.Errorf("%v", err)
	}
	m.Wire = WireAnthropic
	if _, _, err := m.Transcribe(context.Background(), []byte("x"), "a.wav", ""); err == nil {
		t.Error("Anthropic was asked to transcribe")
	}
}
