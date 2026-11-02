// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Text goes to /audio/speech with its voice, MP3 is asked for, and what
// is not MP3 coming back is refused.
func TestTextIsReadAloudAsMP3(t *testing.T) {
	reply := []byte("ID3\x04\x00\x00\x00\x00\x00\x00rest-of-an-mp3")
	var asked map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audio/speech" {
			t.Errorf("%s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&asked)
		w.Write(reply)
	}))
	defer srv.Close()
	m := &HTTPModel{BaseURL: srv.URL + "/v1", APIKey: "k", Model: "tts", Client: srv.Client()}
	audio, u, err := m.Speak(context.Background(), "Welcome to the shop.", "alloy")
	if err != nil || string(audio) != string(reply) || u.In == 0 {
		t.Fatalf("%q %+v %v", audio, u, err)
	}
	if asked["model"] != "tts" || asked["input"] != "Welcome to the shop." || asked["voice"] != "alloy" || asked["response_format"] != "mp3" {
		t.Errorf("%v", asked)
	}
	reply = []byte("<html>not a sound</html>")
	if _, _, err := m.Speak(context.Background(), "Welcome.", "alloy"); err == nil {
		t.Error("what is not MP3 was taken for speech")
	}
	for name, c := range map[string][2]string{
		"empty": {" ", "alloy"}, "too long": {strings.Repeat("x", MaxSpeech+1), "alloy"},
		"bad voice": {"hi", "../alloy"}, "no voice": {"hi", ""},
	} {
		if _, _, err := m.Speak(context.Background(), c[0], c[1]); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	m.Wire = WireAnthropic
	if _, _, err := m.Speak(context.Background(), "hi", "alloy"); err == nil {
		t.Error("Anthropic was asked to speak")
	}
}
