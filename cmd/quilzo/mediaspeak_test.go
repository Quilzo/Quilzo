// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/media"
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
