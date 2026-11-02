// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/provenance"
)

// A made video is stored as an upload is, marked as generated, with the
// person accountable and the prompt; what is not a video is refused.
func TestAMadeVideoIsStoredMarked(t *testing.T) {
	root := demoStore(t)
	mp4 := append([]byte("\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"), make([]byte, 64)...)
	f, err := storeFilmed(root, mp4, "A slow pan over a bakery at dawn", "veo-x", "", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if f.Origin.SourceType != string(provenance.TrainedAlgorithmicMedia) || f.Origin.Author != "dana" ||
		f.Origin.Model != "veo-x" || !strings.HasPrefix(f.Name, "a-slow-pan-over-a") {
		t.Fatalf("%+v", f)
	}
	if _, err := storeFilmed(root, []byte("<html>not a video</html>"), "x", "veo-x", "", "dana"); err == nil {
		t.Fatal("stored what is not a video")
	}
	if err := cmdMedia(root, []string{"film", "a video"}); err == nil {
		t.Fatal("made without anybody accountable")
	}
	if err := cmdMedia(root, []string{"film", "a video", "--author", "dana"}); err == nil || !strings.Contains(err.Error(), "no route makes video") {
		t.Fatalf("%v", err)
	}
}
