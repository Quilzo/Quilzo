// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
)

// Attaching and taking off captions is recorded as whoever the command
// acts as: the holder of the --token given, not whoever QUILZO_TOKEN or
// the token file names. An audit of this command read its calls of
// resolveCaller with an empty token as recording the wrong person; an empty
// token there means the --token, and this holds it to that.
func TestCaptionsAreRecordedAsTheTokenGiven(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"})
	ts, _ := loadTokens(root)
	danas, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	sams, _, err := ts.Issue("sam", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", sams)
	oldToken := flagToken
	t.Cleanup(func() { flagToken = oldToken })
	flagToken = danas

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
	vtt := []byte("WEBVTT\n\n00:00.000 --> 00:02.000\nOpened ink cannot be returned.\n")
	track, err := media.Accept("returns-explained.vtt", vtt, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(video, clip); err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(track, vtt); err != nil {
		t.Fatal(err)
	}

	var seen []audit.Record
	oldWritten := auditWritten
	t.Cleanup(func() { auditWritten = oldWritten })
	auditWritten = func(root string, r audit.Record) {
		if oldWritten != nil {
			oldWritten(root, r)
		}
		if r.Action == "media.captions" {
			seen = append(seen, r)
		}
	}
	if err := cmdMedia(root, []string{"captions", video.ID, track.ID, "--lang", "en"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdMedia(root, []string{"captions", video.ID, "--remove", track.ID}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("%d records of attaching and taking off captions", len(seen))
	}
	for _, r := range seen {
		if r.Principal != "dana" || !r.Verified {
			t.Errorf("%v recorded as %q (verified %v), not as the --token's dana", r.Detail, r.Principal, r.Verified)
		}
	}
}

// Captions take their flags before the two ids, between them, after them
// or on both sides, as other commands do. With the flags first the command saw no ids
// and answered with its usage line, because it read its ids only from the
// front.
func TestCaptionsTakeTheirFlagsAnywhere(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
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
	vtt := []byte("WEBVTT\n\n00:00.000 --> 00:02.000\nOpened ink cannot be returned.\n")
	track, err := media.Accept("returns-explained.vtt", vtt, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(video, clip); err != nil {
		t.Fatal(err)
	}
	if err := lib.Put(track, vtt); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--lang", "fr", "--label", "Français", video.ID, track.ID},
		{video.ID, "--lang", "de", track.ID},
		{video.ID, track.ID, "--lang", "en", "--label", "English"},
		// And on both sides: the flags after the ids were taken as ids.
		{"--lang", "es", video.ID, track.ID, "--default"},
	} {
		if err := mediaCaptions(root, args); err != nil {
			t.Fatalf("quilzo media captions %v: %v", args, err)
		}
		got, err := lib.Stat(video.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Tracks) != 1 || got.Tracks[0].Lang != args[slicesIndex(args, "--lang")+1] ||
			got.Tracks[0].Default != (slicesIndex(args, "--default") >= 0) {
			t.Errorf("quilzo media captions %v left %+v", args, got.Tracks)
		}
	}
	if err := mediaCaptions(root, []string{"--remove", track.ID, video.ID}); err != nil {
		t.Fatalf("taking it off with the flag first: %v", err)
	}
	if got, _ := lib.Stat(video.ID); len(got.Tracks) != 0 {
		t.Errorf("the track is still on: %+v", got.Tracks)
	}
	if err := mediaCaptions(root, []string{video.ID, track.ID, "extra", "--lang", "en"}); err == nil {
		t.Error("a third id was taken without a word")
	}
}

func slicesIndex(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}
