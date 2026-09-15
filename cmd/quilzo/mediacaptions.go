// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
)

// Attaching captions to a video.
//
//	quilzo media captions VIDEO CAPTIONFILE --lang en --label English
//	quilzo media captions VIDEO --remove CAPTIONFILE
//
// # Why on the video and not on the page
//
// Captions belong to the recording, not to one placement of it. A video used
// on three pages is captioned on all three, and nobody has to remember on the
// third — the same argument renditions make for living on the picture.
//
// It also gives the accessibility gate one place to ask. A video with no
// captions is a WCAG 1.2.2 failure at Level A, which this program refuses
// rather than warns about, and a refusal that depended on which page the video
// happened to be on would be a refusal nobody could act on.

// reLang matches a BCP 47 tag conservatively.
//
// This value becomes an attribute a browser reads to decide what to offer in
// a language menu, so it is matched rather than trusted — and the subset here
// covers every tag a caption file realistically carries.
var reLang = regexp.MustCompile(`^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8}){0,2}$`)

func mediaCaptions(root string, args []string) error {
	fs := flag.NewFlagSet("captions", flag.ContinueOnError)
	lang := fs.String("lang", "", "a language tag, like en or pt-BR")
	label := fs.String("label", "",
		"what a reader picks from the player's menu")
	kind := fs.String("kind", media.TrackCaptions,
		"captions, or subtitles for a translation of the dialogue")
	asDefault := fs.Bool("default", false,
		"show this one without being asked")
	remove := fs.String("remove", "", "take a track off instead")
	rest, flags := leadingArgs(args, 2)
	if err := fs.Parse(flags); err != nil {
		return err
	}

	lib, err := openMedia(root)
	if err != nil {
		return err
	}

	if id := strings.TrimSpace(*remove); id != "" {
		if len(rest) < 1 {
			return fmt.Errorf("usage: quilzo media captions VIDEO --remove TRACK")
		}
		return removeTrack(root, rest[0], id)
	}
	if len(rest) != 2 {
		return fmt.Errorf(
			"usage: quilzo media captions VIDEO CAPTIONFILE --lang en " +
				"[--label English] [--kind captions|subtitles] [--default]")
	}

	video, err := lib.Stat(rest[0])
	if err != nil {
		return err
	}
	if video.Kind != media.Video {
		return fmt.Errorf(
			"%s is a %s; captions go on a video", shortID(video.ID), video.Kind)
	}
	track, err := lib.Stat(rest[1])
	if err != nil {
		return err
	}
	if track.Kind != media.Caption {
		return fmt.Errorf(
			"%s is a %s, and a caption track is a WebVTT file. `quilzo media "+
				"add captions.vtt` stores one", shortID(track.ID), track.Kind)
	}

	if !media.ValidTrackKind(*kind) {
		return fmt.Errorf(
			"%q is not a kind of track. captions carry the non-speech audio "+
				"too — a door closing, who is speaking — and subtitles "+
				"translate the dialogue for somebody who can hear the rest. "+
				"Only captions satisfy WCAG 1.2.2", *kind)
	}
	tag := strings.TrimSpace(*lang)
	if tag == "" {
		return fmt.Errorf(
			"--lang is required: a track with no language is one a browser " +
				"cannot offer in a menu, so a reader with two to choose from " +
				"cannot choose")
	}
	if !reLang.MatchString(tag) {
		return fmt.Errorf(
			"%q is not a language tag; they look like en, fr or pt-BR", tag)
	}

	next := media.Track{
		ID: track.ID, Lang: tag, Label: strings.TrimSpace(*label),
		Kind: *kind, Default: *asDefault,
	}
	// Replaced rather than added twice. Attaching the same file again is
	// somebody correcting its label or its language, and two tracks pointing
	// at one file would put the same language in the menu twice.
	kept := make([]media.Track, 0, len(video.Tracks)+1)
	for _, t := range video.Tracks {
		if t.ID == next.ID {
			continue
		}
		if next.Default {
			// One default, or a browser picks for itself and the answer
			// depends on which it read first.
			t.Default = false
		}
		kept = append(kept, t)
	}
	video.Tracks = append(kept, next)

	if err := putSameBytes(lib, video); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("media.captions", "/",
		audit.Success, map[string]string{
			"video": shortID(video.ID), "track": shortID(track.ID),
			"lang": tag, "kind": *kind,
		}))

	if w.JSON(video) {
		return nil
	}
	w.Human("%s%s%s now carries %s captions\n", bold, video.Name, reset, tag)
	for _, t := range video.Tracks {
		mark := " "
		if t.Default {
			mark = "*"
		}
		w.Human("  %s%s %-8s %-10s %s%s\n", dim, mark, t.Lang, t.Kind,
			shortID(t.ID), reset)
	}
	if !video.Captions() {
		w.Human("  %sthere is still no captions track, so a page showing "+
			"this will not publish%s\n", yellow, reset)
	}
	return nil
}

func removeTrack(root, videoID, trackID string) error {
	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	video, err := lib.Stat(videoID)
	if err != nil {
		return err
	}
	kept := make([]media.Track, 0, len(video.Tracks))
	var found bool
	for _, t := range video.Tracks {
		if strings.HasPrefix(t.ID, trackID) {
			found = true
			continue
		}
		kept = append(kept, t)
	}
	if !found {
		return fmt.Errorf("%s carries no track %s",
			shortID(video.ID), shortID(trackID))
	}
	video.Tracks = kept
	if err := putSameBytes(lib, video); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("media.captions", "/",
		audit.Success, map[string]string{
			"video": shortID(video.ID), "removed": shortID(trackID),
		}))
	if w.JSON(video) {
		return nil
	}
	w.Human("  %stook it off %s%s\n", dim, video.Name, reset)
	if !video.Captions() {
		w.Human("  %sthat was the last captions track, so a page showing "+
			"this will not publish%s\n", yellow, reset)
	}
	return nil
}

// putSameBytes writes a record back without touching the file it describes.
//
// The bytes are read and handed straight back because Put refuses a record
// whose id is not the hash of what is being written — which is the check that
// stops a caller editing the metadata and the content out of agreement.
func putSameBytes(lib interface {
	Get(string) (media.File, []byte, error)
	Put(media.File, []byte) error
}, f media.File) error {
	_, body, err := lib.Get(f.ID)
	if err != nil {
		return err
	}
	return lib.Put(f, body)
}
