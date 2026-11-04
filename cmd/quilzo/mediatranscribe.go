// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/provenance"
)

// Captions drafted by a model, from a recording's words.
//
//	quilzo media transcribe RECORDING --lang en --author WHO
//
// # A draft, never attached
//
// A video with no captions does not publish (WCAG 1.2.2), and writing them
// by hand is the hour nobody has. A model hearing the words saves most of
// it. It does not save all of it: a transcript has the words and not the
// door closing, who is speaking, or the name it misheard, and captions are
// for exactly those. So the transcript is stored as a caption file, marked
// as made by a model, and not attached: a person reads it, mends it, and
// attaches it (quilzo media captions VIDEO FILE --lang en), and attaching it
// is the person saying it is right.
//
// # Where it goes
//
// Through the gateway's routes that transcribe, and only those allowed
// personal data: a recording's voices cannot be masked (internal/gateway
// transcribe.go). A model on this machine (whisper.cpp, Speaches) is the
// route that needs no agreement with anybody.

func mediaTranscribe(root string, args []string) error {
	fs := flag.NewFlagSet("transcribe", flag.ContinueOnError)
	lang := fs.String("lang", "", "the language it is spoken in, as two letters: en, fr")
	author := fs.String("author", "", "the person accountable for these captions")
	// The flags on either side of what it acts on, as `media captions` takes
	// them. Read from the front only,
	// `quilzo media transcribe --lang en --author WHO ID` was answered with
	// the usage line.
	rest, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: quilzo media transcribe RECORDING --lang en --author WHO")
	}
	who := strings.TrimSpace(*author)
	if who == "" {
		return errBlocked{fmt.Errorf("--author is required: someone has to be accountable for " +
			"captions a model drafted, and that is never the tool")}
	}
	tag := strings.ToLower(strings.TrimSpace(*lang))
	if tag != "" && !reLang.MatchString(tag) {
		return fmt.Errorf("%q is not a language code, like en or fr", tag)
	}
	caller := resolveCaller(root, flagToken)
	if err := mayStoreMade(root, caller, "a caption draft"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rec, f, model, err := transcribeRecording(ctx, root, caller.Name, rest[0], tag, who)
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("media.transcribe", "/", audit.Success, map[string]string{
		"recording": shortID(rec.ID), "captions": shortID(f.ID), "model": model, "lang": tag}))
	if w.JSON(f) {
		return nil
	}
	w.Human("drafted %s%s%s from %s\n", bold, f.Name, reset, rec.Name)
	w.Human("  %srecorded as %s by %s, for %s%s\n", dim, f.Origin.SourceType, model, who, reset)
	w.Human("  %sid %s%s\n", dim, f.ID, reset)
	w.Human("\n  A model heard the words, not the door closing nor who is speaking. Read it, mend it,\n")
	if rec.Kind == media.Video {
		w.Human("  then attach it:\n")
		w.Human("    quilzo media captions %s %s --lang %s\n", shortID(rec.ID), shortID(f.ID), orDefault(tag, "LANG"))
	} else {
		// A sound has nothing to attach captions to, and no section plays
		// one yet. This said to put the words "on the page that plays it",
		// and there was no such page.
		w.Human("  then place it by hand: no section plays a recording yet, so link /media/%s\n", rec.ID)
		w.Human("  from a page and put these words beside the link, as its transcript\n")
	}
	return nil
}

// tooBigToHear says why a recording cannot be sent to be transcribed as it
// is, and how to get under the limit: why is what taking its sound out
// said, nil when there is no ffmpeg to take it out with.
func tooBigToHear(rec media.File, size int, why error) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is %d MB, and a recording sent to be transcribed is at most %d MB, the most the "+
		"transcription endpoints take. ", shortID(rec.ID), (size+1<<20-1)>>20, assist.MaxTranscribeBytes>>20)
	if why != nil {
		fmt.Fprintf(&b, "Its sound alone is all they hear, and it could not be sent: %v", why)
		return errors.New(b.String())
	}
	b.WriteString("Its sound alone is all they hear, about fifteen MB an hour, and it is taken out here when " +
		"ffmpeg is installed, which it is not. Install it, or take the sound out, store it and transcribe that:\n" +
		"  ffmpeg -i RECORDING -vn -ac 1 -ar 16000 -b:a 32k sound.mp3\n" +
		"  quilzo media add sound.mp3\n" +
		"  quilzo media transcribe SOUND --lang LANG --author WHO")
	if rec.Kind == media.Video {
		fmt.Fprintf(&b, "\nThe draft is timed as the video is, so it attaches to it: quilzo media captions %s DRAFT --lang LANG",
			shortID(rec.ID))
	}
	return errors.New(b.String())
}

// transcribeRecording drafts a recording's captions and stores them,
// marked, unattached.
func transcribeRecording(ctx context.Context, root, person, id, lang, author string) (media.File, media.File, string, error) {
	lib, err := openMedia(root)
	if err != nil {
		return media.File{}, media.File{}, "", err
	}
	rec, body, err := lib.Get(id)
	if err != nil {
		return media.File{}, media.File{}, "", err
	}
	if rec.Kind != media.Video && rec.Kind != media.Audio {
		return media.File{}, media.File{}, "", fmt.Errorf("%s is a %s; a recording is a video or a sound", shortID(rec.ID), rec.Kind)
	}
	name := "recording" + rec.Extension()
	if len(body) > assist.MaxTranscribeBytes {
		// The sound alone, which is all a transcription hears: see
		// media.SoundFrom. This refused anything over the limit with "send
		// its sound alone, smaller", and nothing here took it out.
		sound, err := media.SoundFrom(body, assist.MaxTranscribeBytes)
		if sound == nil {
			return media.File{}, media.File{}, "", errBlocked{tooBigToHear(rec, len(body), err)}
		}
		body, name = sound, "recording.m4a"
	}
	gw, _, err := modelGateway(root)
	if err != nil {
		return media.File{}, media.File{}, "", err
	}
	if gw == nil {
		return media.File{}, media.File{}, "", errBlocked{fmt.Errorf("no route transcribes: quilzo gateway " +
			"route add NAME --transcribes --personal ... (a model on this machine needs no agreement)")}
	}
	consumers := []string{"media"}
	if person != "" {
		consumers = append(consumers, "person:"+person)
	}
	// The endpoints take a language's two letters: pt-BR is spoken pt.
	spoken, _, _ := strings.Cut(lang, "-")
	if len(spoken) != 2 {
		spoken = ""
	}
	vtt, model, _, err := gw.Transcribe(ctx, consumers, body, name, spoken, rec.Seconds)
	if err != nil {
		return media.File{}, media.File{}, "", errBlocked{err}
	}
	// Accepted exactly the way an upload is: a model's reply is untrusted
	// input, and a caption file is checked to be WebVTT and nothing else.
	base := strings.TrimSuffix(rec.Name, rec.Extension())
	f, err := media.Accept(base+"-captions-draft.vtt", []byte(vtt), time.Now())
	if err != nil || f.Kind != media.Caption {
		return media.File{}, media.File{}, "", errBlocked{fmt.Errorf("the transcript is not a caption file "+
			"this can store: %v", err)}
	}
	f.Source = "model:" + model
	f.UploadedBy = author
	// The mark, as for a picture: not a flag, not a default.
	f.Origin = media.Origin{
		SourceType:  string(provenance.TrainedAlgorithmicMedia),
		Model:       model,
		Instruction: "transcribe " + shortID(rec.ID),
		Author:      author,
	}
	if err := lib.Put(f, []byte(vtt)); err != nil {
		return media.File{}, media.File{}, "", err
	}
	stored, err := lib.Stat(f.ID)
	if err != nil {
		return media.File{}, media.File{}, "", err
	}
	return rec, stored, model, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
