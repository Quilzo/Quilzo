// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/provenance"
)

// Text read aloud by a model, and the mark that cannot be left off.
//
//	quilzo media speak "text" --voice alloy --author WHO
//	quilzo media speak @article.txt --voice alloy --author WHO
//
// An audio version of an article, a shop's welcome, a voice-over for a
// video. The recording is stored as a synthetic voice (EU AI Act Article
// 50: a person hearing it is owed knowing it is not a person), by the
// same rule as a generated picture: the function that stores the bytes
// writes the mark, and no caller can leave it off. Its words travel with
// it as its transcript, which is what a recording on a page needs for
// somebody who cannot hear it (WCAG 1.2.1).

func mediaSpeak(root string, args []string) error {
	fs := flag.NewFlagSet("speak", flag.ContinueOnError)
	voice := fs.String("voice", "alloy", "the voice, as the route's model names its voices")
	author := fs.String("author", "", "the person accountable for publishing this")
	name := fs.String("name", "", "what to call the recording in the library")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: quilzo media speak \"text\" | @FILE --voice VOICE --author WHO")
	}
	who := strings.TrimSpace(*author)
	if who == "" {
		return errBlocked{fmt.Errorf("--author is required: someone has to be accountable for a " +
			"synthetic voice, and that is never the tool")}
	}
	text := rest[0]
	if strings.HasPrefix(text, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(text, "@"))
		if err != nil {
			return err
		}
		text = string(b)
	}
	text = strings.TrimSpace(text)
	if text == "" || len(text) > assist.MaxSpeech {
		return errBlocked{fmt.Errorf("what is read aloud is 1 to %d characters; this is %d", assist.MaxSpeech, len(text))}
	}
	caller := resolveCaller(root, flagToken)
	if err := mayStoreMade(root, caller, "a recording"); err != nil {
		return err
	}
	gw, _, err := modelGateway(root)
	if err != nil {
		return err
	}
	if gw == nil || !gw.Speaks() {
		return errBlocked{fmt.Errorf("no route reads text aloud: quilzo gateway route add NAME --speaks ...")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	consumers := []string{"media", "person:" + caller.Name}
	audio, model, _, err := gw.Speak(ctx, consumers, text, strings.TrimSpace(*voice))
	if err != nil {
		return errBlocked{err}
	}
	f, err := storeSpoken(root, audio, text, model, strings.TrimSpace(*voice), strings.TrimSpace(*name), who)
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("media.speak", "/", audit.Success, map[string]string{
		"id": shortID(f.ID), "model": model, "voice": strings.TrimSpace(*voice), "chars": fmt.Sprint(len(text))}))
	if w.JSON(f) {
		return nil
	}
	w.Human("made %s%s%s\n", bold, f.Name, reset)
	w.Human("  %srecorded as a synthetic voice (%s) by %s, for %s%s\n", dim, f.Origin.SourceType, model, who, reset)
	w.Human("  %sid %s%s\n", dim, f.ID, reset)
	// No section plays a recording yet, and nothing on a page shows a
	// recording's words for it. This said "in a page: /media/ID, with its
	// words beside it as its transcript", which read as a player and a
	// transcript a page would show; neither appeared, so it says what a
	// person has to do by hand.
	w.Human("  %sin a page, by hand: no section plays a recording yet, so link /media/%s%s\n", dim, f.ID, reset)
	w.Human("  %sand put its words beside the link yourself, as its transcript (WCAG 1.2.1)%s\n", dim, reset)
	return nil
}

// storeSpoken puts a model's speech in the library, marked, with its
// words as its transcript.
func storeSpoken(root string, audio []byte, text, model, voice, name, author string) (media.File, error) {
	if name == "" {
		words := strings.Fields(strings.ToLower(text))
		if len(words) > 5 {
			words = words[:5]
		}
		var kept []rune
		for _, r := range strings.Join(words, "-") {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				kept = append(kept, r)
			}
		}
		name = strings.Trim(string(kept), "-")
		if name == "" {
			name = "spoken"
		}
	}
	// Accepted exactly the way an upload is: a model's reply is untrusted
	// input, and what is not a recording is refused here.
	f, err := media.Accept(name+".mp3", audio, time.Now())
	if err != nil || f.Kind != media.Audio {
		return media.File{}, errBlocked{fmt.Errorf("the model's reply was not a recording this can store: %v", err)}
	}
	f.Alt = text
	f.Source = "model:" + model
	f.UploadedBy = author
	// The mark. Not a flag, not a default, not a reminder.
	f.Origin = media.Origin{
		SourceType:  string(provenance.TrainedAlgorithmicMedia),
		Model:       model,
		Instruction: "read aloud in the voice " + voice,
		Author:      author,
	}
	lib, err := openMedia(root)
	if err != nil {
		return media.File{}, err
	}
	if err := lib.Put(f, audio); err != nil {
		return media.File{}, err
	}
	return lib.Stat(f.ID)
}
