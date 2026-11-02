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

// A video made from a prompt, through the gateway's routes that make video
// (Google's Veo, or a model on fal's queue), into the media library marked
// as generated, with the prompt as what it shows until somebody writes
// better, and the person accountable named.
//
//	quilzo media film "a slow pan over a bakery at dawn" --author WHO [--aspect 9:16] [--name N]
//
// A video still needs its captions before a page may show it, as every
// video does; one with no speech says so in its captions.

func mediaFilm(root string, args []string) error {
	fs := flag.NewFlagSet("film", flag.ContinueOnError)
	aspect := fs.String("aspect", "16:9", "the shape: 16:9 or 9:16")
	author := fs.String("author", "", "the person accountable for publishing this")
	name := fs.String("name", "", "what to call the video in the library")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: quilzo media film \"prompt\" | @FILE --author WHO [--aspect 16:9|9:16]")
	}
	who := strings.TrimSpace(*author)
	if who == "" {
		return errBlocked{fmt.Errorf("--author is required: someone has to be accountable for a generated " +
			"video, and that is never the tool")}
	}
	prompt := rest[0]
	if strings.HasPrefix(prompt, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(prompt, "@"))
		if err != nil {
			return err
		}
		prompt = string(b)
	}
	prompt = strings.TrimSpace(prompt)
	if prompt == "" || len(prompt) > 4000 {
		return errBlocked{fmt.Errorf("a video is asked for in 1 to 4,000 characters; this is %d", len(prompt))}
	}
	caller := resolveCaller(root, flagToken)
	gw, _, err := modelGateway(root)
	if err != nil {
		return err
	}
	if gw == nil || !gw.Films() {
		return errBlocked{fmt.Errorf("no route makes video: quilzo gateway route add NAME --provider google-veo --model MODEL --films")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), assist.FilmWait+time.Minute)
	defer cancel()
	consumers := []string{"media", "person:" + caller.Name}
	w.Human("  %sasking for the video; this takes minutes%s\n", dim, reset)
	video, model, _, err := gw.Film(ctx, consumers, prompt, strings.TrimSpace(*aspect))
	if err != nil {
		return errBlocked{err}
	}
	f, err := storeFilmed(root, video, prompt, model, strings.TrimSpace(*name), who)
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("media.film", "/", audit.Success, map[string]string{
		"id": shortID(f.ID), "model": model, "aspect": strings.TrimSpace(*aspect), "chars": fmt.Sprint(len(prompt))}))
	if w.JSON(f) {
		return nil
	}
	w.Human("made %s%s%s\n", bold, f.Name, reset)
	w.Human("  %smarked as generated (%s) by %s, for %s%s\n", dim, f.Origin.SourceType, model, who, reset)
	w.Human("  %sid %s; it needs its captions before a page shows it: quilzo media captions %s ...%s\n", dim, f.ID, shortID(f.ID), reset)
	return nil
}

// storeFilmed puts a model's video in the library, marked.
func storeFilmed(root string, video []byte, prompt, model, name, author string) (media.File, error) {
	if name == "" {
		name = slugWords(prompt, 5, "video")
	}
	// Accepted exactly the way an upload is: a model's reply is untrusted
	// input, and what is not a video is refused here.
	f, err := media.Accept(name+".mp4", video, time.Now())
	if err != nil || f.Kind != media.Video {
		return media.File{}, errBlocked{fmt.Errorf("the model's reply was not a video this can store: %v", err)}
	}
	f.Alt = clip(prompt, 500)
	f.Source = "model:" + model
	f.UploadedBy = author
	f.Origin = media.Origin{
		SourceType:  string(provenance.TrainedAlgorithmicMedia),
		Model:       model,
		Instruction: clip(prompt, 1000),
		Author:      author,
	}
	lib, err := openMedia(root)
	if err != nil {
		return media.File{}, err
	}
	if err := lib.Put(f, video); err != nil {
		return media.File{}, err
	}
	return lib.Stat(f.ID)
}

// slugWords is a name from the first words of a text.
func slugWords(text string, n int, fallback string) string {
	words := strings.Fields(strings.ToLower(text))
	if len(words) > n {
		words = words[:n]
	}
	var kept []rune
	for _, r := range strings.Join(words, "-") {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			kept = append(kept, r)
		}
	}
	if s := strings.Trim(string(kept), "-"); s != "" {
		return s
	}
	return fallback
}
