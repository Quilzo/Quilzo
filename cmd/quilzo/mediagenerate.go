// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/provenance"
)

// Making a picture, and the mark that cannot be left off.
//
// # The whole design is one sentence
//
// There is no code path that stores a generated picture undeclared.
//
// The page side settled this argument twice already, and the wording is
// cmd/quilzo/mcp.go's: "Marked without being asked. An agent is a model, and a
// model writing a page is exactly what Article 50 is about — leaving this to
// the caller would mean the one interface built for agents is the one that
// forgets." A picture is the same case. So the origin is not a flag, not a
// default and not a reminder: the function that stores the bytes is the
// function that writes trainedAlgorithmicMedia, and they cannot be separated
// by a caller who was in a hurry.
//
// What follows from that, with the gate merged earlier: a page carrying one of
// these and recorded as human-written will not publish. The two halves were
// built in the wrong order on purpose — the gate first, so that the feature
// that creates the obligation arrived after the thing that enforces it.
//
// # Why the description is required and the prompt will not do
//
// An image cannot go on a page without one; internal/media refuses it at the
// point it is attached, for WCAG 1.1.1. The prompt is *not* a description. It
// is what somebody asked for, and the picture may not show it — which is the
// ordinary case with these models rather than an edge one. Offering the prompt
// as the alt text would be the accessible-looking version of describing an
// image nobody has looked at.

func mediaGenerate(root string, args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	alt := fs.String("alt", "", "what the picture shows, once you have looked at it")
	size := fs.String("size", "1024x1024", "how big to ask for")
	author := fs.String("author", "",
		"the person accountable for publishing this")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf(
			"usage: quilzo media generate \"what to draw\" --alt \"what it " +
				"shows\" --author WHO")
	}
	prompt := strings.TrimSpace(rest[0])

	// Required, and not defaulted to whoever's shell this is. `quilzo assist`
	// settled this for the same obligation in the same words: "a record naming
	// 'cli' would satisfy the struct and nobody at all." Two commands that
	// both write trainedAlgorithmicMedia must not disagree about who may be
	// named in one.
	who := strings.TrimSpace(*author)
	if who == "" {
		return errBlocked{fmt.Errorf(
			"--author is required: someone has to be accountable for what " +
				"the model draws, and that is never the tool")}
	}
	if strings.TrimSpace(*alt) == "" {
		return errBlocked{fmt.Errorf(
			"this picture needs a description: --alt \"what it shows\"\n" +
				"  The prompt is not a description. It is what you asked for, " +
				"and these models routinely produce something else — so look " +
				"at the picture and say what is in it")}
	}

	m, err := assist.NewHTTPModel()
	if err != nil {
		return errBlocked{err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), assist.RequestTimeout)
	defer cancel()

	pic, err := m.Paint(ctx, prompt, strings.TrimSpace(*size))
	if err != nil {
		return errBlocked{err}
	}

	f, body, err := storeGenerated(root, pic, strings.TrimSpace(*alt), who)
	if err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("media.generate", "/",
		audit.Success, map[string]string{
			"id": shortID(f.ID), "model": pic.Model,
			"source_type": f.Origin.SourceType,
		}))

	if w.JSON(f) {
		return nil
	}
	w.Human("made %s%s%s\n", bold, f.Name, reset)
	w.Human("  %s%s · %dx%d · %d bytes%s\n", dim,
		f.Format, f.Width, f.Height, len(body), reset)
	w.Human("  %srecorded as %s by %s, for %s%s\n", dim,
		f.Origin.SourceType, pic.Model, who, reset)
	w.Human("  %sid %s%s\n", dim, f.ID, reset)
	w.Human("  %sin a page: /media/%s%s\n", dim, f.ID, reset)
	w.Human("  %sa page carrying this and recorded as human-written will not "+
		"publish%s\n", dim, reset)
	return nil
}

// storeGenerated puts a model's picture in the library, marked.
//
// The marking is here rather than at the call site, and it is not a parameter.
// A caller cannot ask for it to be left off, cannot pass an empty source type,
// and cannot reach the library another way with these bytes and no record —
// because this is the only function that turns an assist.Picture into a stored
// file.
func storeGenerated(root string, pic assist.Picture, alt, author string) (
	media.File, []byte, error) {

	// Accepted exactly the way an upload is. A model's output is untrusted
	// input: the format is decided by the bytes, the pixel count is bounded,
	// and a reply that is not a picture is refused here rather than served.
	f, err := media.Accept(generatedName(pic), pic.Body, time.Now())
	if err != nil {
		return media.File{}, nil, errBlocked{fmt.Errorf(
			"the model's reply was not a picture this can store: %w", err)}
	}
	if f.Kind != media.Image {
		return media.File{}, nil, errBlocked{fmt.Errorf(
			"the model returned a %s rather than a picture", f.Kind)}
	}

	body := pic.Body
	if opt, oerr := media.Optimise(f.Format, body, mediaOptionsAt(root)); oerr == nil &&
		len(opt.Did) > 0 {
		body = opt.Body
		if reaccepted, aerr := media.Accept(f.Name, body, time.Now()); aerr == nil {
			f = reaccepted
		}
	}

	f.Alt = alt
	f.Source = "model:" + pic.Model
	f.UploadedBy = author
	// The mark. Not a flag, not a default, not a reminder.
	f.Origin = media.Origin{
		SourceType:  string(provenance.TrainedAlgorithmicMedia),
		Model:       pic.Model,
		Instruction: pic.Prompt,
		Author:      author,
	}

	lib, err := openMedia(root)
	if err != nil {
		return media.File{}, nil, err
	}
	if err := lib.Put(f, body); err != nil {
		return media.File{}, nil, err
	}
	stored, err := lib.Stat(f.ID)
	if err != nil {
		return media.File{}, nil, err
	}
	return stored, body, nil
}

// generatedName gives the file something recognisable in a list.
//
// The first few words of the instruction, because that is what the person will
// be looking for, and the address is the hash so the name is free to be prose.
func generatedName(pic assist.Picture) string {
	words := strings.Fields(strings.ToLower(pic.Prompt))
	if len(words) > 5 {
		words = words[:5]
	}
	var kept []rune
	for _, r := range strings.Join(words, "-") {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			kept = append(kept, r)
		}
	}
	name := strings.Trim(string(kept), "-")
	if name == "" {
		name = "generated"
	}
	// No extension. Accept reads the format out of the bytes and gives the
	// file its own; guessing one here would put .png on a JPEG and make the
	// only untrustworthy thing about the name the part that matters.
	return name
}
