package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/provenance"
)

// Declaring where a picture came from.
//
// The field existed with no way to set it, which made the whole disclosure
// path decorative: every manifest asserted nothing, and the one term that
// carries a legal obligation -- trainedAlgorithmicMedia, the marking the EU AI
// Act Article 50 requires -- could not be written down.
//
// The vocabulary is the IPTC one, the same strings internal/provenance uses
// for pages, and it is validated against that rather than accepted as free
// text: a source type nobody recognises is a disclosure that discloses
// nothing, and it would be signed into every copy of the picture.

func mediaOrigin(root string, args []string) error {
	fs := flag.NewFlagSet("origin", flag.ContinueOnError)
	sourceType := fs.String("source-type", "",
		"an IPTC digital source type: trainedAlgorithmicMedia, "+
			"compositeWithTrainedAlgorithmicMedia, algorithmicMedia, humanEdits")
	model := fs.String("model", "", "the model, when one was involved")
	prompt := fs.String("prompt", "", "what it was asked for")
	author := fs.String("author", "", "the person accountable")
	clear := fs.Bool("clear", false, "remove the declaration")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf(
			"usage: quilzo media origin <id> --source-type <term> " +
				"[--model M] [--prompt P] [--author A]")
	}

	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	f, err := lib.Stat(rest[0])
	if err != nil {
		return err
	}

	if *clear {
		f.Origin = media.Origin{}
	} else {
		if strings.TrimSpace(*sourceType) == "" {
			return fmt.Errorf(
				"--source-type is required: a declaration that names no " +
					"source declares nothing")
		}
		// Checked against the vocabulary rather than stored as typed. This
		// string is signed into every copy of the picture and read by other
		// people's software; a typo would be a disclosure nothing recognises.
		if !provenance.SourceType(*sourceType).Valid() {
			return fmt.Errorf(
				"%q is not an IPTC digital source type. The ones this "+
					"program uses are:\n"+
					"    trainedAlgorithmicMedia                a model made it\n"+
					"    compositeWithTrainedAlgorithmicMedia   a person and a model\n"+
					"    algorithmicMedia                       software, not a model\n"+
					"    humanEdits                             a person",
				*sourceType)
		}
		f.Origin = media.Origin{
			SourceType:  *sourceType,
			Model:       strings.TrimSpace(*model),
			Instruction: strings.TrimSpace(*prompt),
			Author:      strings.TrimSpace(*author),
		}
	}

	// Written through the library, which is also what re-derives the narrower
	// copies -- so a declaration reaches the file a phone downloads rather
	// than only the original nobody fetches.
	_, body, err := lib.Get(f.ID)
	if err != nil {
		return err
	}
	// The existing copies are rebuilt rather than edited, because each is its
	// own file at its own hash and inheritance happens where they are made.
	f.Renditions = nil
	if err := lib.Put(f, body); err != nil {
		return err
	}
	after, err := lib.Stat(f.ID)
	if err != nil {
		return err
	}

	if w.JSON(map[string]any{
		"id": after.ID, "origin": after.Origin,
		"renditions": len(after.Renditions),
	}) {
		return nil
	}
	if *clear {
		w.Human("%s%s%s declares nothing about where it came from\n",
			bold, after.Name, reset)
		return nil
	}
	w.Human("%s%s%s\n", bold, after.Name, reset)
	w.Human("  %s\n", provenance.SourceType(after.Origin.SourceType).Describe())
	if after.Origin.Model != "" {
		w.Human("  model %s\n", after.Origin.Model)
	}
	if provenance.SourceType(after.Origin.SourceType).RequiresDisclosure() {
		w.Human("\n  %sthis is the marking the AI Act asks for. It is signed "+
			"into the\n  picture and into every narrower copy%s\n", dim, reset)
	}
	w.Human("  %s%d narrower copy(ies) carry it too%s\n",
		dim, len(after.Renditions), reset)
	return nil
}
