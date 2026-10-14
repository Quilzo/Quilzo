// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/section"
)

// Making a feature from a sentence or from a file. Both only write a draft
// package, and the rows a file held, for a person to read on its card and
// install; neither installs anything.

// featureDraftTimeout bounds one draft, both rounds.
const featureDraftTimeout = 3 * time.Minute

// draftedFeature is a package a model drafted and what was decided about it.
type draftedFeature struct {
	Package *feature.Package `json:"package"`
	Body    []byte           `json:"-"`
	Notes   []string         `json:"notes,omitempty"`
	// Invalid is why it would not install as it is, after one try at
	// putting it right.
	Invalid string `json:"invalid,omitempty"`
}

// renderedSections is the page sections this program renders.
func renderedSections() ([]string, map[string]bool) {
	var names []string
	set := map[string]bool{}
	for _, k := range section.Kinds() {
		names = append(names, k.Name)
		set[k.Name] = true
	}
	return names, set
}

// draftFeature asks a model for a package from a description and reads it
// through the checks. One answer that fails them is shown its failures and
// asked once more.
func draftFeature(ctx context.Context, root, description string, caller *Caller) (draftedFeature, error) {
	var out draftedFeature
	description = strings.TrimSpace(plaintext.Clean(description))
	if description == "" {
		return out, errors.New("describe the feature you want")
	}
	if len(description) > 2000 {
		return out, errors.New("a description is at most 2,000 characters")
	}
	model, why := draftModelFor(root, caller, "studio:feature")
	if model == nil {
		return out, errors.New("drafting from a description needs a model, and " + why +
			"; start from quilzo feature example instead")
	}
	names, kinds := renderedSections()
	system := feature.DraftPrompt(names)
	read := func(answer string) (*feature.Package, []string, error) {
		return feature.ReadDraft(answer, kinds, caller.Name, description, model.Name(), time.Now())
	}
	answer, err := model.Complete(ctx, system, description)
	if err != nil {
		return out, fmt.Errorf("the model did not answer: %w", err)
	}
	p, notes, err := read(answer)
	if err != nil {
		return out, err
	}
	verr := p.Validate(featureChecks(root))
	if verr != nil {
		retry := description + "\n\nYour previous answer was:\n" + clip(answer, 20000) +
			"\n\nIt failed these checks:\n" + verr.Error() + "\n\nAnswer with the corrected package only."
		if again, err := model.Complete(ctx, system, retry); err == nil {
			if p2, notes2, err := read(again); err == nil {
				if verr2 := p2.Validate(featureChecks(root)); verr2 == nil || len(verr2.Error()) < len(verr.Error()) {
					p, notes, verr = p2, notes2, verr2
				}
			}
		}
	}
	out.Package, out.Notes = p, notes
	if verr != nil {
		out.Invalid = verr.Error()
	}
	out.Body, err = json.MarshalIndent(p, "", "  ")
	if err != nil {
		return out, err
	}
	out.Body = append(out.Body, '\n')
	return out, nil
}

// featureDraftCmd is `quilzo feature draft "…" [-o FILE]`.
func featureDraftCmd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("feature draft", flag.ContinueOnError)
	outPath := fs.String("o", "", "where to write the draft; NAME.json by default")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(`usage: quilzo feature draft "what you want it to do" [-o FILE]`)
	}
	caller := resolveCaller(root, flagToken)
	ctx, cancel := context.WithTimeout(context.Background(), featureDraftTimeout)
	defer cancel()
	d, err := draftFeature(ctx, root, pos[0], caller)
	if err != nil {
		return err
	}
	path := *outPath
	if path == "" {
		path = d.Package.Name + ".json"
		if d.Package.Name == "" {
			path = "feature-draft.json"
		}
	}
	if err := atomicfile.Write(path, d.Body, 0o644); err != nil {
		return err
	}
	if w.JSON(map[string]any{"file": path, "draft": d, "card": d.Package.MakeCard()}) {
		return nil
	}
	printFeatureCard(d.Package.MakeCard())
	for _, n := range d.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	if d.Invalid != "" {
		w.Human("\n%sthe draft does not pass the checks yet; edit %s and run quilzo feature check:%s\n  %s\n",
			yellow, path, reset, d.Invalid)
		return nil
	}
	w.Human("\nwrote %s; read it, then: quilzo feature check %s, and quilzo feature install %s\n", path, path, path)
	return nil
}

// featureFromCmd is `quilzo feature from FILE [--name N] [-o FILE]`.
func featureFromCmd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("feature from", flag.ContinueOnError)
	name := fs.String("name", "", "what the feature is called; the file's name by default")
	outPath := fs.String("o", "", "where to write the package; NAME.json by default")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo feature from FILE.csv|FILE.json [--name N] [-o FILE]")
	}
	body, err := readBounded(pos[0], 64<<20)
	if err != nil {
		return err
	}
	n := *name
	if n == "" {
		n = strings.TrimSuffix(filepath.Base(pos[0]), filepath.Ext(pos[0]))
	}
	in, err := feature.Infer(n, body)
	if err != nil {
		return err
	}
	if err := in.Package.Validate(featureChecks(root)); err != nil {
		return err
	}
	path := *outPath
	if path == "" {
		path = in.Package.Name + ".json"
	}
	rowsPath := strings.TrimSuffix(path, ".json") + ".rows.json"
	pb, err := json.MarshalIndent(in.Package, "", "  ")
	if err != nil {
		return err
	}
	rb, err := json.Marshal(feature.Rows{Collection: in.Collection, Records: in.Rows})
	if err != nil {
		return err
	}
	if err := atomicfile.Write(path, append(pb, '\n'), 0o644); err != nil {
		return err
	}
	// The rows are the file's own data, kept as private as it was.
	if err := atomicfile.Write(rowsPath, append(rb, '\n'), 0o600); err != nil {
		return err
	}
	if w.JSON(map[string]any{"package": path, "rows": rowsPath, "records": len(in.Rows), "notes": in.Notes,
		"card": in.Package.MakeCard()}) {
		return nil
	}
	printFeatureCard(in.Package.MakeCard())
	for _, n := range in.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	w.Human("\nwrote %s and %s (%d records); install both with:\n  quilzo feature install %s --rows %s\n",
		path, rowsPath, len(in.Rows), path, rowsPath)
	return nil
}
