// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Building a whole site, and filling in what only its owner knows.
//
// `quilzo site new` writes a site package (internal/feature/sitebuild.go),
// drafted by a model when one is allowed and from the kind of site when
// not, and installs it when asked. `quilzo site fill` writes the facts the
// builder left as [[blanks]] into the draft's pages; the publish gate
// refuses a page that still holds one.

// builtPath records the packages this installation's builder made, so an
// install can say truthfully how their pages were written: a package file
// cannot vouch for itself.
func builtPath(root string) string { return filepath.Join(featuresDir(root), "built.json") }

// builtRecord is one package the builder made.
type builtRecord struct {
	Model string    `json:"model,omitempty"`
	At    time.Time `json:"at"`
}

type builtFile struct {
	Packages map[string]builtRecord `json:"packages"`
}

// rememberBuilt notes a package the builder made, by digest. The newest
// hundred are kept: a site built and never installed is not worth more.
func rememberBuilt(root string, p *feature.Package, model string) error {
	digest, err := p.Digest()
	if err != nil {
		return err
	}
	var f builtFile
	if err := loadJSON(builtPath(root), &f); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if f.Packages == nil {
		f.Packages = map[string]builtRecord{}
	}
	f.Packages[digest] = builtRecord{Model: model, At: time.Now().UTC()}
	for len(f.Packages) > 100 {
		oldest, at := "", time.Time{}
		for d, r := range f.Packages {
			if oldest == "" || r.At.Before(at) {
				oldest, at = d, r.At
			}
		}
		delete(f.Packages, oldest)
	}
	if err := os.MkdirAll(featuresDir(root), 0o700); err != nil {
		return err
	}
	return saveJSON(builtPath(root), f)
}

// pagesWrittenBy is how a package's pages came to be, for their provenance:
// by this installation's builder, with a model or without one; by a model,
// as the package says; or unknown, which leaves them for a person to say.
func pagesWrittenBy(root string, p *feature.Package, digest string) (provenance.SourceType, string) {
	var f builtFile
	if loadJSON(builtPath(root), &f) == nil {
		if r, ok := f.Packages[digest]; ok {
			if r.Model != "" {
				return provenance.TrainedAlgorithmicMedia, r.Model
			}
			return provenance.AlgorithmicMedia, ""
		}
	}
	// A package that says a model made it is believed: the mark it earns is
	// the one that discloses. One that says nothing is not taken at its word.
	if p.Made != nil && p.Made.Model != "" {
		return provenance.TrainedAlgorithmicMedia, p.Made.Model
	}
	return "", ""
}

// markFeaturePages records the provenance of the pages a package just put
// in the draft, when how they were written is known; author is the person
// who answers for them.
func markFeaturePages(root string, s *store.Store, p *feature.Package, digest string, pages []string, author string) error {
	source, model := pagesWrittenBy(root, p, digest)
	if source == "" || len(pages) == 0 {
		return nil
	}
	ids, err := site.PageIDsAt(s, s.GetRef(site.RefDraft))
	if err != nil {
		return err
	}
	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}
	instruction := ""
	if p.Made != nil {
		instruction = p.Made.From
	}
	for _, name := range pages {
		hash, ok := ids[name]
		if !ok {
			continue
		}
		if err := idx.Set(name, provenance.Record{ContentHash: hash, SourceType: source, Model: model,
			Instruction: instruction, Author: author, At: time.Now().Unix(),
			Note: "installed with the feature " + p.Name + " " + p.Version}); err != nil {
			return err
		}
	}
	return saveJSON(provPath(root), idx)
}

// siteBuilt is a site package the builder made, and what came with it.
type siteBuilt struct {
	draftedFeature
	// Model is the model that drafted it, empty when the builder wrote it.
	Model string `json:"model,omitempty"`
	// Fill is what its pages still need from the person, in their words.
	Fill []string `json:"fill,omitempty"`
}

// buildSite builds a site package from a brief: drafted by a model when
// one is allowed and wanted, from the kind of site otherwise. It is
// remembered, so installing it marks its pages for what they are.
func buildSite(ctx context.Context, root string, b feature.SiteBrief, useModel bool, caller *Caller) (siteBuilt, error) {
	var out siteBuilt
	b.Description = strings.TrimSpace(plaintext.Clean(b.Description))
	b.Name = strings.TrimSpace(plaintext.Clean(b.Name))
	if b.Description == "" && b.Name == "" {
		return out, errors.New("say what the site is for")
	}
	if len(b.Description) > feature.MaxBrief {
		return out, fmt.Errorf("a description is at most %d characters", feature.MaxBrief)
	}
	if len([]rune(b.Name)) > feature.MaxSiteName || strings.IndexFunc(b.Name, unicode.IsControl) >= 0 {
		return out, fmt.Errorf("a site's name is at most %d characters, on one line", feature.MaxSiteName)
	}
	b.Colour = strings.TrimSpace(b.Colour)
	var model assist.Model
	why := "drafting was not asked for"
	if useModel && authorise(root, caller, auth.ActUseModels, "/") != nil {
		why, useModel = "you may not use models here", false
	}
	if useModel {
		if m, w := draftModelFor(root, caller, "studio:site"); m != nil {
			model = m
		} else {
			why = w
		}
	}
	name := b.Name
	if name == "" && model != nil {
		// A placeholder for the start; the model names the site.
		name = "Your site"
	}
	start, err := feature.BuildSite(feature.SiteBrief{Description: b.Description, Name: name, Kind: b.Kind,
		Colour: b.Colour, Style: b.Style}, caller.Name, time.Now())
	if err != nil {
		if b.Name == "" && useModel {
			return out, fmt.Errorf("%w; there is no model to suggest one, because %s", err, why)
		}
		return out, err
	}
	if verr := start.Validate(featureChecks(root)); verr != nil {
		return out, verr
	}
	pkg := start
	if model != nil {
		request, err := feature.SiteRequest(b, start)
		if err != nil {
			return out, err
		}
		system := feature.SitePrompt(section.Kinds())
		answer, err := model.Complete(ctx, system, request)
		if err != nil {
			return out, fmt.Errorf("the model did not answer: %w", err)
		}
		drafted, notes, err := feature.ReadSiteDraft(answer, b, start, caller.Name, model.Name(), time.Now())
		if err != nil {
			out.Notes = append(out.Notes, "the model's site could not be read, so this is the builder's own: "+err.Error())
		} else if verr := drafted.Validate(featureChecks(root)); verr != nil {
			out.Notes = append(notes, "the model's site did not pass the checks, so this is the builder's own: "+verr.Error())
		} else {
			if b.Name == "" && drafted.Name == start.Name {
				drafted.Name = feature.PackageName(drafted.Site.Name)
			}
			pkg, out.Notes, out.Model = drafted, notes, model.Name()
		}
	}
	out.Package = pkg
	out.Fill = pkg.BlankWhats()
	out.Body, err = json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return out, err
	}
	out.Body = append(out.Body, '\n')
	if err := rememberBuilt(root, pkg, out.Model); err != nil {
		return out, err
	}
	record(root, caller.auditRecord("site.built", "/", audit.Success, map[string]string{
		"package": pkg.Name, "pages": fmt.Sprint(len(pkg.Pages)), "model": out.Model, "to_fill": fmt.Sprint(len(out.Fill))}))
	return out, nil
}

// siteNewCmd is `quilzo site new "what it is for" [--name N] …`.
func siteNewCmd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("site new", flag.ContinueOnError)
	name := fs.String("name", "", "what the site is called")
	kind := fs.String("kind", "", "the kind of site: "+strings.Join(siteKindNames(), ", ")+"; read from the description by default")
	colour := fs.String("colour", "", "the main colour, as #rrggbb")
	style := fs.String("style", "", "the style; `quilzo theme styles` lists them")
	outPath := fs.String("o", "", "where to write the package; NAME.json by default")
	noModel := fs.Bool("no-model", false, "build from the kind of site only, without asking a model")
	install := fs.Bool("install", false, "install it as well, as `quilzo feature install` does")
	takeSite := fs.Bool("take-site", false, "with --install: let it take over a site somebody set up by hand")
	fs.StringVar(&featureDesignDir, "templates", featureDesignDir, "the site's templates directory, for --install")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 && *name == "" {
		return errors.New(`usage: quilzo site new "what the site is for" [--name N] [--kind K] [--colour #rrggbb] [--style S] [-o FILE] [--install]`)
	}
	brief := ""
	if len(pos) == 1 {
		brief = pos[0]
	}
	caller := resolveCaller(root, flagToken)
	if *install {
		if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
			return fmt.Errorf("--install installs a feature, which needs whoever may install them: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), featureDraftTimeout)
	defer cancel()
	built, err := buildSite(ctx, root, feature.SiteBrief{Description: brief, Name: *name, Kind: *kind,
		Colour: *colour, Style: *style}, !*noModel, caller)
	if err != nil {
		return err
	}
	path := *outPath
	if path == "" {
		path = built.Package.Name + ".json"
	}
	if err := atomicfile.Write(path, built.Body, 0o644); err != nil {
		return err
	}
	if !*install {
		if w.JSON(map[string]any{"file": path, "site": built, "card": built.Package.MakeCard()}) {
			return nil
		}
		printBuiltSite(built)
		w.Human("\nwrote %s; read it, then: quilzo feature install %s\n", path, path)
		return nil
	}
	printBuiltSite(built)
	return installFeatureFileWith(root, path, "", "", *takeSite, caller)
}

func siteKindNames() []string {
	var out []string
	for _, k := range feature.SiteKinds() {
		out = append(out, k.Name)
	}
	return out
}

func printBuiltSite(b siteBuilt) {
	printFeatureCard(b.Package.MakeCard())
	if b.Model != "" {
		w.Human("  %swritten by %s, from the builder's start%s\n", dim, b.Model, reset)
	}
	for _, n := range b.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	if len(b.Fill) > 0 {
		w.Human("\n%d things only you know, which the pages leave blank until you fill them in:\n", len(b.Fill))
		for _, f := range b.Fill {
			w.Human("  [[%s]]\n", f)
		}
		w.Human("%safter installing: quilzo site fill \"%s=…\"; a page with a blank in it is not published%s\n",
			dim, b.Fill[0], reset)
	}
}

// siteKindsCmd is `quilzo site kinds`.
func siteKindsCmd() error {
	kinds := feature.SiteKinds()
	if w.JSON(kinds) {
		return nil
	}
	for _, k := range kinds {
		w.Human("%-11s %s. %s\n", k.Name, k.Title, k.Summary)
	}
	return nil
}

// builderBlanks is every blank the installed packages' pages were written
// with, which is what the publish gate, `site fill` and Fill in look for.
// Two square brackets are not a blank on their own: a page about shell
// scripts says [[ -f file ]], and a page somebody wrote is theirs.
func builderBlanks(root string) (map[string]bool, error) {
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for name, in := range installed {
		p, _, err := loadFeaturePackage(root, name, in.Digest)
		if err != nil {
			return nil, fmt.Errorf("the feature %s cannot be read to see what it left blank: %w", name, err)
		}
		for _, what := range p.BlankWhats() {
			out[what] = true
		}
	}
	return out, nil
}

// unfilledOn is the builder's blanks still on a page.
func unfilledOn(body any, known map[string]bool) []section.Blank {
	var out []section.Blank
	for _, b := range section.Unfilled(body) {
		if known[b.What] {
			out = append(out, b)
		}
	}
	return out
}

// siteBlanks is what the draft's pages still need, by what goes there, and
// the pages each appears on.
func siteBlanks(pages map[string]any, known map[string]bool) (whats []string, on map[string][]string) {
	on = map[string][]string{}
	for _, name := range sortedNames(pages) {
		seen := map[string]bool{}
		for _, b := range unfilledOn(pages[name], known) {
			if seen[b.What] {
				continue
			}
			seen[b.What] = true
			if len(on[b.What]) == 0 {
				whats = append(whats, b.What)
			}
			on[b.What] = append(on[b.What], name)
		}
	}
	sort.Strings(whats)
	return whats, on
}

// checkFill refuses a value that could not stand in a page as written.
func checkFill(what, value string) error {
	switch {
	case len(value) > 2000:
		return fmt.Errorf("what goes in [[%s]] is over 2,000 characters", what)
	case strings.Contains(value, "[[") || strings.Contains(value, "]]"):
		return fmt.Errorf("what goes in [[%s]] has [[ or ]] in it, which is how a blank is written", what)
	case strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) >= 0:
		return fmt.Errorf("what goes in [[%s]] has a control character in it", what)
	}
	return nil
}

// fillSite writes values into the draft's pages for the blanks they name,
// and records who did on each page it changed. It returns how many places
// it filled and the pages it changed.
func fillSite(root string, values map[string]string, caller *Caller) (int, []string, error) {
	known, err := builderBlanks(root)
	if err != nil {
		return 0, nil, err
	}
	for what, v := range values {
		if !known[what] {
			return 0, nil, fmt.Errorf("no page was built with a blank for %q; `quilzo site fill` lists them", what)
		}
		if err := checkFill(what, v); err != nil {
			return 0, nil, err
		}
	}
	s, err := open(root)
	if err != nil {
		return 0, nil, err
	}
	base := s.GetRef(site.RefDraft)
	pages, err := draftPages(root)
	if err != nil {
		return 0, nil, err
	}
	total := 0
	var changed []string
	for _, name := range sortedNames(pages) {
		filled, n := section.Fill(pages[name], values)
		if n == 0 {
			continue
		}
		pages[name] = filled
		total += n
		changed = append(changed, name)
	}
	if total == 0 {
		return 0, nil, nil
	}
	msg := fmt.Sprintf("fill in %d %s", total, map[bool]string{true: "blank", false: "blanks"}[total == 1])
	if err := saveDraft(root, s, pages, msg, caller.Name, base); err != nil {
		return 0, nil, err
	}
	if err := markFilled(root, s, changed, caller); err != nil {
		return 0, nil, err
	}
	// How many, and where; never what, which may be a telephone number.
	if err := recordE(root, caller.auditRecord("site.filled", "/", audit.Success, map[string]string{
		"blanks": fmt.Sprint(total), "pages": strings.Join(changed, ",")})); err != nil {
		return 0, nil, err
	}
	return total, changed, nil
}

// markFilled moves a filled page's provenance on: what a model wrote and a
// person completed is both, and a template a person completed is theirs.
// A page with no record keeps none, for a person to say.
func markFilled(root string, s *store.Store, pages []string, caller *Caller) error {
	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}
	ids, err := site.PageIDsAt(s, s.GetRef(site.RefDraft))
	if err != nil {
		return err
	}
	changed := false
	for _, name := range pages {
		r, ok := idx.Records[name]
		if !ok {
			continue
		}
		switch r.SourceType {
		case provenance.TrainedAlgorithmicMedia, provenance.CompositeWithTrainedAlgorithmicMedia:
			r.SourceType = provenance.CompositeWithTrainedAlgorithmicMedia
		default:
			r.SourceType, r.Model = provenance.HumanEdits, ""
		}
		r.ContentHash, r.Author, r.At = ids[name], caller.Name, time.Now().Unix()
		r.Note = "blanks filled in by " + caller.Name
		if err := idx.Set(name, r); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return saveJSON(provPath(root), idx)
}

// siteFillCmd is `quilzo site fill ["WHAT=VALUE" …]`.
func siteFillCmd(root string, args []string) error {
	pos, flags := leadingArgs(args, 999)
	fs := flag.NewFlagSet("site fill", flag.ContinueOnError)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if len(pos) == 0 {
		pages, err := draftPages(root)
		if err != nil {
			return err
		}
		known, err := builderBlanks(root)
		if err != nil {
			return err
		}
		whats, on := siteBlanks(pages, known)
		if w.JSON(map[string]any{"blanks": whats, "on": on}) {
			return nil
		}
		if len(whats) == 0 {
			w.Human("nothing to fill in: no page in the draft has a [[blank]] left\n")
			return nil
		}
		w.Human("%d things to fill in before the pages they are on can be published:\n", len(whats))
		for _, what := range whats {
			w.Human("  %-50s %s%s%s\n", "[["+what+"]]", dim, strings.Join(on[what], ", "), reset)
		}
		w.Human("\n%squilzo site fill \"%s=what it is\"; an empty value leaves it out%s\n", dim, whats[0], reset)
		return nil
	}
	values := map[string]string{}
	for _, pair := range pos {
		what, value, ok := strings.Cut(pair, "=")
		what = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(what), "[["), "]]"))
		if !ok || what == "" {
			return fmt.Errorf("%q is not WHAT=VALUE; `quilzo site fill` lists what there is", pair)
		}
		values[what] = strings.TrimSpace(value)
	}
	n, changed, err := fillSite(root, values, caller)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"filled": n, "pages": changed}) {
		return nil
	}
	if n == 0 {
		return errors.New("no page in the draft has those blanks; `quilzo site fill` lists what there is")
	}
	w.Human("filled %d %s on %s\n", n, map[bool]string{true: "blank", false: "blanks"}[n == 1], strings.Join(changed, ", "))
	return nil
}
