// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
)

// Every way an image gets into the library runs it through the pipeline.
//
// internal/media states the property flatly: re-encoding "makes this a
// property of the pipeline rather than a filter somebody has to remember."
// A property of the pipeline has to be in the pipeline. It was not — `quilzo
// media get` called Accept and then Put and no optimiser at all, so the one
// path that ingests a file from somebody else's server stored a photograph
// unresized with its EXIF intact. GPS coordinates and a camera serial number,
// published, on the surface where the uploader is a stranger.
//
// It was written without the optimiser because the settings were read in four
// places and a fifth caller simply did not repeat them. A source walk, because
// this is exactly the kind of thing that is correct when written and forgotten
// when the next entrance is added.
func TestEveryImageEntranceRunsTheOptimiser(t *testing.T) {
	// The function that stores an image, and what surface it is.
	entrances := map[string]string{
		"mediaAdd": "quilzo media add",
		"mediaGet": "quilzo media get",
	}
	found := map[string]bool{}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, e.Name(), nil, 0)
		if perr != nil {
			t.Fatalf("%s: %v", e.Name(), perr)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			if _, wanted := entrances[fn.Name.Name]; !wanted {
				return true
			}
			var calls []string
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				sel, ok := inner.(*ast.SelectorExpr)
				if ok {
					calls = append(calls, sel.Sel.Name)
				}
				return true
			})
			for _, c := range calls {
				if c == "Optimise" {
					found[fn.Name.Name] = true
				}
			}
			return true
		})
	}

	if len(found) == 0 {
		t.Fatal("no entrance was parsed at all; the walk is wrong and this " +
			"test would pass by checking nothing")
	}
	var missing []string
	for name, what := range entrances {
		if !found[name] {
			missing = append(missing, name+" — "+what)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s stores an image without running media.Optimise. That "+
			"path publishes a photograph's GPS coordinates, and it is the "+
			"one nobody notices", m)
	}
}

// The settings are read in one place, so a new entrance cannot read three of
// the five keys.
func TestTheOptimiserSettingsAreReadInOnePlace(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var elsewhere []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			e.Name() == "mediaopts.go" ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(e.Name())
		if rerr != nil {
			t.Fatal(rerr)
		}
		if strings.Contains(string(body), `"media.max_width"`) {
			elsewhere = append(elsewhere, e.Name())
		}
	}
	sort.Strings(elsewhere)
	for _, f := range elsewhere {
		t.Errorf("%s reads the optimiser settings itself. They live in "+
			"mediaOptions, because four copies of the same five keys is how "+
			"the fifth caller came to be written with none of them", f)
	}
}

// media.strip_metadata reaches the optimiser.
//
// It was declared with a Weaker clause and the NIST controls SI-12 and PM-30,
// and read by nothing at all: setting it to false changed no behaviour. A
// control that appears in the posture report and does nothing is a claim the
// product does not keep, which is the worst-shaped bug available to a project
// whose argument is that the documented behaviour and the real behaviour are
// the same thing.
func TestStripMetadataIsActuallyRead(t *testing.T) {
	c := config.New()
	if opt := mediaOptions(c); opt.KeepMetadata {
		t.Error("the default keeps metadata; it is documented as removing it")
	}
	if err := c.Set("media.strip_metadata", "false",
		"a photography site keeps its capture data", "test"); err != nil {
		t.Fatal(err)
	}
	if opt := mediaOptions(c); !opt.KeepMetadata {
		t.Error("turning media.strip_metadata off changed nothing, which is " +
			"the state this test exists to end")
	}
}

// An unreadable configuration is the defaults, not an empty Options.
//
// media.Options{} means no maximum width, which would store a
// six-thousand-pixel photograph because a file had a syntax error in it.
func TestABadConfigStillOptimises(t *testing.T) {
	opt := mediaOptionsAt(t.TempDir())
	if opt.MaxWidth <= 0 {
		t.Errorf("MaxWidth is %d, so a site with no config stores every "+
			"photograph at full size", opt.MaxWidth)
	}
	if opt.KeepMetadata {
		t.Error("a site with no config keeps EXIF")
	}
}

// The public site is handed a way to stream, not only a way to read.
//
// public.MediaOpen is nil in a build that forgets it, and then everything
// falls back to the byte lookup — which works, and reads a whole film to
// answer a two-byte range request. That is the failure this exists to stop,
// and a nil field has no symptom until somebody serves a recording to ten
// people at once.
func TestTheSiteIsHandedAWayToStream(t *testing.T) {
	body, err := os.ReadFile("sitebuild.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"st.MediaOpen = ", "lib.Open("} {
		if !strings.Contains(string(body), want) {
			t.Errorf("sitebuild.go no longer wires %s, so a range request "+
				"for two bytes of a recording reads the whole recording", want)
		}
	}
}
