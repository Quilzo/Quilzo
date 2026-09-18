// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package render_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every shipped template that carries the timing field must fill it in.
//
// # The bug this is for
//
// internal/demo/assets/page.html rendered the field as
//
//	<input type="hidden" name="form_started" value="{{ page.stamp }}">
//
// and the renderer provides "stamp" at the top level of the context, not under
// "page". So the value came out empty, the timing check refuses a submission
// with no stamp — deliberately, because removing the field must not be a way
// around it — and THE DEMO'S ONLY FORM COULD NOT BE SUBMITTED AT ALL. The demo
// advertises that form as "the one thing the public server may write".
//
// The renderer's own comment about this field records the same symptom arrived
// at from a different direction: an int64 there "came out as nothing at all:
// value="" in the markup and every submission refused". The type was fixed and
// the path was wrong in one of three shipped templates, which produced the
// identical failure.
//
// So this checks the templates rather than the renderer. A test of the
// renderer passes while a template reads the wrong name, which is exactly what
// happened: internal/render's own tests were green throughout.
func TestEveryShippedTemplateFillsTheTimingField(t *testing.T) {
	// The field's own markup, with whatever expression the template put in it.
	field := regexp.MustCompile(
		`name="form_started"[^>]*value="([^"]*)"`)

	checked := 0
	for _, path := range templatesUnder(t, "..") {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range field.FindAllStringSubmatch(string(src), -1) {
			expr := strings.TrimSpace(m[1])
			checked++

			// The one expression that works. Written out rather than
			// pattern-matched, because "contains stamp" passes for
			// page.stamp, which is the bug.
			if expr == "{{ stamp }}" || expr == "{{stamp}}" {
				continue
			}
			// The documentation snippet in internal/form deliberately carries
			// a placeholder for a template author to replace.
			if expr == "UNIX_TIMESTAMP_WHEN_RENDERED" {
				continue
			}
			t.Errorf("%s fills the timing field with %q. The renderer "+
				"provides \"stamp\" at the top level of the context, so "+
				"anything else is empty — and an empty stamp means every "+
				"submission through this template is refused.", path, expr)
		}
	}
	if checked == 0 {
		t.Fatal("found no timing field in any template; the walk is wrong " +
			"and a test that sees nothing passes")
	}
}

// templatesUnder lists the HTML templates in the tree, so a template added
// later is covered without anybody remembering.
func templatesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".html") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
