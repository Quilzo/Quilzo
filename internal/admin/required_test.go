// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A required field says so in its label.
//
// The marker existed in edit.html and nowhere else, while fourteen other
// templates carried a bare `required` attribute with nothing announcing it.
// The browser refuses the submit and points at the field — what it does not do
// is tell somebody, before they start, which of eleven inputs they have to
// fill in. WCAG 3.3.2 asks for the label to carry it, and a validation message
// that appears only after a failed submit is not a label.
//
// Thirty controls across fourteen templates were unmarked, including the API
// token on the sign-in screen, which is the first field anybody using this
// program ever types into.
//
// The check walks the markup rather than the rendered pages, because a
// required field on a screen no fixture happens to populate is still a
// required field.
func TestEveryRequiredFieldIsMarkedInItsLabel(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	files, err := filepath.Glob(filepath.Join(dir, "assets", "*.html"))
	if err != nil || len(files) == 0 {
		t.Skip("no templates found")
	}

	control := regexp.MustCompile(`<(?:input|select|textarea)\b[^>]*\bid="([^"]+)"[^>]*>`)
	// A whole conditional span, not each action separately. Removing
	// {{if .Required}} and {{end}} one at a time leaves the word between them
	// behind and reads a conditional attribute as a hard-coded one — which is
	// how the first version of this test reported edit.html, the one template
	// that was already doing it correctly.
	conditional := regexp.MustCompile(`(?s)\{\{if [^}]*\}\}.*?\{\{end\}\}`)
	action := regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	bare := regexp.MustCompile(`\brequired\b`)

	checked := 0
	var problems []string
	for _, f := range files {
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			continue
		}
		src := string(b)
		name := filepath.Base(f)
		for _, m := range control.FindAllStringSubmatch(src, -1) {
			tag, id := m[0], m[1]
			// name="required" is a checkbox for a field's own requiredness,
			// not a required control.
			if strings.Contains(tag, `name="required"`) {
				continue
			}
			// A conditional `{{if .Required}} required{{end}}` is marked by
			// the same condition on its label, which is how edit.html does it
			// — so only a hard-coded attribute is in scope here.
			plain := action.ReplaceAllString(conditional.ReplaceAllString(tag, ""), "")
			if !bare.MatchString(plain) {
				continue
			}
			checked++
			if !labelMarks(src, id) {
				problems = append(problems, name+": "+id)
			}
		}
	}

	if checked < 25 {
		t.Fatalf("found %d required controls; the parse is wrong and a test "+
			"that checks nothing passes", checked)
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("%s carries a required attribute and its label does not say "+
			"so, so the only thing that tells anybody is the browser refusing "+
			"the submit", p)
	}
}

// labelMarks reports whether the label for an id carries the marker.
func labelMarks(src, id string) bool {
	pat := regexp.MustCompile(`(?s)<label for="` + regexp.QuoteMeta(id) +
		`"[^>]*>(.*?)</label>`)
	m := pat.FindStringSubmatch(src)
	if m == nil {
		// No label at all is a worse problem than an unmarked one, and
		// another test owns it; not marking this as passing either.
		return false
	}
	return strings.Contains(m[1], `template "req"`) ||
		strings.Contains(m[1], `class="req"`)
}
