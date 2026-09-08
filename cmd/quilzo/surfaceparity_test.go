// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// The same capability needs the same privilege on every surface.
//
// CONTRIBUTING.md asks that every capability be reachable from the CLI, the
// browser and the agent interface. Nothing asked that they agree about who may
// use it, and they did not: writing a content type needed publish on the
// command line and edit-draft in the browser, so an author could bind or
// unbind the type gate through a screen and was refused from a script.
//
// The two code comments had made the same observation — editing a type
// "changes what every author may store" — and stopped at different
// conclusions. That is the failure mode this test is for: not a missing check,
// but two correct-looking local decisions that disagree, in files nobody reads
// together.
//
// Deliberately a small table rather than a generated one. A test that tried to
// derive every route's action would be a second implementation of the admin's
// routing, and the entries here are the ones where a disagreement is a
// privilege inversion rather than a difference of opinion.
func TestTheSurfacesAgreeAboutPrivilege(t *testing.T) {
	cases := []struct {
		capability string // key in commandNeeds
		file       string // the admin file holding the gate
		fn         string // the preamble or handler that gates it
	}{
		{"type", "types.go", "typeWriter"},
		{"types", "types.go", "typeWriter"},
	}

	root := repoRoot(t)
	for _, c := range cases {
		want, ok := commandNeeds[c.capability]
		if !ok {
			t.Errorf("commandNeeds has no %q, so this test is out of date",
				c.capability)
			continue
		}
		got, err := adminAction(root, c.file, c.fn)
		if err != nil {
			t.Errorf("%s: %v", c.capability, err)
			continue
		}
		if got != want.action {
			t.Errorf("%q needs %s on the command line and %s in the browser "+
				"(%s/%s). One of the two lets somebody do through a screen "+
				"what they are refused from a script",
				c.capability, want.action, got, c.file, c.fn)
		}
	}
}

// adminAction reads the action a named admin function checks.
var reCan = regexp.MustCompile(`s\.can\([^)]*auth\.(Act[A-Za-z]+)`)

func adminAction(root, file, fn string) (auth.Action, error) {
	b, err := os.ReadFile(filepath.Join(root, "internal", "admin", file))
	if err != nil {
		return "", err
	}
	src := string(b)
	i := strings.Index(src, ") "+fn+"(")
	if i < 0 {
		i = strings.Index(src, "func "+fn+"(")
	}
	if i < 0 {
		return "", fmt.Errorf("no function %s in internal/admin/%s", fn, file)
	}
	body := src[i:]
	if j := strings.Index(body, "\n}\n"); j > 0 {
		body = body[:j]
	}
	m := reCan.FindStringSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("%s in internal/admin/%s calls no s.can, so it gates "+
			"on nothing this test can read", fn, file)
	}
	switch m[1] {
	case "ActView":
		return auth.ActView, nil
	case "ActEditDraft":
		return auth.ActEditDraft, nil
	case "ActPublish":
		return auth.ActPublish, nil
	case "ActRollback":
		return auth.ActRollback, nil
	case "ActGrant":
		return auth.ActGrant, nil
	case "ActToken":
		return auth.ActToken, nil
	}
	return "", fmt.Errorf("%s checks auth.%s, which this test does not know", fn, m[1])
}
