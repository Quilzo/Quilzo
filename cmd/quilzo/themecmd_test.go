// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/theme"
)

// savedTheme is the theme a reader would be served from what dir holds.
func savedTheme(t *testing.T, dir string) *theme.Theme {
	t.Helper()
	values, err := loadThemeFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	th, problems := theme.New(values, nil)
	if theme.Blocks(problems) {
		t.Fatalf("the saved theme does not load: %v", problems)
	}
	return th
}

// A colour set for both schemes takes effect in both, whatever the file
// already says for one of them.
//
// `theme generate` writes a key per scheme, on-surface.light and
// on-surface.dark, and a key that names a scheme wins over the bare one in
// that scheme. So `theme set on-surface …` afterwards was saved, printed back
// as set, and changed nothing a reader sees, in either scheme.
func TestSettingAColourForBothSchemesIsNotShadowedByOneScheme(t *testing.T) {
	root, dir := t.TempDir(), t.TempDir()
	if err := writeThemeFile(dir, map[string]string{
		"on-surface.light": "#222222", "on-surface.dark": "#eeeeee",
		"primary.dark": "#8ecfe8",
	}); err != nil {
		t.Fatal(err)
	}

	said, err := humanOutput(t, func() error {
		return cmdTheme(root, []string{"set", "on-surface", "#333333", "--dir", dir, "--force"})
	})
	if err != nil {
		t.Fatal(err)
	}
	th := savedTheme(t, dir)
	for _, dark := range []bool{false, true} {
		if v, _ := th.Value("on-surface", dark); v != "#333333" {
			t.Errorf("on-surface in the %s scheme is %s after `theme set on-surface #333333`",
				schemeName(dark), v)
		}
	}
	if !strings.Contains(said, "on-surface.dark and on-surface.light") {
		t.Errorf("the command does not say which keys its value replaced:\n%s", said)
	}

	// A scheme key named in the same command is what was asked for, in
	// either order, and a key for another token is left alone.
	if _, err := humanOutput(t, func() error {
		return cmdTheme(root, []string{"set", "on-surface.dark", "#dddddd",
			"on-surface", "#444444", "--dir", dir, "--force"})
	}); err != nil {
		t.Fatal(err)
	}
	th = savedTheme(t, dir)
	if v, _ := th.Value("on-surface", true); v != "#dddddd" {
		t.Errorf("on-surface.dark, named in the same command, came out %s", v)
	}
	if v, _ := th.Value("on-surface", false); v != "#444444" {
		t.Errorf("on-surface in the light scheme came out %s", v)
	}
	if v, _ := th.Value("primary", true); v != "#8ecfe8" {
		t.Errorf("primary.dark was touched by a set of on-surface: %s", v)
	}
}
