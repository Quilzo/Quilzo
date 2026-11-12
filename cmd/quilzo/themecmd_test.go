// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
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

// `theme set` before any site existed answered "open
// templates/theme.json: no such file or directory": true, and no help to
// somebody who has not started a site yet, which is the only way to have no
// templates directory. It says to start one, and how, and leaves nothing
// behind; so does `theme generate`, and the Design screen's save, which
// write the same file.
func TestThemeSetOnAnEmptyStoreSaysWhatToDo(t *testing.T) {
	asMachine(t, false)
	root := t.TempDir()
	tpl := filepath.Join(t.TempDir(), "templates")
	for _, args := range [][]string{
		{"set", "radius", "3px", "--dir", tpl},
		{"generate", "#0b57d0", "--dir", tpl},
	} {
		err := cmdTheme(root, args)
		if err == nil || !strings.Contains(err.Error(), "quilzo site new") || !strings.Contains(err.Error(), "quilzo demo") ||
			strings.Contains(err.Error(), "no such file") {
			t.Errorf("theme %s on an empty store: %v", args[0], err)
		}
	}
	if err := writeThemeFile(tpl, map[string]string{"radius": "3px"}); err == nil || !strings.Contains(err.Error(), "quilzo site new") {
		t.Errorf("the Design screen's save on an empty store: %v", err)
	}
	if _, err := os.Stat(tpl); !os.IsNotExist(err) {
		t.Errorf("an empty store was given a templates directory: %v", err)
	}
	// Where there is a site, it is set as before.
	if err := os.MkdirAll(tpl, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cmdTheme(root, []string{"set", "radius", "3px", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if v, _ := loadThemeFile(tpl); v["radius"] != "3px" {
		t.Errorf("saved %v", v)
	}
}

// A style layer is saved into the same directory as theme.json, and on a
// store with no site it answered "preparing to write templates/style.css:
// ... no such file or directory", from `theme layer set` and from the Design
// screen alike: the answer `theme set` gave before it said to start a site.
// It says so too, and leaves nothing behind.
func TestALayerSetOnAnEmptyStoreSaysWhatToDo(t *testing.T) {
	root, _ := designStore(t)
	asPublisher(t, root)
	tpl := filepath.Join(t.TempDir(), "templates")
	css := writeTemp(t, "arena.css", []byte(".card { border-color: var(--outline); }\n"))
	err := cmdTheme(root, []string{"layer", "set", css, "--dir", tpl})
	if err == nil || !strings.Contains(err.Error(), "quilzo site new") || strings.Contains(err.Error(), "no such file") {
		t.Errorf("theme layer set on an empty store: %v", err)
	}
	dw := newDesignWatch(tpl, nil, func(*Design) {})
	err = adminDesignHooks(tpl, dw).SaveLayer(".card { border-color: var(--outline); }\n")
	if err == nil || !strings.Contains(err.Error(), "quilzo site new") || strings.Contains(err.Error(), "no such file") {
		t.Errorf("the Design screen's layer on an empty store: %v", err)
	}
	if _, err := os.Stat(tpl); !os.IsNotExist(err) {
		t.Errorf("an empty store was given a templates directory: %v", err)
	}
}
