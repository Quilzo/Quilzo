// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
)

// Finding STACK-F3. In the reference container /srv is read-only, and the
// demonstration's examples go beside its templates, to /srv/examples. So
// `quilzo demo` there wrote the pages, records, types, listings, forms,
// menus, templates and settings, then failed at "mkdir /srv/examples:
// read-only file system" -- and the next `demo` was refused, "already
// installed here", until `demo remove --yes`. The folders it writes outside
// the store are written last; whether they can be is asked first.
func TestADemoThatCannotWriteItsFoldersWritesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	w = out.New(false)
	base := t.TempDir()
	root := filepath.Join(base, "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	// A place no folder can be made in, whoever runs this: a file where the
	// folder's parent would be, as unwritable to root as a read-only /srv.
	blocked := filepath.Join(base, "srv")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tpl, ex := filepath.Join(base, "templates"), filepath.Join(base, "examples")
	for _, c := range []struct{ flag, tpl, ex string }{
		{"--examples", tpl, filepath.Join(blocked, "examples")},
		{"--templates", filepath.Join(blocked, "templates"), ex},
	} {
		err := cmdDemo(root, []string{"--templates", c.tpl, "--examples", c.ex})
		if err == nil {
			t.Fatalf("installed with %s where nothing can be written", c.flag)
		}
		if !strings.Contains(err.Error(), "quilzo demo "+c.flag) {
			t.Errorf("the refusal does not say which folder to give instead: %v", err)
		}
		if !gone(t, demoManifestPath(root)) {
			t.Fatalf("with %s unwritable, a half-installed demonstration was left behind: %v", c.flag, err)
		}
		if pages := pagesIn(t, root, site.RefDraft); len(pages) > 0 {
			t.Fatalf("with %s unwritable, %d page(s) were written", c.flag, len(pages))
		}
		if cfg, cerr := loadConfig(root); cerr != nil || cfg.Raw("site.name") != "" {
			t.Fatalf("with %s unwritable, the settings were changed (%v)", c.flag, cerr)
		}
	}
	// And so it installs once given folders it can write, rather than being
	// refused as already there.
	if err := cmdDemo(root, []string{"--templates", tpl, "--examples", ex}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tpl, "page.html")); err != nil {
		t.Fatal(err)
	}
}
