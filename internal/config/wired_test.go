// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package config_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
)

// Every setting must be read by something.
//
// # Why this exists
//
// An audit found six settings that were settable, validated, documented with a
// compliance mapping, rendered in the admin, and read by nothing. `quilzo
// config set` reported success and the value went nowhere.
//
// The worst of them was approval.required_humans, whose own explanatory text
// ends "Set to two, nothing publishes without two people." Setting it to two
// did nothing at all. Two others — api.page.max and api.body.max_bytes — were
// shadowed by compile-time constants, and the table advertised a default of
// 1 MiB while the code enforced 2 MiB, so an operator who tightened the limit
// got a looser one than the documentation promised.
//
// A setting nobody reads is worse than a missing one. A missing setting is a
// feature request; a dead one is a control an operator believes they have, and
// it will be written into a system security plan as satisfied.
//
// # Why this is a source walk
//
// Because the failure is a call nobody wrote. There is no behaviour to drive:
// the setting parses, stores and displays correctly, and does nothing. The
// only evidence is the absence of a reader, so the absence is what this looks
// for.
//
// A key may be exempt, and the exemption has to name a reason. The point is
// that removing a reader becomes a decision somebody writes down rather than
// something that happens.
func TestEverySettingIsReadBySomething(t *testing.T) {
	src := sourceOfTree(t, "../..")
	if len(src) < 200_000 {
		t.Fatalf("read %d bytes of source; the walk is wrong and a test that "+
			"sees nothing passes", len(src))
	}

	var dead []string
	for _, s := range config.All() {
		if why := exempt[s.Key]; why != "" {
			continue
		}
		// The key as a reader would spell it: a quoted string handed to
		// cfg.Bool, cfg.Int, cfg.Raw and the rest.
		if strings.Contains(src, `"`+s.Key+`"`) {
			continue
		}
		dead = append(dead, s.Key)
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf("these settings are offered and nothing reads them:\n  %s\n"+
			"A setting nobody reads is a control an operator believes they "+
			"have. Wire it, remove it, or add it to `exempt` with the "+
			"reason.", strings.Join(dead, "\n  "))
	}
}

// exempt names the settings that are deliberately read by nothing, and why.
//
// Empty, and that is the point: every entry added here is an argument somebody
// had to write down.
var exempt = map[string]string{}

// sourceOfTree concatenates the non-test Go source, so a walk covers what is
// added later rather than a list from the day it was written.
func sourceOfTree(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// The table itself is where the keys are declared, not read.
		if strings.HasSuffix(path, "internal/config/settings.go") {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		b.Write(body)
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
