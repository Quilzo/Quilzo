// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"os"
	"path/filepath"
	"testing"
)

// localChromium is a Chromium on this machine, or the test is skipped.
func localChromium(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("QUILZO_TEST_CHROMIUM"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	found, _ := filepath.Glob(filepath.Join(home, ".cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"))
	if len(found) == 0 {
		t.Skip("no Chromium here (set QUILZO_TEST_CHROMIUM)")
	}
	return found[len(found)-1]
}
