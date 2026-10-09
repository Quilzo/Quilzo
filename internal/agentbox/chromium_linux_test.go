// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build linux

package agentbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/sandbox"
)

// localChromium is a Chromium on this machine to run in a box: QUILZO_TEST_CHROMIUM,
// or the headless shell Playwright installs. A machine with neither skips.
func localChromium(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("QUILZO_TEST_CHROMIUM"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	found, _ := filepath.Glob(filepath.Join(home, ".cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"))
	if len(found) == 0 {
		t.Skip("no Chromium here to run in a box (set QUILZO_TEST_CHROMIUM)")
	}
	return found[len(found)-1]
}

// A browser runs in the box with every part of it on: its own namespaces,
// files and ports confined, the system call filter, no capabilities, and a
// memory limit it can live with. It sees an empty /sys of the box's own,
// not the machine's hardware.
func TestABrowserRunsInTheBox(t *testing.T) {
	chrome := localChromium(t)
	n := native(t)
	work := t.TempDir()
	var out, errb bytes.Buffer
	res, err := n.Run(context.Background(), Spec{Run: "browser", Agent: "browser", Program: chrome,
		Args: []string{"--headless", "--no-sandbox", "--disable-dev-shm-usage",
			"--user-data-dir=" + filepath.Join(work, "profile"), "--dump-dom", "data:text/html,<p>inside the box</p>"},
		Env: []string{"HOME=" + work, "TMPDIR=" + work}, Workdir: work, Read: []string{filepath.Dir(chrome)},
		Limits: sandbox.Limits{DataBytes: 1 << 30, Processes: 4096, OpenFiles: 1024, CPUSeconds: 60},
		Wall:   30 * time.Second, Stdout: &out, Stderr: &errb})
	if err != nil || res.Exit != 0 {
		t.Fatalf("exit %d, %v\n%s", res.Exit, err, errb.String())
	}
	if !strings.Contains(out.String(), "<p>inside the box</p>") {
		t.Fatalf("the browser drew %q", out.String())
	}
	c := res.Confined
	if !c.Namespaces || !c.Seccomp || !c.Capabilities || !c.Files || !c.Ports || !c.OwnProc {
		t.Errorf("confined %+v", c)
	}
}
