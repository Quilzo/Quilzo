// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/browser"
	"github.com/quilzo/quilzo/internal/fetch"
)

// The browser an agent's browser runs: the pinned Chrome for Testing build,
// kept in the store's own directory, or a Chromium named by browser.path for
// a machine that cannot download it.

func browserDir(root string) string { return filepath.Join(root, "browser") }

// browserPath is the browser agents would use, and where it came from.
func browserPath(root string) (path, from string, err error) {
	if c, cerr := loadConfig(root); cerr == nil {
		if p := c.Raw("browser.path"); p != "" {
			if !filepath.IsAbs(p) {
				return "", "", fmt.Errorf("browser.path is %q, which is not an absolute path", p)
			}
			fi, serr := os.Stat(p)
			if serr != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
				return "", "", fmt.Errorf("browser.path is %s, which is not a program here", p)
			}
			return p, "browser.path", nil
		}
	}
	if exe, ok := browser.Pinned.Installed(browserDir(root)); ok {
		if abs, aerr := filepath.Abs(exe); aerr == nil {
			exe = abs
		}
		return exe, "the pinned Chrome for Testing " + browser.Pinned.Version, nil
	}
	return "", "", errors.New("no browser yet: quilzo browser install fetches the pinned one, " +
		"or set browser.path to a Chromium on this machine")
}

func cmdBrowser(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		path, from, err := browserPath(root)
		if err != nil {
			fmt.Printf("  %s%s%s\n", yellow, err.Error(), reset)
		} else {
			fmt.Printf("%s%s%s\n  %sfrom %s%s\n", bold, path, reset, dim, from, reset)
		}
		n, nerr := programBackend(root, "native", "")
		if nerr != nil {
			return nerr
		}
		if a := n.Check(); a.OK {
			fmt.Printf("  %sruns in the agent box on this machine%s\n", green, reset)
		} else {
			fmt.Printf("  %sno agent box here, so no agent browses: %s%s\n", yellow, a.Why, reset)
		}
		return nil
	case "install":
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		d, err := browser.Pinned.ForThisMachine()
		if err != nil {
			return err
		}
		fmt.Printf("  %sfetching Chrome for Testing %s (%d MB), checked against the SHA-256 this release pins%s\n",
			dim, browser.Pinned.Version, d.Size>>20, reset)
		exe, err := browser.Pinned.Install(ctx, browserDir(root), func(ctx context.Context, url string, max int64) ([]byte, error) {
			c := fetch.For("browser")
			c.Limits = fetch.Limits{MaxBytes: max, Timeout: 15 * time.Minute, MaxRedirects: -1}
			r, err := c.Get(ctx, url)
			if err != nil {
				return nil, err
			}
			return r.Body, nil
		})
		if err != nil {
			return err
		}
		caller := resolveCaller(root, "")
		record(root, caller.auditRecord("browser.install", "/", audit.Success,
			map[string]string{"version": browser.Pinned.Version, "sha256": d.SHA256}))
		fmt.Printf("%s\n  %sinstalled and checked%s\n", exe, green, reset)
		return nil
	}
	return fmt.Errorf("unknown browser command %q; try status or install", args[0])
}
