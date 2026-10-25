// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/browser"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/out"
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
		if w.Mode == out.JSON {
			doc := map[string]any{"browser": nil, "from": nil}
			if err != nil {
				doc["problem"] = err.Error()
			} else {
				doc["browser"], doc["from"] = path, from
			}
			n, nerr := programBackend(root, "native", "")
			if nerr != nil {
				return nerr
			}
			a := n.Check()
			doc["agent_box"], doc["agent_box_why"] = a.OK, a.Why
			w.JSON(doc)
			return nil
		}
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
	case "grant", "grants":
		return cmdBrowserGrant(root, args[1:])
	}
	return fmt.Errorf("unknown browser command %q; try status, install or grant", args[0])
}

// cmdBrowserGrant declares what an outside MCP client's browser may do:
// which hosts, which actions, how many calls a day. An offer that names no
// host and no action is refused, as an agent's declaration is.
func cmdBrowserGrant(root string, args []string) error {
	if len(args) == 0 {
		set, err := loadBrowserGrants(root)
		if err != nil {
			return err
		}
		if len(set) == 0 {
			fmt.Printf("  no browser grants. `quilzo browser grant NAME --read HOST,…` declares one\n")
			return nil
		}
		for _, name := range grantNames(root) {
			g := set[name]
			fmt.Printf("%s  %s%s reads %s", bold, name, reset, strings.Join(g.Read, ", "))
			if len(g.Write) > 0 {
				fmt.Printf(", acts on %s", strings.Join(g.Write, ", "))
			}
			if g.Pictures {
				fmt.Printf(", with pictures")
			}
			if g.Daily > 0 {
				fmt.Printf(", at most %d calls a caller a day", g.Daily)
			}
			fmt.Println()
		}
		fmt.Printf("  offered at /mcp/browser/NAME on the admin, to any token that reaches that path:\n")
		fmt.Printf("  a reader's to read the page, an author's to act on it\n")
		return nil
	}
	name := args[0]
	if name == "--off" {
		return fmt.Errorf("say which grant: `quilzo browser grant NAME --off`")
	}
	if !grantName.MatchString(name) {
		return fmt.Errorf("%q is not a name a grant may carry", name)
	}
	fs := flag.NewFlagSet("browser grant", flag.ContinueOnError)
	read := fs.String("read", "", "hosts the browser may open and read, comma-separated")
	write := fs.String("write", "", "hosts it may also act on, comma-separated")
	ops := fs.String("ops", "", "actions offered (default: all but sign-in)")
	pictures := fs.Bool("pictures", false, "allow browser_look, which carries a picture of the page")
	daily := fs.Int("daily", 0, "calls one caller may make a day")
	off := fs.Bool("off", false, "withdraw the grant")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	if err := authorise(root, caller, auth.ActGrant, "/browser/grant"); err != nil {
		return err
	}
	if *off {
		set, err := loadBrowserGrants(root)
		if err != nil {
			return err
		}
		if _, ok := set[name]; !ok {
			return fmt.Errorf("there is no browser grant called %s", name)
		}
		delete(set, name)
		var f grantsFile
		for _, g := range set {
			f.Grants = append(f.Grants, g)
		}
		b, _ := json.MarshalIndent(f, "", "  ")
		if err := os.MkdirAll(filepath.Dir(grantsPath(root)), 0o700); err != nil {
			return err
		}
		if err := atomicfile.Write(grantsPath(root), b, 0o600); err != nil {
			return err
		}
		closeGrantSessionsOf(name, "the grant was withdrawn", time.Now())
		record(root, caller.auditRecord("browser.grant", "/mcp/browser/"+name, audit.Success,
			map[string]string{"grant": name, "off": "1"}))
		fmt.Printf("  %swithdrawn, and any browser running on it closed%s\n", green, reset)
		return nil
	}
	hosts := func(list string) []string {
		var out []string
		for _, h := range strings.Split(list, ",") {
			if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
				out = append(out, h)
			}
		}
		return out
	}
	g := browserGrant{Name: name, Read: hosts(*read), Write: hosts(*write),
		Ops: hosts(*ops), Pictures: *pictures, Daily: *daily}
	for _, op := range g.Ops {
		if op != "browser_sign_in" && !slices.Contains(agent.BrowserCapabilities[:], op) {
			return fmt.Errorf("%q is not a browser action a grant may offer", op)
		}
	}
	if _, err := g.manifest(); err != nil {
		return err
	}
	if len(g.Ops) == 0 {
		g.Ops = nil
	}
	if err := saveBrowserGrant(root, g); err != nil {
		return err
	}
	record(root, caller.auditRecord("browser.grant", "/mcp/browser/"+name, audit.Success,
		map[string]string{"grant": name, "reads": strconv.Itoa(len(g.Read)), "acts_on": strconv.Itoa(len(g.Write))}))
	fmt.Printf("  %soffered at /mcp/browser/%s on the admin%s\n", green, name, reset)
	fmt.Printf("  any token that reaches that path may use it, a reader's to read and an author's to act;\n")
	fmt.Printf("  one for it alone: `quilzo token issue NAME --on /mcp/browser/%s`\n", name)
	return nil
}
