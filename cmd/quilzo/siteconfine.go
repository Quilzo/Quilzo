// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/sandbox"
	"github.com/quilzo/quilzo/internal/shield"
)

// The public site, confined.
//
// It is the one process facing the internet, and it ran as the store's
// owner with the run of the store: a flaw in it was a way to write
// policy.json, tokens.json or config.json, and so to make anybody an
// administrator. It re-executes itself under Landlock (internal/sandbox),
// able to read everything it could before and to write only where its own
// state is kept: form submissions, boards, members, handoffs, analytics, the
// shield, its followers, the model ledger, webhook deliveries, bookings, the
// newsletter's list, the audit log's two files, and a temporary directory of
// its own. The network is left alone:
// it serves, and it calls models, mail and webhooks.
//
// What the site writes was moved out of the store's root to make this
// possible (sitestate.go); what it makes once, the provenance key and the
// audit key, is made before the restriction, by the process that is not yet
// confined. A kernel without Landlock runs it as before, and says so.

// siteConfinedEnv marks the process that is the confined site, so it does
// not confine itself again.
const siteConfinedEnv = "QUILZO_SITE_CONFINED"

// siteTempDir is the confined site's temporary directory (TMPDIR): in the
// store, not the system's, which could hold the store itself and would hand
// the site all of it.
func siteTempDir(root string) string { return filepath.Join(root, "tmp") }

// siteWritable is where the public site may write.
func siteWritable(root string) (dirs, files []string) {
	dirs = []string{
		submissionDir(root), postsDir(root), membersDir(root), handoffDir(root), analyticsDir(root),
		filepath.Dir(shield.Path(root)), filepath.Dir(fediverseFollowersPath(root)),
		filepath.Dir(usagePath(root)), filepath.Dir(deliveriesPath(root)), siteTempDir(root),
		bookingsDir(root), newsletterDir(root),
	}
	// The audit log, unless a separate writer keeps it: then the site hands
	// records to it over its socket and writes none itself.
	if !fileExists(logSocketPath(root)) {
		files = []string{auditPath(root), auditPath(root) + ".lock"}
	}
	return dirs, files
}

// prepareSite makes what the confined site writes to and may not make
// itself, because making it takes writing at the store's root: the audit
// key, the provenance key, the newsletter's key, its directories and the
// audit log's files. It returns the paths the site writes, for a service
// manager that makes the store read-only to be told (`quilzo site
// --prepare`).
//
// strict is for --prepare, run by the store's owner to make them. Starting
// the site is not strict: in a store a service manager keeps read-only, a
// directory an upgrade added cannot be made here, and the feature that
// writes it is off, said so, until the owner runs --prepare, rather than
// the whole site not starting.
func prepareSite(root string, strict bool) ([]string, error) {
	if _, err := openAudit(root); err != nil {
		return nil, err
	}
	_, _, _ = provenanceSigner(root, siteName(root), time.Now())
	// The newsletter's key, which its links are made with: read by the site,
	// written by nobody once made.
	if err := newsletter.MakeKey(newsletterKeyPath(root)); err != nil {
		if strict {
			return nil, fmt.Errorf("making the newsletter's key: %w", err)
		}
		fmt.Fprintf(os.Stderr, "  %sthe newsletter takes no sign-ups until its key is made: run quilzo site "+
			"--prepare as the store's owner (%v)%s\n", yellow, err, reset)
	}
	dirs, files := siteWritable(root)
	var made []string
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			if !strict && (errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EROFS)) {
				fmt.Fprintf(os.Stderr, "  %s%s cannot be made in a read-only store, so what is kept there is off "+
					"until quilzo site --prepare is run as the store's owner%s\n", yellow, d, reset)
				continue
			}
			return nil, fmt.Errorf("making %s for the confined site: %w", d, err)
		}
		made = append(made, d)
	}
	for _, f := range files {
		h, err := os.OpenFile(f, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("making %s for the confined site: %w", f, err)
		}
		_ = h.Close()
	}
	return append(made, files...), nil
}

// confineSite re-executes the site confined, and returns only when it did
// not: the kernel has no Landlock, which it says.
func confineSite(root string) error {
	if sandbox.ABI() == 0 {
		fmt.Fprintf(os.Stderr, "  %snot confined: this kernel has no Landlock, so the site can write "+
			"anything the account running it can%s\n", yellow, reset)
		return nil
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	// Made now, while this process may still make them.
	writable, err := prepareSite(abs, false)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	rules := sandbox.Rules{
		// Read is everything: the store, the templates, the certificates
		// that let it reach a model, the zone database. What it must not
		// do is write, and that is what the rest of this is.
		Read:         []string{"/"},
		ReadWrite:    writable,
		AllowNetwork: true,
	}
	return sandbox.RestrictAndExec(rules, exe, os.Args,
		append(os.Environ(), siteConfinedEnv+"=1", "TMPDIR="+siteTempDir(abs)))
}

// checkSiteConfined proves, in the confined site, that what it must not
// write it cannot: each file is opened for writing, which changes nothing,
// and must be refused. A site that could is not started.
func checkSiteConfined(root string) error {
	// The payment links too: a site that could rewrite them could send every
	// Buy button to somebody else's checkout.
	// And how bookings are taken: a site that could rewrite its own hours
	// or turn on a feed of its calendar would be answering to nobody.
	// And the newsletter's key: a site that could replace it could make
	// every link already mailed stop working.
	for _, name := range []string{"policy.json", "tokens.json", "config.json", "pay/links.json", "pay/pay.json",
		"bookings.json", "newsletter.key"} {
		path := filepath.Join(root, name)
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			_ = f.Close()
			return fmt.Errorf("the site was to be confined and can still write %s; it is not started", path)
		}
		if !errors.Is(err, syscall.EACCES) && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("checking the site cannot write %s: %w", path, err)
		}
	}
	// And nothing new at the root.
	probe := filepath.Join(root, ".site-confined-probe")
	if f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
		_ = f.Close()
		_ = os.Remove(probe)
		return fmt.Errorf("the site was to be confined and can still make files in %s; it is not started", root)
	}
	return nil
}
