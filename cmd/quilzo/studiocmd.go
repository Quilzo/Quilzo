// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/studio"
	"github.com/quilzo/quilzo/internal/throttle"
)

// cmdStudio serves the capture surface.
//
// A fourth server, on a fourth port, because it runs a script and the admin
// does not. See internal/studio for the argument; the short version is that
// the admin's `default-src 'none'` is a property worth keeping and a screen
// recorder cannot exist under it.
//
// Loopback by default, like the admin. This is authenticated and writable,
// which is the combination that belongs behind whatever tunnel the operator
// already trusts rather than on a hostname.
func cmdStudio(root string, args []string) error {
	fs := flag.NewFlagSet("studio", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8084", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	tokens, err := loadTokens(root)
	if err != nil {
		return err
	}
	if len(tokens.Snapshot()) == 0 {
		// Said before it is a mystery. A capture surface nobody can sign in
		// to looks broken, and the reason is one command away.
		fmt.Fprintf(os.Stderr, "  %sno tokens exist yet, so nobody can sign "+
			"in:%s\n", dim, reset)
		fmt.Fprintf(os.Stderr, "  %squilzo token issue you --principal you "+
			"--role author%s\n", dim, reset)
	}

	srv := &studio.Server{
		Tokens: tokens,
		Policy: pol,
		Library: func() (*medialib.Library, error) {
			return openMedia(root)
		},
		Options:  func() media.Options { return mediaOptionsAt(root) },
		Throttle: throttle.New(throttle.Default()),
		Audit: func(action, resource string, detail map[string]string) {
			record(root, resolveCaller(root, "").auditRecord(
				action, resource, audit.Success, detail))
		},
	}

	fmt.Fprintf(os.Stderr, "studio on http://%s\n", *addr)
	fmt.Fprintf(os.Stderr, "  %sit records the screen and stores the result; "+
		"there is no editor here%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sa separate origin because it runs a script, "+
		"which the admin does not%s\n", dim, reset)
	if _, ok := media.HaveFFmpeg(); !ok {
		fmt.Fprintf(os.Stderr, "  %sno ffmpeg here, so a recording is stored "+
			"without its length or a poster frame%s\n", dim, reset)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout. A recording is large and the upload is the whole
		// point; a deadline here would cut off the operation this server
		// exists for, on exactly the slow connection that needs longest.
		IdleTimeout: 2 * time.Minute,
	}
	return server.ListenAndServe()
}
