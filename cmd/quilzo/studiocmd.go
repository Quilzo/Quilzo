// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/listen"
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
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}

	srv, err := studioServer(root)
	if err != nil {
		return err
	}
	if len(srv.Tokens.Snapshot()) == 0 {
		// Said before it is a mystery. A capture surface nobody can sign in
		// to looks broken, and the reason is one command away.
		fmt.Fprintf(os.Stderr, "  %sno tokens exist yet, so nobody can sign "+
			"in:%s\n", dim, reset)
		fmt.Fprintf(os.Stderr, "  %squilzo token issue you --principal you "+
			"--role author%s\n", dim, reset)
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

	server := &http.Server{Addr: *addr, Handler: srv.Handler()}
	// A recording is large and the upload is the whole point, so neither the
	// request nor the response is given a fixed deadline; what bounds this
	// server is the idle deadline and the connection limit. The headers still
	// have ten seconds. See internal/listen.
	return listen.Uploads().Serve(server)
}

// studioServer is the capture surface over a store.
func studioServer(root string) (*studio.Server, error) {
	pol, err := loadPolicy(root)
	if err != nil {
		return nil, err
	}
	tokens, err := loadTokens(root)
	if err != nil {
		return nil, err
	}
	// The shield's lockdown and suspensions, on every token store this
	// server loads, as the admin's and the API's are (shieldhost.go). The
	// studio loaded its own and asked nothing, so a token suspended with
	// `quilzo shield suspend`, or one from before a lockdown, went on
	// recording here after every other door had shut on it.
	sh := newShieldHost(root)
	return &studio.Server{
		Tokens: sh.gate(tokens),
		Policy: pol,
		// Read again for every request, as the admin's are (serve.go):
		// revoking a token or withdrawing a grant stops it here too, and a
		// token issued since the studio started signs in.
		Reload: func() (*auth.Policy, *auth.TokenStore, error) {
			pol, err := loadPolicy(root)
			if err != nil {
				return nil, nil, err
			}
			toks, err := loadTokens(root)
			if err != nil {
				return nil, nil, err
			}
			return pol, sh.gate(toks), nil
		},
		Library: func() (*medialib.Library, error) {
			return openMedia(root)
		},
		Options: func() media.Options { return mediaOptionsAt(root) },
		// The configured policy, not the compiled-in default.
		//
		// throttlePolicy's own comment says it exists so "the CLI, the admin
		// interface and the API cannot end up with three different ideas of
		// how many attempts are free" — and this was the fourth surface,
		// built after that sentence was written, holding throttle.Default().
		// Every auth.throttle setting was silently ignored
		// on this port, and the studio does authenticate tokens, so the
		// policy mattered here.
		Throttle: throttle.New(throttlePolicy(mustConfig(root))),
		Audit: func(action, resource string, detail map[string]string) {
			record(root, studioRecord(action, resource, detail))
		},
		// When each token was last used, which a copy read per request
		// forgot, as at the admin's /api/v1 and /mcp (useRecorder).
		OnTokenUsed: useRecorder(root),
	}, nil
}

// studioRecord is an audit record for what the studio reports, made out to
// the holder of the token it authenticated.
//
// It was made out to whoever started the studio: resolveCaller on the
// process, so its token file, QUILZO_TOKEN or $USER. Every recording
// anybody put in the library through the page was in the log as the
// operator's, the person whose token did it only a detail beside it, and a
// refused sign-in was the operator's success. The studio names the holder
// under "principal" once it has checked their token, a person at a
// browser; a refusal at the door names nobody, and is a refusal, the way
// the admin's are (adminRecord).
func studioRecord(action, resource string, detail map[string]string) audit.Record {
	r := adminRecord(action, resource, detail)
	if who := detail["principal"]; who != "" {
		r.Principal, r.Kind, r.Verified = who, audit.KindHuman, true
	}
	return r
}
