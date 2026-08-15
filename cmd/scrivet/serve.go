package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rsh1k/scrivet/internal/admin"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/posture"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/schema"
)

func cmdServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	tplDir := fs.String("templates", "templates", "where page.html lives")
	// Declared so the posture scan can tell interception from exposure. An
	// operator who terminates TLS at a proxy should not be told they serve
	// cleartext — a rule a correct deployment cannot satisfy is a rule people
	// learn to ignore.
	behindProxy := fs.Bool("behind-proxy", false,
		"a reverse proxy terminates TLS in front of this")
	publicAddr := fs.String("public-addr", "",
		"where the public site is served, for the posture scan")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	toks, err := loadTokens(root)
	if err != nil {
		return err
	}

	siteTpl := ""
	if b, err := os.ReadFile(filepath.Join(*tplDir, "page.html")); err == nil {
		siteTpl = string(b)
	} else {
		fmt.Fprintf(os.Stderr, "  %sno %s; preview and the accessibility check "+
			"are unavailable%s\n", dim, filepath.Join(*tplDir, "page.html"), reset)
	}

	srv, err := admin.New(s, pol, toks, siteTpl)
	if err != nil {
		return err
	}
	// The admin does not need to know where provenance lives, so the host
	// supplies the two functions and keeps the file layout in one place.
	srv.LoadProvenance = func() (*provenance.Index, error) { return loadProvenance(root) }
	srv.SaveProvenance = func(i *provenance.Index) error { return saveJSON(provPath(root), i) }
	// Types are re-read per request rather than captured once. A type added
	// from the CLI while the server is running must take effect immediately,
	// for the same reason revoked tokens do: a control that needs a restart is
	// a control that is off for as long as nobody restarts.
	srv.CheckTypes = func(pages map[string]any) []schema.Failure {
		st, err := schema.Load(root)
		if err != nil {
			// Fail closed. An unreadable types file is not the same as a site
			// with no types, and treating it as one would make corrupting the
			// file a way to switch validation off.
			return []schema.Failure{{Page: "(all)", Type: "?", Problems: []schema.Problem{
				{Field: "types.json", Reason: "cannot be read: " + err.Error()}}}}
		}
		return st.Gate(pages)
	}
	srv.TypeFor = func(page string) (schema.Type, bool) {
		st, err := schema.Load(root)
		if err != nil {
			return schema.Type{}, false
		}
		name, bound := st.Bound[page]
		if !bound {
			return schema.Type{}, false
		}
		return st.Registry.Get(name)
	}
	// The scan runs per request rather than on a timer here, because the
	// dashboard is the thing being looked at: a cached posture is a posture
	// from before whatever the person just changed.
	srv.Posture = func() posture.Report {
		state := Observe(root, *tplDir, posture.ServerFacts{
			AdminAddr: *addr, PublicAddr: *publicAddr, BehindProxy: *behindProxy,
		})
		sup, _ := loadSuppressions(root)
		return posture.Scan(state, sup)
	}
	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		pol, err := loadPolicy(root)
		if err != nil {
			return nil, nil, err
		}
		toks, err := loadTokens(root)
		if err != nil {
			return nil, nil, err
		}
		return pol, toks, nil
	}

	// Loopback by default. An editing interface that binds every interface the
	// moment someone runs it is how a development server ends up on the
	// internet, and the fix has to be a decision rather than a default.
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("admin on http://%s\n", *addr)
	fmt.Printf("  %ssign in with a token: scrivet token issue you --principal you "+
		"--role admin%s\n", dim, reset)
	if len(toks.Tokens) == 0 {
		fmt.Printf("  %sno tokens exist yet, so nobody can sign in%s\n", yellow, reset)
	}
	return httpSrv.ListenAndServe()
}
