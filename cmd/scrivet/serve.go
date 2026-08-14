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
	"github.com/rsh1k/scrivet/internal/provenance"
)

func cmdServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	tplDir := fs.String("templates", "templates", "where page.html lives")
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
