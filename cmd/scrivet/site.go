package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/public"
)

// cmdSite serves the published site.
//
// Separate from `serve`, which is the admin, and separate on purpose. They have
// different audiences, different auth, and different exposure: the admin belongs
// on loopback behind whatever you already trust, and this is the thing you point
// the internet at. Running both on one port would mean one misconfiguration
// exposes the editing interface.
func cmdSite(root string, args []string) error {
	fs := flag.NewFlagSet("site", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:8081", "listen address")
	tplDir := fs.String("templates", "templates", "where page.html lives")
	name := fs.String("name", "", "site name, shown when installing")
	desc := fs.String("description", "", "site description")
	index := fs.String("index", "index", "the page served at /")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	tplPath := filepath.Join(*tplDir, "page.html")
	raw, err := os.ReadFile(tplPath)
	if err != nil {
		return fmt.Errorf("no template at %s: %w", tplPath, err)
	}

	st := public.New(s, string(raw))
	// The stylesheet beside the template, if there is one. A starter writes
	// both into the same directory, so this is the file `template use` just
	// produced — and it is read once here rather than resolved per request.
	if css, err := os.ReadFile(filepath.Join(*tplDir, "site.css")); err == nil {
		st.Stylesheet = string(css)
	}
	st.Index = *index
	if *name != "" {
		st.Name = *name
	}
	st.Description = *desc
	st.LoadProvenance = func() (*provenance.Index, error) { return loadProvenance(root) }

	srv := &http.Server{
		Addr:              *addr,
		Handler:           st.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("site on http://%s\n", *addr)
	fmt.Printf("  %sserving the live ref; drafts are not public%s\n", dim, reset)
	fmt.Printf("  %sinstallable: /manifest.webmanifest · offline: /sw.js%s\n", dim, reset)
	if fp := st.Fingerprint(); fp != "" {
		fmt.Printf("  %spublished fingerprint %s%s\n", dim, fp, reset)
	} else {
		fmt.Printf("  %snothing is published yet; run scrivet publish%s\n", yellow, reset)
	}
	return srv.ListenAndServe()
}
