package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/public"
	"github.com/rsh1k/scrivet/internal/seo"
	"github.com/rsh1k/scrivet/internal/site"
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
	baseURL := fs.String("base-url", "",
		"absolute origin, e.g. https://example.com — required for the sitemap")
	redirectFile := fs.String("redirects", "",
		"a redirect map, as written by scrivet import")
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
	st.BaseURL = strings.TrimSpace(*baseURL)

	// Languages, if configured. A single-language site never sees this: the
	// sitemap is byte-identical to what it was before the feature existed.
	if locales, lerr := loadLocales(root); lerr == nil && locales != nil &&
		len(locales.Locales) > 1 {
		st.Locales = locales
	}

	// lastmod is computed per request rather than cached, because it is derived
	// from history and history only grows. A cached value would go stale
	// exactly when a page changed, which is the one moment it matters.
	st.LastChanged = func() (map[string]time.Time, error) {
		return seo.LastChanged(s, s.GetRef(site.RefLive), 5000)
	}

	if *redirectFile != "" {
		var file struct {
			Redirects []seo.Redirect `json:"redirects"`
		}
		if err := loadJSON(*redirectFile, &file); err != nil {
			return err
		}
		m, err := seo.NewMap(file.Redirects)
		if err != nil {
			// Refused at startup rather than at request time. A redirect map
			// with a loop in it should stop the server coming up, not send
			// visitors round in circles.
			return fmt.Errorf("%s: %w", *redirectFile, err)
		}
		st.Redirects = m
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
