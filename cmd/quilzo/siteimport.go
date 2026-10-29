// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/webimport"
)

// Bringing a live website in by its address (internal/webimport): read
// through the fetcher that refuses private addresses, under the import
// purpose, made into a site package, and installed like any other.

// siteImportTimeout bounds one import, the pages and the pictures.
const siteImportTimeout = 10 * time.Minute

// siteImportGetSeam replaces the web in tests.
var siteImportGetSeam webimport.Getter

// importSite reads a site and makes it a package, keeping the pictures it
// describes in the media library when pictures is set.
func importSite(ctx context.Context, root, address, name string, max int, pictures bool, caller *Caller) (*webimport.Brought, *webimport.Site, error) {
	client := fetch.For("import")
	get := siteImportGetSeam
	if get == nil {
		get = func(ctx context.Context, raw string) (*webimport.Fetched, error) {
			res, err := client.Get(ctx, raw)
			if err != nil {
				return nil, err
			}
			return &webimport.Fetched{FinalURL: res.FinalURL, Status: res.Status, ContentType: res.ContentType,
				Body: res.Body, Truncated: res.Truncated}, nil
		}
	}
	site, err := webimport.Crawl(ctx, address, webimport.Options{Max: max, Get: get})
	if err != nil {
		return nil, site, err
	}
	var picture webimport.Picture
	if pictures {
		picture = func(src *url.URL, alt string) (string, error) {
			res, err := get(ctx, src.String())
			if err != nil {
				return "", err
			}
			f, err := keepFetched(root, &fetch.Result{URL: src.String(), FinalURL: res.FinalURL, Status: res.Status,
				ContentType: res.ContentType, Body: res.Body, Truncated: res.Truncated}, alt)
			if err != nil {
				return "", err
			}
			return "/media/" + f.ID, nil
		}
	}
	b, err := webimport.Package(site, name, caller.Name, picture, time.Now())
	if err != nil {
		return nil, site, err
	}
	if err := b.Package.Validate(featureChecks(root)); err != nil {
		return nil, site, fmt.Errorf("what was read does not make a package that installs: %w", err)
	}
	// This installation brought it, so its pages are marked for what they
	// are when it is installed: a site carried over by software.
	if err := rememberBuilt(root, b.Package, ""); err != nil {
		return nil, site, err
	}
	record(root, caller.auditRecord("site.imported", "/", audit.Success, map[string]string{
		"from": site.Home.Host, "pages": fmt.Sprint(len(b.Package.Pages)), "read": fmt.Sprint(len(site.Pages)),
		"redirects": fmt.Sprint(len(b.Redirects))}))
	return b, site, nil
}

// siteImportCmd is `quilzo site import https://…|FILE|FOLDER [--pages N] …`.
func siteImportCmd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("site import", flag.ContinueOnError)
	pages := fs.Int("pages", webimport.DefaultPages, fmt.Sprintf("how many pages to read, at most %d", webimport.MaxPages))
	name := fs.String("name", "", "what the site is called; what it calls itself by default")
	noPictures := fs.Bool("no-pictures", false, "leave pictures out rather than keep the ones the site describes")
	outPath := fs.String("o", "", "where to write the package; NAME.json by default")
	install := fs.Bool("install", false, "install it as well, as `quilzo feature install` does")
	takeSite := fs.Bool("take-site", false, "with --install: let it take over a site somebody set up by hand")
	where := fs.String("site", "", "for an export: the address the site was at, which a Ghost export needs for its pictures")
	fs.StringVar(&featureDesignDir, "templates", featureDesignDir, "the site's templates directory, for --install")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo site import https://your-old-site.example | EXPORT.xml | EXPORT.json | FOLDER | FOLDER.zip " +
			"[--pages N] [--name N] [--site https://…] [--no-pictures] [-o FILE] [--install]")
	}
	caller := resolveCaller(root, flagToken)
	if *install {
		if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
			return fmt.Errorf("--install installs a feature, which needs whoever may install them: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), siteImportTimeout)
	defer cancel()
	var (
		b    *webimport.Brought
		site *webimport.Site
		err  error
	)
	if !strings.HasPrefix(pos[0], "http://") && !strings.HasPrefix(pos[0], "https://") {
		// A file the old site exported, or a folder of its files.
		if _, serr := os.Stat(pos[0]); serr != nil {
			return fmt.Errorf("%s is not a file or folder here, nor an address beginning https://", pos[0])
		}
		src, done, oerr := openExport(pos[0])
		if oerr != nil {
			return oerr
		}
		defer done()
		w.Human("%sreading %s%s\n", dim, pos[0], reset)
		b, site, err = importExport(ctx, root, src, *name, *where, !*noPictures, caller)
	} else {
		w.Human("%sreading %s, politely: robots.txt first, then its map of itself or its links%s\n", dim, pos[0], reset)
		b, site, err = importSite(ctx, root, pos[0], *name, *pages, !*noPictures, caller)
	}
	if err != nil {
		return err
	}
	path := *outPath
	if path == "" {
		path = b.Package.Name + ".json"
	}
	body, err := json.MarshalIndent(b.Package, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := atomicfile.Write(path, body, 0o644); err != nil {
		return err
	}
	redirects := ""
	if len(b.Redirects) > 0 {
		redirects = strings.TrimSuffix(path, ".json") + ".redirects.json"
		if err := saveJSON(redirects, struct {
			Redirects []seo.Redirect `json:"redirects"`
		}{b.Redirects}); err != nil {
			return err
		}
	}
	if w.JSON(map[string]any{"file": path, "redirects": redirects, "read": len(site.Pages), "posts": len(b.Posts),
		"from": site.From, "notes": b.Notes, "card": b.Package.MakeCard()}) {
		return nil
	}
	switch site.From {
	case "sitemap", "links":
		w.Human("read %d page(s) of %s, from its %s\n\n", len(site.Pages), site.Home.Host,
			map[string]string{"sitemap": "map of itself", "links": "links"}[site.From])
	default:
		w.Human("read %d page(s) and %d post(s) from %s\n\n", len(site.Pages), len(b.Posts), site.Origin)
	}
	printFeatureCard(b.Package.MakeCard())
	for _, n := range b.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	if redirects != "" {
		w.Human("\nwrote %s with %d redirect(s), so the old addresses keep working: quilzo site --redirects %s\n",
			redirects, len(b.Redirects), redirects)
	}
	if !*install {
		w.Human("wrote %s; read it, then: quilzo feature install %s\n", path, path)
		return nil
	}
	return installFeatureFileWith(root, path, "", "", *takeSite, caller)
}
