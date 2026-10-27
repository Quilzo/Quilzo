// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/render"
)

// The site block of a package that is a whole site: its name, its
// description, its layouts and its look (internal/feature/site.go).
//
// The name and the description are settings, and the look and the layouts
// live in the templates directory, as `quilzo site` and `quilzo serve` read
// them. A site somebody set up by hand belongs to them: a package takes it
// over only when told to, and what it was is kept, so removing the package
// puts it back. The layouts a package writes stay when it goes, because a
// site with no layouts renders nothing.

// featureDesignDir is the templates directory a site package writes its
// look and layouts into. Commands set it from --templates and the admin
// from its own, so both write where the site reads.
var featureDesignDir = "templates"

// designFlag reads --templates from a command's arguments into
// featureDesignDir, for the commands that may apply or release a site
// package, and returns the rest.
func designFlag(name string, args []string) ([]string, error) {
	pos, rest := leadingArgs(args, 1)
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&featureDesignDir, "templates", featureDesignDir, "the site's templates directory, for a site package")
	if err := fs.Parse(rest); err != nil {
		return nil, err
	}
	return append(pos, fs.Args()...), nil
}

// sitePrior is the site as it was before a package took it over.
type sitePrior struct {
	Name           string `json:"name,omitempty"`
	Description    string `json:"description,omitempty"`
	ThemeExisted   bool   `json:"theme_existed,omitempty"`
	Theme          []byte `json:"theme,omitempty"`
	LayoutsWritten bool   `json:"layouts_written,omitempty"`
}

func sitePriorPath(root string) string { return filepath.Join(featuresDir(root), "site-prior.json") }

// siteByHand is whether somebody set the site's name or look themselves:
// a name in the settings, or a theme file in the templates directory.
func siteByHand(root string) bool {
	cfg, err := loadConfig(root)
	if err == nil && cfg.Raw("site.name") != "" {
		return true
	}
	return fileExists(filepath.Join(featureDesignDir, themeFile))
}

// siteState puts the site block into a feature state: the site its owning
// package declared, or a marker for a site made by hand, which a site
// package conflicts with unless it is to take it over.
func siteState(root string, st feature.State, installed map[string]*feature.Installed, takeSite bool) error {
	for name, in := range installed {
		for _, r := range in.Owns {
			if r != feature.SiteRef {
				continue
			}
			p, _, err := loadFeaturePackage(root, name, in.Digest)
			if err != nil {
				return fmt.Errorf("the site that %s declared cannot be read: %w", name, err)
			}
			if p.Site != nil {
				b, err := json.Marshal(p.Site)
				if err != nil {
					return err
				}
				st.Current[feature.SiteRef] = b
			}
			return nil
		}
	}
	if !takeSite && siteByHand(root) {
		st.Current[feature.SiteRef] = json.RawMessage(`{"by":"a person"}`)
	}
	return nil
}

// applySite writes a package's site block: layouts when the site has none,
// the look, the name and the description. The site as it was is kept the
// first time a package takes it over.
func applySite(root string, pkg *feature.Package, action string, caller *Caller) error {
	s := pkg.Site
	look, err := s.Look()
	if err != nil {
		return err
	}
	if action == feature.Add {
		if err := keepSitePrior(root); err != nil {
			return err
		}
	}
	if !fileExists(filepath.Join(featureDesignDir, render.DefaultLayout+".html")) {
		name := s.Starter
		if name == "" {
			name = "sections"
		}
		if _, err := installStarter(featureDesignDir, name); err != nil {
			return fmt.Errorf("the site's layouts: %w", err)
		}
		// The starter's own tokens first, so a site that names no colour
		// keeps the starter's palette; the package's look goes over them.
		if base, err := loadThemeFile(featureDesignDir); err == nil && base != nil {
			for k, v := range look {
				base[k] = v
			}
			look = base
		}
		var prior sitePrior
		if loadJSON(sitePriorPath(root), &prior) == nil && !prior.LayoutsWritten {
			prior.LayoutsWritten = true
			if err := saveJSON(sitePriorPath(root), prior); err != nil {
				return err
			}
		}
	}
	if err := writeThemeFile(featureDesignDir, look); err != nil {
		return err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	why := "the site, as the feature " + pkg.Name + " " + pkg.Version + " declares it"
	if err := cfg.Set("site.name", s.Name, why, caller.Name); err != nil {
		return err
	}
	if s.Description != "" {
		err = cfg.Set("site.description", s.Description, why, caller.Name)
	} else {
		err = cfg.Unset("site.description")
	}
	if err != nil {
		return err
	}
	if err := saveConfig(root, cfg); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("site.declared", "/", audit.Success, map[string]string{
		"feature": pkg.Name, "version": pkg.Version, "style": s.Style, "colour": s.Colour}))
}

// keepSitePrior records the site as it is, once: the record stays until
// the package that took the site over lets it go.
func keepSitePrior(root string) error {
	if fileExists(sitePriorPath(root)) {
		return nil
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	prior := sitePrior{Name: cfg.Raw("site.name"), Description: cfg.Raw("site.description")}
	if b, err := os.ReadFile(filepath.Join(featureDesignDir, themeFile)); err == nil {
		prior.ThemeExisted, prior.Theme = true, b
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(featuresDir(root), 0o700); err != nil {
		return err
	}
	return saveJSON(sitePriorPath(root), prior)
}

// releaseSite puts the site back as it was before a package took it over.
// The layouts stay: a site with none renders nothing.
func releaseSite(root string, pkg string, caller *Caller) error {
	var prior sitePrior
	if err := loadJSON(sitePriorPath(root), &prior); err != nil {
		return fmt.Errorf("what the site was before %s took it over cannot be read: %w", pkg, err)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	for key, was := range map[string]string{"site.name": prior.Name, "site.description": prior.Description} {
		if was == "" {
			err = cfg.Unset(key)
		} else {
			err = cfg.Set(key, was, "as it was before the feature "+pkg, caller.Name)
		}
		if err != nil {
			return err
		}
	}
	if err := saveConfig(root, cfg); err != nil {
		return err
	}
	themePath := filepath.Join(featureDesignDir, themeFile)
	if prior.ThemeExisted {
		if err := os.WriteFile(themePath, prior.Theme, 0o600); err != nil {
			return err
		}
	} else if err := os.Remove(themePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(sitePriorPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return recordE(root, caller.auditRecord("site.released", "/", audit.Success, map[string]string{"feature": pkg}))
}
