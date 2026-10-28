// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/gate"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
)

// blanksGate runs the publish gate that refuses a page with a blank in it.
func blanksGate(t *testing.T, root string) []gate.Finding {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range contentGates(root, s, "") {
		if c.Name == "blanks" {
			blocking, _, err := c.Run()
			if err != nil {
				t.Fatal(err)
			}
			return blocking
		}
	}
	t.Fatal("there is no blanks gate")
	return nil
}

func builtAndInstalled(t *testing.T, root string, b feature.SiteBrief, useModel bool) siteBuilt {
	t.Helper()
	built, err := buildSite(context.Background(), root, b, useModel, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), built.Package.Name+".json")
	if err := os.WriteFile(path, built.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, path, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	// A site has a contact form, so a second administrator approves it.
	pend, err := pendingFeatures(root)
	if err != nil || len(pend) != 1 {
		t.Fatalf("waiting: %v %v", pend, err)
	}
	if err := decideFeature(root, pend[0].ID, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	return built
}

func provenanceOf(t *testing.T, root, page string) provenance.Record {
	t.Helper()
	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	return idx.Records[page]
}

// A site built without a model installs as a whole site, its pages marked
// as a template's, and cannot be published until the blanks only its owner
// can fill are filled; filling them makes the pages the owner's, and leaves
// nothing for the provenance gate to refuse.
func TestASiteIsBuiltInstalledAndFilledIn(t *testing.T) {
	root, design := siteStore(t)
	built := builtAndInstalled(t, root, feature.SiteBrief{Description: "Our bakery in Leeds", Name: "Hart's Bakery"}, false)
	if built.Package.Name != "harts-bakery" || built.Model != "" || len(built.Fill) == 0 {
		t.Fatalf("built %s by %q with %d blanks", built.Package.Name, built.Model, len(built.Fill))
	}
	if n, _ := siteSettings(t, root); n != "Hart's Bakery" {
		t.Fatalf("the site is called %q", n)
	}
	if siteLook(t, design)["style"] != "soft" {
		t.Fatal("a bakery did not get the restaurant look")
	}
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"index", "menu", "visit", "about", "contact", "privacy"} {
		if pages[p] == nil {
			t.Fatalf("no %s page in the draft: %v", p, sortedNames(pages))
		}
		if r := provenanceOf(t, root, p); r.SourceType != provenance.AlgorithmicMedia || r.Author != "dana" {
			t.Fatalf("page %s is marked %+v", p, r)
		}
	}

	if got := blanksGate(t, root); len(got) == 0 {
		t.Fatal("a site with blanks in it would publish")
	}
	known, err := builderBlanks(root)
	if err != nil {
		t.Fatal(err)
	}
	whats, on := siteBlanks(pages, known)
	if len(whats) != len(built.Fill) || len(on["your address"]) != 2 {
		t.Fatalf("to fill: %v, on %v", whats, on)
	}

	// A value that would read as a blank, or a line break where none can
	// go, is refused before anything is written.
	if _, _, err := fillSite(root, map[string]string{"your address": "[[x]]"}, asAdmin("dana")); err == nil {
		t.Fatal("a value with a blank in it was written")
	}

	values := map[string]string{}
	for _, w := range whats {
		values[w] = "Filled: " + w
	}
	values["how to get there, and where to park"] = ""
	n, changed, err := fillSite(root, values, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if n < len(whats) || len(changed) == 0 {
		t.Fatalf("filled %d on %v", n, changed)
	}
	if got := blanksGate(t, root); len(got) != 0 {
		t.Fatalf("filled in, the gate still refuses: %v", got)
	}
	pages, _ = draftPages(root)
	visit, _ := json.Marshal(pages["visit"])
	if !strings.Contains(string(visit), "Filled: your address") || strings.Contains(string(visit), "where to park") {
		t.Fatalf("the visit page is %s", visit)
	}
	for _, p := range changed {
		if r := provenanceOf(t, root, p); r.SourceType != provenance.HumanEdits || r.Author != "dana" {
			t.Fatalf("filled, page %s is marked %+v", p, r)
		}
	}
	s, _ := open(root)
	unmarked, err := unmarkedAt(root, s, s.GetRef(site.RefDraft))
	if err != nil || len(unmarked) != 0 {
		t.Fatalf("pages the publish gate would call unmarked: %v %v", unmarked, err)
	}
}

// A site a model wrote says so on every page, and keeps saying so once a
// person has filled it in: both of them wrote it.
func TestASiteAModelWroteIsMarkedAsOne(t *testing.T) {
	root, _ := siteStore(t)
	m := withDraftModel(t, `{"name": "harts-bakery", "title": "Hart's Bakery", "purpose": "The bakery's website.",
		"site": {"name": "Hart's Bakery", "description": "Sourdough and rye, baked before dawn in Leeds.", "style": "soft", "colour": "#c2410c"},
		"pages": [{"name": "index", "body": {"title": "Hart's Bakery", "hero": {"lead": "Sourdough and rye, baked before dawn.", "cta_label": "Find us", "cta_href": "/contact"},
			"sections": [{"prose": {"title": "Open from", "paragraphs": ["We open at [[your opening time]]."]}}]}},
			{"name": "contact", "body": {"title": "Contact", "form": "contact"}}],
		"menus": [{"name": "main", "items": [{"id": "contact", "label": "Contact", "kind": "page", "target": "contact", "order": 1}]}]}`)
	built := builtAndInstalled(t, root, feature.SiteBrief{Description: "A bakery in Leeds that sells sourdough"}, true)
	if built.Model != "saying" || built.Package.Site.Name != "Hart's Bakery" || built.Package.Name != "harts-bakery" {
		t.Fatalf("built by %q: %+v", built.Model, built.Package.Site)
	}
	if !strings.Contains(m.system, "Never make up a fact") || !strings.Contains(m.prompt, "Starting site:") {
		t.Fatal("the model was not given the rules and the start")
	}
	if r := provenanceOf(t, root, "index"); r.SourceType != provenance.TrainedAlgorithmicMedia || r.Model != "saying" {
		t.Fatalf("the index page is marked %+v", r)
	}
	if _, _, err := fillSite(root, map[string]string{"your opening time": "four",
		"the name of the person or organisation that runs this site": "Hart's Bakery Ltd",
		"your data protection authority, such as the ICO in the UK":  "the ICO"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if r := provenanceOf(t, root, "index"); r.SourceType != provenance.CompositeWithTrainedAlgorithmicMedia || r.Author != "dana" {
		t.Fatalf("filled in, the index page is marked %+v", r)
	}
	if got := blanksGate(t, root); len(got) != 0 {
		t.Fatalf("filled in, the gate still refuses: %v", got)
	}
}

// Without a model and without a name, nothing can name the site, and the
// person is told why rather than given "Your site".
func TestASiteWithNoNameAndNoModelSaysWhy(t *testing.T) {
	root, _ := siteStore(t)
	draftModelSeam = func(string) (assist.Model, string) { return nil, "no model is configured" }
	t.Cleanup(func() { draftModelSeam = nil })
	_, err := buildSite(context.Background(), root, feature.SiteBrief{Description: "A bakery"}, true, asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), "no model is configured") {
		t.Fatalf("%v", err)
	}
}

// The only administrator installs a site alone, as they make any change
// two people would otherwise approve, and the record says so.
func TestTheOnlyAdministratorInstallsASiteAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"dana", "admin"})
	old := featureDesignDir
	featureDesignDir = filepath.Join(t.TempDir(), "templates")
	t.Cleanup(func() { featureDesignDir = old })

	built, err := buildSite(context.Background(), root, feature.SiteBrief{Description: "A plumber", Name: "Pipe & Co"}, false, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if c := built.Package.MakeCard(); c.Approvers != 2 {
		t.Fatalf("a site with a contact form needs %d approvers", c.Approvers)
	}
	path := filepath.Join(t.TempDir(), "site.json")
	if err := os.WriteFile(path, built.Body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, path, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if pend, _ := pendingFeatures(root); len(pend) != 0 {
		t.Fatal("the only administrator was left waiting for a second one")
	}
	if n, _ := siteSettings(t, root); n != "Pipe & Co" {
		t.Fatalf("the site is called %q", n)
	}
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	alone := false
	for _, e := range evs {
		alone = alone || (e.Action == "feature.approved" && e.Detail["alone"] == "true")
	}
	if !alone {
		t.Fatal("the record does not say it was approved alone")
	}
}

// Two square brackets a person wrote are theirs: a page about shell scripts
// publishes with [[ -f file ]] in it, and Fill in does not offer it.
func TestOnlyTheBuildersBlanksHoldAPageBack(t *testing.T) {
	root, _ := siteStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveDraft(root, s, map[string]any{"shell": map[string]any{"title": "Shell",
		"body": "Test for a file with [[ -f file ]] before reading it."}}, "a page", "dana", ""); err != nil {
		t.Fatal(err)
	}
	if got := blanksGate(t, root); len(got) != 0 {
		t.Fatalf("a page somebody wrote is held back: %v", got)
	}
	builtAndInstalled(t, root, feature.SiteBrief{Description: "A plumber", Name: "Pipe & Co"}, false)
	if got := blanksGate(t, root); len(got) == 0 {
		t.Fatal("the built site's blanks do not hold it back")
	}
	for _, f := range blanksGate(t, root) {
		if f.Page == "shell" {
			t.Fatalf("with a site installed, the shell page is held back: %v", f)
		}
	}
	if _, _, err := fillSite(root, map[string]string{"-f file": "x"}, asAdmin("dana")); err == nil {
		t.Fatal("a person's own brackets were filled in as a blank")
	}
}
