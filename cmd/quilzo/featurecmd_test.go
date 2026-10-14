// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/schema"
)

// featureSite is a store with two administrators and a reader.
func featureSite(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	for _, g := range [][]string{{"grant", "dana", "admin"}, {"grant", "sam", "admin"}, {"grant", "rae", "reader"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// writePackage writes the example, changed by edit, and returns its path.
func writePackage(t *testing.T, edit func(*feature.Package)) string {
	t.Helper()
	p, err := feature.Decode(bytes.NewReader(feature.Example()))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(p)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), p.Name+"-"+p.Version+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func withoutAddress(p *feature.Package) {
	p.Types[0].Fields = p.Types[0].Fields[:3]
	p.Types[0].Fields = append(p.Types[0].Fields, schema.Field{Name: "received", Kind: schema.Date})
}

func owns(t *testing.T, root, name string) map[string]bool {
	t.Helper()
	in, err := loadInstalledFeatures(root)
	if err != nil {
		t.Fatal(err)
	}
	if in[name] == nil {
		return nil
	}
	out := map[string]bool{}
	for _, r := range in[name].Owns {
		out[r.String()] = true
	}
	return out
}

// A feature that stores email addresses waits for a second person; the
// one who asked cannot approve it, and a model cannot either.
func TestAFeatureHoldingPersonalDataNeedsASecondPerson(t *testing.T) {
	root := featureSite(t)
	if err := installFeatureFile(root, writePackage(t, nil), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if owns(t, root, "lab-samples") != nil {
		t.Fatal("installed on one person's say-so")
	}
	pend, err := pendingFeatures(root)
	if err != nil || len(pend) != 1 {
		t.Fatalf("pending %v %v", pend, err)
	}
	id := pend[0].ID
	if err := decideFeature(root, id, true, asAdmin("dana")); err == nil {
		t.Fatal("the person who asked approved their own install")
	}
	model := asAdmin("helper")
	model.Kind = audit.KindAI
	if err := decideFeature(root, id, true, model); err == nil {
		t.Fatal("a model approved an install")
	}
	reader := human("rae")
	reader.Role = "reader"
	if err := decideFeature(root, id, true, reader); err == nil {
		t.Fatal("a reader approved an install")
	}

	// The approvals inbox shows it to the other administrator only.
	items, _ := waitingFor(root, asAdmin("sam"), time.Now().UTC())
	found := false
	for _, it := range items {
		found = found || (it.Source == "feature" && strings.Contains(it.Decide, id))
	}
	if !found {
		t.Errorf("the waiting install is not in sam's approvals: %+v", items)
	}

	if err := decideFeature(root, id, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	got := owns(t, root, "lab-samples")
	for _, want := range []string{"type sample", "collection samples", "listing available_samples", "page samples"} {
		if !got[want] {
			t.Errorf("does not own %s: %v", want, got)
		}
	}
	types, _ := schema.Load(root)
	if _, ok := types.Registry.Get("sample"); !ok || types.Collections["samples"] != "sample" {
		t.Error("the type or the collection binding is missing")
	}
	pages, _ := draftPages(root)
	if _, ok := pages["samples"]; !ok {
		t.Error("the page is not in the draft")
	}
	if p, _ := pendingFeatures(root); len(p) != 0 {
		t.Error("the request is still waiting after it was approved")
	}
	in, _ := loadInstalledFeatures(root)
	if by := in["lab-samples"].By; len(by) != 2 || by[0] != "dana" || by[1] != "sam" {
		t.Errorf("approved by %v", by)
	}
}

// A feature that stores and shows nothing about people installs on one
// administrator's decision, and a reader cannot install anything.
func TestAPlainFeatureInstallsAtOnceForAnAdministrator(t *testing.T) {
	root := featureSite(t)
	path := writePackage(t, withoutAddress)
	reader := human("rae")
	reader.Role = "reader"
	if err := installFeatureFile(root, path, "", "", reader); err == nil {
		t.Fatal("a reader installed a feature")
	}
	if err := installFeatureFile(root, path, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if owns(t, root, "lab-samples")["type sample"] != true {
		t.Fatal("not installed")
	}
}

// A block somebody made by hand is theirs: a feature using its name is
// refused, and nothing of the feature is written.
func TestAFeatureNeverTakesABlockItDidNotMake(t *testing.T) {
	root := featureSite(t)
	mine := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Name, p.Title = "mine", "Mine"
		p.Collections, p.Listings, p.Pages, p.Roles = nil, nil, nil, nil
	})
	if err := installFeatureFile(root, mine, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), "the feature mine") {
		t.Fatalf("took another feature's type: %v", err)
	}
	if owns(t, root, "lab-samples") != nil {
		t.Error("part of the refused feature was installed")
	}
}

// An upgrade changes what changed and removes what the new version no
// longer declares; a rollback puts the earlier version back.
func TestAnUpgradeRemovesWhatItDroppedAndARollbackRestoresIt(t *testing.T) {
	root := featureSite(t)
	if err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	v2 := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Version = "1.1.0"
		p.Types[0].Description = "A sample, with its storage"
		p.Listings = nil
		p.Pages[0].Body["sections"] = []any{}
	})
	if err := installFeatureFile(root, v2, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if owns(t, root, "lab-samples")["listing available_samples"] {
		t.Error("the upgrade kept a listing it no longer declares")
	}
	listings, _ := loadListings(root)
	if _, ok := listings.Get("available_samples"); ok {
		t.Error("the dropped listing is still there")
	}
	if _, _, err := rollbackFeature(root, "lab-samples", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	listings, _ = loadListings(root)
	if _, ok := listings.Get("available_samples"); !ok {
		t.Error("the rollback did not restore the listing")
	}
	in, _ := loadInstalledFeatures(root)
	if v := in["lab-samples"].Version; v != "1.0.0" {
		t.Errorf("after the rollback the version is %s", v)
	}
}

// Removing a feature takes back everything it made and leaves the rest.
func TestRemovingAFeatureTakesBackOnlyWhatItMade(t *testing.T) {
	root := featureSite(t)
	if err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	before, _ := draftPages(root)
	if err := removeFeature(root, "lab-samples", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	types, _ := schema.Load(root)
	if _, ok := types.Registry.Get("sample"); ok {
		t.Error("the type is still there")
	}
	pages, _ := draftPages(root)
	if _, ok := pages["samples"]; ok {
		t.Error("the page is still in the draft")
	}
	if len(pages) != len(before)-1 {
		t.Errorf("removing the feature changed %d other pages", len(before)-1-len(pages))
	}
	if owns(t, root, "lab-samples") != nil {
		t.Error("still recorded as installed")
	}
}

// An exported package signed with the log's keys checks out with the
// published keys, and the slightest change to it does not.
func TestASignedExportChecksOutAndATamperedOneDoesNot(t *testing.T) {
	root := featureSite(t)
	if err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "signed.json")
	if err := featureExport(root, []string{"lab-samples", "-o", out, "--sign"}); err != nil {
		t.Fatal(err)
	}
	keys := headKeysPath(root)
	if _, _, err := readFeature(root, out, keys); err != nil {
		t.Fatalf("a good signature was refused: %v", err)
	}
	if _, _, err := readFeature(root, out, ""); err == nil {
		t.Error("a signed package was read without its signature being checked")
	}
	body, _ := os.ReadFile(out)
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	_ = os.WriteFile(tampered, bytes.Replace(body, []byte("Keep track"), []byte("Keep TRACK"), 1), 0o600)
	if _, _, err := readFeature(root, tampered, keys); err == nil {
		t.Error("a changed package passed its signature check")
	}
}

// Blocks made by hand can be captured into a package another installation
// can install.
func TestCaptureMakesAPackageFromExistingBlocks(t *testing.T) {
	root := featureSite(t)
	if err := installFeatureFile(root, writePackage(t, withoutAddress), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "captured.json")
	err := featureCapture(root, []string{"inventory", "--title", "Inventory", "--purpose", "What the lab holds",
		"--type", "sample", "--collection", "samples", "--listing", "available_samples", "--page", "samples", "-o", out})
	if err != nil {
		t.Fatal(err)
	}
	other := featureSite(t)
	if err := installFeatureFile(other, out, "", "", asAdmin("sam")); err != nil {
		t.Fatalf("the captured package does not install elsewhere: %v", err)
	}
	if !owns(t, other, "inventory")["page samples"] {
		t.Error("the captured page did not arrive")
	}
}

// A package agent that hands work to another is declared after it, an
// agent arrives answered for by the person who installed it, and agents
// that hand work to each other in a circle install nothing.
func TestAFeaturesAgentsArriveInTheOrderTheyDependOn(t *testing.T) {
	root := featureSite(t)
	boss := asker("boss")
	boss.Kind = agent.KindSupervisor
	boss.Delegates = []string{"helper"}
	path := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Agents = []agent.Manifest{boss, asker("helper")}
	})
	if err := installFeatureFile(root, path, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	if _, ok := set.Agents["boss"]; !ok {
		t.Fatal("the supervisor was not declared")
	}
	if id := set.identityOf("helper"); id == nil || id.Sponsor != "dana" {
		t.Errorf("the helper is answered for by %+v", id)
	}

	other := featureSite(t)
	a, b := asker("a"), asker("b")
	a.Kind, b.Kind = agent.KindSupervisor, agent.KindSupervisor
	a.Delegates, b.Delegates = []string{"b"}, []string{"a"}
	circle := writePackage(t, func(p *feature.Package) {
		withoutAddress(p)
		p.Agents = []agent.Manifest{a, b}
	})
	if err := installFeatureFile(other, circle, "", "", asAdmin("dana")); err == nil {
		t.Fatal("agents in a circle were installed")
	}
	if owns(t, other, "lab-samples") != nil {
		t.Error("part of the refused feature was installed")
	}
	types, _ := schema.Load(other)
	if _, ok := types.Registry.Get("sample"); ok {
		t.Error("the refused feature's type was written")
	}
}
