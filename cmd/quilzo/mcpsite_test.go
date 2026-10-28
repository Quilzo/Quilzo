// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/webimport"
)

// siteCrew is an agent at the machine interface, acting for dana.
func siteCrew(t *testing.T, root string) func(tool, op string, args map[string]any) map[string]any {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("dana"), "templates")
	return func(tool, op string, args map[string]any) map[string]any {
		t.Helper()
		params, _ := json.Marshal(map[string]any{"name": tool, "arguments": map[string]any{"operation": op, "arguments": args}})
		resp := srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params})
		b, _ := json.Marshal(resp)
		var out map[string]any
		if resp.Error != nil {
			return map[string]any{"error": resp.Error.Message}
		}
		var res struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		}
		rb, _ := json.Marshal(resp.Result)
		if err := json.Unmarshal(rb, &res); err != nil || len(res.Content) == 0 {
			t.Fatalf("%s answered %s", op, b)
		}
		if res.IsError || json.Unmarshal([]byte(res.Content[0].Text), &out) != nil {
			return map[string]any{"error": res.Content[0].Text}
		}
		return out
	}
}

// An agent builds a whole site. It waits as a proposal, installed by
// nobody; the person it acted for installs it as their own decision, and
// it leaves the list. The agent then fills in what the person told it, and
// those pages say an agent wrote them.
func TestAnAgentBuildsASiteAndAPersonInstallsIt(t *testing.T) {
	root, _ := siteStore(t)
	call := siteCrew(t, root)

	got := call("quilzo_write", "site_build", map[string]any{
		"description": "A plumber in Leeds: boilers, leaks and bathrooms", "name": "Leeds Plumbing"})
	id, _ := got["proposal"].(string)
	if id == "" || got["error"] != nil {
		t.Fatalf("the agent's build: %v", got)
	}
	if fill, _ := got["to_fill"].([]any); len(fill) == 0 {
		t.Fatalf("a site built from a sentence has nothing to fill in: %v", got)
	}
	if n, _ := siteSettings(t, root); n == "Leeds Plumbing" {
		t.Fatal("an agent's site was installed")
	}
	list, err := proposals(root)
	if err != nil || len(list) != 1 || list[0].ID != id || list[0].For != "dana" || list[0].By != "mcp-client" {
		t.Fatalf("waiting: %+v, %v", list, err)
	}
	// Built again, the newer one replaces it rather than waiting beside it.
	again := call("quilzo_write", "site_build", map[string]any{
		"description": "A plumber in Leeds: boilers, leaks and bathrooms", "name": "Leeds Plumbing"})
	if list, _ := proposals(root); len(list) != 1 || list[0].ID != again["proposal"] {
		t.Fatalf("built twice, waiting: %+v", list)
	}
	id = again["proposal"].(string)

	// The agent cannot install it, however it asks.
	agent := asAdmin("dana")
	agent.Kind, agent.Model = audit.KindAI, "mcp-client"
	if err := installFeatureFile(root, proposalPath(root, id), "", "", agent); err == nil {
		t.Fatal("an agent installed what it proposed")
	}
	if err := dismissProposal(root, id, agent); err == nil {
		t.Fatal("an agent set a proposal aside")
	}

	// A person reads it and installs it: two approve a contact form.
	if err := installFeatureFile(root, proposalPath(root, id), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	approveWaiting(t, root, "sam")
	if n, _ := siteSettings(t, root); n != "Leeds Plumbing" {
		t.Fatalf("installed, the site is called %q", n)
	}
	if list, _ := proposals(root); len(list) != 0 {
		t.Fatalf("an installed proposal is still waiting: %+v", list)
	}
	if r := provenanceOf(t, root, "index"); r.SourceType != provenance.AlgorithmicMedia {
		t.Fatalf("the builder's page is marked %+v", r)
	}

	blanks := call("quilzo_read", "site_blanks", nil)
	whats, _ := blanks["blanks"].([]any)
	if len(whats) == 0 {
		t.Fatalf("no blanks: %v", blanks)
	}
	what := whats[0].(string)
	filled := call("quilzo_write", "site_fill", map[string]any{"values": map[string]any{what: "Something the person said"}})
	pages, _ := filled["pages"].([]any)
	if filled["error"] != nil || len(pages) == 0 {
		t.Fatalf("the agent's fill: %v", filled)
	}
	r := provenanceOf(t, root, pages[0].(string))
	if r.SourceType != provenance.CompositeWithTrainedAlgorithmicMedia || r.Model != "mcp-client" {
		t.Fatalf("a page an agent filled in is marked %+v", r)
	}
}

// A fill touches each page by its own path, so a deny on a page holds
// against filling it as it does against editing it.
func TestAFillRespectsADenyOnThePage(t *testing.T) {
	root, _ := siteStore(t)
	builtAndInstalled(t, root, feature.SiteBrief{Description: "A plumber in Leeds", Name: "Leeds Plumbing"}, false)
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	known, _ := builderBlanks(root)
	whats, on := siteBlanks(pages, known)
	if len(whats) == 0 {
		t.Fatal("nothing to fill")
	}
	page := on[whats[0]][0]
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if err := p.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
			return err
		}
		return p.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/" + page, Deny: true})
	}); err != nil {
		t.Fatal(err)
	}
	rae := human("rae")
	rae.Role = auth.RoleAuthor
	if _, _, err := fillSite(root, map[string]string{whats[0]: "x"}, rae); err == nil || !strings.Contains(err.Error(), "not yours") {
		t.Fatalf("rae filled a page denied to her: %v", err)
	}
}

// An agent brings a site in by its address, and it waits like any other
// proposal, with what was left behind.
func TestAnAgentBringsASiteInAsAProposal(t *testing.T) {
	root, _ := siteStore(t)
	siteImportGetSeam = func(_ context.Context, raw string) (*webimport.Fetched, error) {
		if u, _ := url.Parse(raw); u.Path == "/" {
			return &webimport.Fetched{FinalURL: raw, Status: 200, ContentType: "text/html",
				Body: []byte(`<html><head><title>Hart's</title></head><body><main><h1>Hart's</h1><p>Bread.</p>` +
					`<img src="/loaf.png" alt="A loaf"><form><input name="q"></form></main></body></html>`)}, nil
		}
		if u, _ := url.Parse(raw); u.Path == "/loaf.png" {
			return &webimport.Fetched{FinalURL: raw, Status: 200, ContentType: "image/png", Body: tinyPNG(t)}, nil
		}
		return nil, errors.New("404")
	}
	t.Cleanup(func() { siteImportGetSeam = nil })
	got := siteCrew(t, root)("quilzo_write", "site_import", map[string]any{"address": "https://hartsbakery.example/"})
	notes, _ := got["notes"].([]any)
	if got["proposal"] == nil || len(notes) == 0 || got["read"] != float64(1) {
		t.Fatalf("the agent's import: %v", got)
	}
	// Nothing it brought is kept before a person decides: no pictures in
	// the library, and the notes say how a person keeps them.
	if lib, err := openMedia(root); err != nil {
		t.Fatal(err)
	} else if files, _ := lib.List(); len(files) != 0 {
		t.Fatalf("an agent's import kept %d file(s) in the media library", len(files))
	}
	if !strings.Contains(strings.Join(func() []string {
		var out []string
		for _, n := range notes {
			out = append(out, n.(string))
		}
		return out
	}(), "\n"), "Bring your site") {
		t.Fatalf("the notes do not say how to keep the pictures: %v", notes)
	}
	list, _ := proposals(root)
	if len(list) != 1 || !strings.Contains(list[0].What, "hartsbakery.example") {
		t.Fatalf("waiting: %+v", list)
	}
}

// A package an agent wrote is a model's: installed, its pages say so.
func TestAPackageAnAgentWroteIsMarkedAsAModels(t *testing.T) {
	root, _ := siteStore(t)
	var pkg map[string]any
	if err := json.Unmarshal(feature.Example(), &pkg); err != nil {
		t.Fatal(err)
	}
	pages, _ := pkg["pages"].([]any)
	pkg["pages"] = append(pages, map[string]any{"name": "opening", "body": map[string]any{"title": "Opening hours"}})
	got := siteCrew(t, root)("quilzo_write", "propose_feature", map[string]any{"package": pkg})
	id, _ := got["proposal"].(string)
	if id == "" {
		t.Fatalf("the agent's package: %v", got)
	}
	if err := installFeatureFile(root, proposalPath(root, id), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	approveWaiting(t, root, "sam")
	if r := provenanceOf(t, root, "opening"); r.SourceType != provenance.TrainedAlgorithmicMedia {
		t.Fatalf("an agent's page is marked %+v", r)
	}

	// Something that would not install is refused, not kept.
	if bad := siteCrew(t, root)("quilzo_write", "propose_feature", map[string]any{"package": map[string]any{"name": "x"}}); bad["error"] == nil {
		t.Fatalf("an unusable package was proposed: %v", bad)
	}
}

// What agents can leave waiting is bounded, and a person sets one aside.
func TestProposalsAreBoundedAndSetAsideByAPerson(t *testing.T) {
	root, _ := siteStore(t)
	for i := 0; i < maxProposals; i++ {
		path := sitePackage(t, "site"+string(rune('a'+i)), "1.0", "#c2410c")
		body, _ := os.ReadFile(path)
		if _, _, err := proposeFeature(root, body, "a test", nil, asAdmin("dana")); err != nil {
			t.Fatalf("proposal %d: %v", i, err)
		}
	}
	body, _ := os.ReadFile(sitePackage(t, "onemore", "1.0", "#c2410c"))
	if _, _, err := proposeFeature(root, body, "a test", nil, asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "already waiting") {
		t.Fatalf("past the bound: %v", err)
	}
	list, _ := proposals(root)
	if err := dismissProposal(root, list[0].ID, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	if after, _ := proposals(root); len(after) != maxProposals-1 {
		t.Fatalf("set aside, %d wait", len(after))
	}
	if _, _, err := proposalBody(root, "../../etc"); err == nil {
		t.Fatal("a path was read as a proposal")
	}
}

// approveWaiting approves every install waiting for a second person.
func approveWaiting(t *testing.T, root, by string) {
	t.Helper()
	pend, err := pendingFeatures(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pend {
		if err := decideFeature(root, p.ID, true, asAdmin(by)); err != nil {
			t.Fatal(err)
		}
	}
}
