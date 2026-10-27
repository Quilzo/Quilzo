// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/icons"
	"github.com/quilzo/quilzo/internal/section"
)

var buildTime = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

func pageBodies(p *Package) map[string]any {
	out := map[string]any{}
	for _, pg := range p.Pages {
		out[pg.Name] = pg.Body
	}
	return out
}

// Every kind of site builds into a package that installs: every section a
// kind this program renders in its shipped shape, every icon one it draws,
// every menu entry and link a page of the site, the forms on their pages
// and on the privacy page, and a question box that sends nothing anywhere.
func TestEveryKindOfSiteBuildsIntoAPackageThatInstalls(t *testing.T) {
	for _, k := range SiteKinds() {
		t.Run(k.Name, func(t *testing.T) {
			p, err := BuildSite(SiteBrief{Description: "Something for " + k.Name, Name: "Hart & Daughters", Kind: k.Name}, "dana", buildTime)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(Checks{}); err != nil {
				t.Fatal(err)
			}
			if p.Name != "hart-daughters" || p.Site.Name != "Hart & Daughters" || p.Site.Style != k.Style || p.Made.By != "dana" {
				t.Fatalf("the package is %s, the site %+v", p.Name, p.Site)
			}
			pages := pageBodies(p)
			for _, must := range []string{"index", "about", "contact", "privacy"} {
				if pages[must] == nil {
					t.Errorf("no %s page", must)
				}
			}
			for name, body := range pages {
				bad, advice := section.Validate(body)
				if len(bad)+len(advice) > 0 {
					t.Errorf("page %s: %v %v", name, bad, advice)
				}
				links(body, func(_, href string) string {
					target := strings.Trim(href, "/")
					if target == "" {
						target = "index"
					}
					if pages[target] == nil {
						t.Errorf("page %s links to %s, which is not a page", name, href)
					}
					return href
				})
				for _, s := range section.On(body) {
					inner, _ := body.(map[string]any)["sections"].([]any)[s.Index].(map[string]any)[s.Kind].(map[string]any)
					items, _ := inner["items"].([]any)
					for _, it := range items {
						if icon, ok := it.(map[string]any)["icon"].(string); ok && !icons.Has(icon) {
							t.Errorf("page %s: no icon called %s", name, icon)
						}
					}
				}
				if f, ok := body.(map[string]any)["form"].(string); ok {
					found := false
					for _, fm := range p.Forms {
						found = found || fm.Name == f
					}
					if !found {
						t.Errorf("page %s shows the form %s, which is not declared", name, f)
					}
				}
			}
			for _, m := range p.Menus {
				if err := m.Validate(pages); err != nil {
					t.Errorf("menu %s: %v", m.Name, err)
				}
			}
			privacy, _ := json.Marshal(pages["privacy"])
			for _, f := range p.Forms {
				if !strings.Contains(string(privacy), "The "+f.Label+" form") {
					t.Errorf("the privacy page does not mention the %s form: %s", f.Name, privacy)
				}
			}
			if len(p.Chatbots) != 1 || p.Chatbots[0].UseModel || !p.Chatbots[0].Public || p.Chatbots[0].Handoff {
				t.Errorf("the question box is %+v", p.Chatbots)
			}
			// One blank is one fact: the same words in two entries of one
			// list would be filled with one answer, and mean two things.
			for name, body := range pages {
				for _, sc := range section.On(body) {
					inner, _ := body.(map[string]any)["sections"].([]any)[sc.Index].(map[string]any)[sc.Kind].(map[string]any)
					for key, list := range inner {
						entries, _ := list.([]any)
						seen := map[string]int{}
						for i, e := range entries {
							for _, b := range section.Unfilled(e) {
								if j, ok := seen[b.What]; ok && j != i {
									t.Errorf("page %s: %s %s entries %d and %d share the blank %q", name, sc.Kind, key, j, i, b.What)
								}
								seen[b.What] = i
							}
						}
					}
				}
			}
			if len(p.BlankWhats()) == 0 {
				t.Error("a site built without a model has nothing to fill in, so it made something up")
			}
			c := p.MakeCard()
			if !strings.Contains(c.Shows[0].Text, `Names the site "Hart & Daughters"`) {
				t.Errorf("the card opens with %q", c.Shows[0].Text)
			}
		})
	}
}

func TestTheKindOfSiteIsReadFromTheDescription(t *testing.T) {
	for desc, want := range map[string]string{
		"A website for our bakery and café in Leeds":            "restaurant",
		"A portfolio for my wedding photography":                "portfolio",
		"The village choir: who we are and how to join":         "community",
		"Our two-day conference on soil science, with tickets":  "event",
		"An app that reminds people to water their plants":      "product",
		"Something nobody has a word for":                       "business",
		"Plumbers covering North Yorkshire, emergency call-out": "business",
	} {
		if got := GuessSiteKind(desc).Name; got != want {
			t.Errorf("%q is a %s site, not %s", desc, got, want)
		}
	}
	if _, err := BuildSite(SiteBrief{Description: "A bakery"}, "dana", buildTime); err == nil {
		t.Error("a site with no name and no model to suggest one was built")
	}
	if _, err := BuildSite(SiteBrief{Description: "x", Name: "X", Kind: "casino"}, "dana", buildTime); err == nil {
		t.Error("a kind of site there is not was built")
	}
	p, err := BuildSite(SiteBrief{Description: "A bakery", Name: "Hart's", Colour: "#15803d", Style: "bold"}, "dana", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	if p.Site.Colour != "#15803d" || p.Site.Style != "bold" {
		t.Errorf("the person's choice of look was not kept: %+v", p.Site)
	}
}

// What a model answers is put right against the site it was given: what the
// person chose wins, what every site has comes back, and links, sections,
// forms and settings that could not work, or would send a visitor's words
// somewhere, are taken out. The privacy page is the builder's, not the
// model's.
func TestADraftedSiteIsPutRight(t *testing.T) {
	brief := SiteBrief{Description: "A bakery in Leeds", Name: "Hart's Bakery", Colour: "#c2410c"}
	start, err := BuildSite(brief, "dana", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	answer := "```json\n" + `{
		"format": 1, "name": "harts", "version": "9", "title": "Hart's Bakery", "purpose": "The bakery's site.",
		"site": {"name": "Something Else", "description": "Bread baked before dawn in Leeds.", "style": "brutalist",
			"colour": "#00ff00", "starter": "landing", "tokens": {"surface": "#000000"}},
		"agents": [{"name": "x"}],
		"forms": [{"name": "order", "label": "Order", "fields": [{"name": "what", "label": "What", "kind": "line"}]},
			{"name": "contact", "label": "Write to us", "notice": "We reply.", "fields": [{"name": "message", "label": "Message", "kind": "para", "required": true}]}],
		"chatbots": [{"name": "help", "title": "Ask the bakery", "use_model": true, "handoff": true, "embed": ["https://evil.example"], "public": true}],
		"pages": [
			{"name": "index", "body": {"title": "Hart's Bakery", "members_only": true,
				"hero": {"lead": "Sourdough every morning.", "cta_label": "Order", "cta_href": "https://evil.example/pay", "secondary_label": "Menu", "secondary_href": "/menu"},
				"sections": [{"gallry": {}}, {"listing": {"name": "breads"}}, {"ask": {"title": "Ask", "assistant": "other"}},
					{"prose": {"title": "Our bread", "paragraphs": ["Baked at [[the time you start baking]]."]}}]}},
			{"name": "menu", "body": {"title": "Menu", "form": "nope"}},
			{"name": "Bad Name", "body": {"title": "x"}},
			{"name": "privacy", "body": {"title": "Privacy", "sections": [{"prose": {"paragraphs": ["We collect nothing."]}}]}}
		],
		"menus": [{"name": "main", "items": [{"id": "m", "label": "Menu", "kind": "page", "target": "menu", "order": 1},
			{"id": "x", "label": "Elsewhere", "kind": "external", "target": "https://evil.example"},
			{"id": "y", "label": "Gone", "kind": "page", "target": "gone"}]}]
	}` + "\n```"
	p, notes, err := ReadSiteDraft(answer, brief, start, "dana", "test-model", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(Checks{}); err != nil {
		t.Fatalf("%v\nnotes: %v", err, notes)
	}
	s := p.Site
	if s.Name != "Hart's Bakery" || s.Colour != "#c2410c" || s.Style != start.Site.Style || s.Starter != "sections" ||
		s.Tokens != nil || s.Description != "Bread baked before dawn in Leeds." {
		t.Errorf("the site is %+v", s)
	}
	if p.Version != "1.0.0" || len(p.Agents) != 0 || p.Made.Model != "test-model" {
		t.Errorf("the package is %s with %d agents, made %+v", p.Version, len(p.Agents), p.Made)
	}
	pages := pageBodies(p)
	if pages["contact"] == nil || pages["Bad Name"] != nil {
		t.Errorf("pages: %v", p.Pages)
	}
	index := pages["index"].(map[string]any)
	if _, ok := index["members_only"]; ok {
		t.Error("a built page kept members_only")
	}
	if h := index["hero"].(map[string]any); h["cta_href"] != "" || h["secondary_href"] != "/menu" {
		t.Errorf("the hero's links are %v", h)
	}
	secs := index["sections"].([]any)
	if len(secs) != 2 || secs[0].(map[string]any)["ask"].(map[string]any)["assistant"] != "help" {
		t.Errorf("the index sections are %v", secs)
	}
	if _, ok := pages["menu"].(map[string]any)["form"]; ok {
		t.Error("a page kept a form the site does not have")
	}
	privacy, _ := json.Marshal(pages["privacy"])
	if strings.Contains(string(privacy), "We collect nothing") || !strings.Contains(string(privacy), "The Write to us form") {
		t.Errorf("the privacy page is the model's: %s", privacy)
	}
	bot := p.Chatbots[0]
	if bot.UseModel || bot.Handoff || len(bot.Embed) != 0 || bot.Title != "Ask the bakery" {
		t.Errorf("the question box is %+v", bot)
	}
	for _, f := range p.Forms {
		if f.Name == "order" {
			t.Error("a form that does not pass its checks was kept")
		}
	}
	var main []string
	for _, m := range p.Menus {
		if m.Name == "main" {
			for _, it := range m.Items {
				main = append(main, it.Target)
			}
		}
	}
	if strings.Join(main, ",") != "menu" {
		t.Errorf("the main menu is %v", main)
	}
	if got := p.BlankWhats(); len(got) != 3 || got[0] != "the time you start baking" ||
		got[1] != "the name of the person or organisation that runs this site" {
		t.Errorf("to fill in: %q", got)
	}
	joined := strings.Join(notes, "\n")
	for _, want := range []string{`"agents"`, "form order", "Bad Name", "gallry", "listing section", "https://evil.example/pay", "members_only", `"Elsewhere"`, `"Gone"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("no note mentions %s:\n%s", want, joined)
		}
	}

	// An answer with no site at all still makes one, from the start.
	p, _, err = ReadSiteDraft(`{"name": "x", "title": "x", "purpose": "x"}`, brief, start, "dana", "m", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(Checks{}); err != nil || pageBodies(p)["index"] == nil || p.Site.Name != "Hart's Bakery" {
		t.Fatalf("from nothing: %v, %+v", err, p.Site)
	}
}

func TestTheSitePromptListsEverySectionKind(t *testing.T) {
	prompt := SitePrompt(section.Kinds())
	for _, k := range section.Kinds() {
		if !strings.Contains(prompt, "- "+k.Name+": ") {
			t.Errorf("the prompt does not show %s", k.Name)
		}
	}
	if !strings.Contains(prompt, "[[what goes here]]") || !strings.Contains(prompt, "soft") {
		t.Error("the prompt does not say how to leave a fact out, or which styles there are")
	}
}
