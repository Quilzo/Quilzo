package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/site"
)

func TestZZScratchSiteRemoval(t *testing.T) {
	root, design := siteStore(t)
	built := builtAndInstalled(t, root, feature.SiteBrief{Description: "Our bakery in Leeds", Name: "Hart's Bakery"}, false)
	pages, _ := draftPages(root)
	known, _ := builderBlanks(root)
	whats, _ := siteBlanks(pages, known)
	values := map[string]string{}
	for _, w := range whats {
		values[w] = "Filled: " + w
	}
	if _, _, err := fillSite(root, values, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "dana")
	t.Logf("publish: %v", cmdPublish(root, []string{"--templates", design}))
	s, _ := open(root)
	t.Logf("live %q draft %q", s.GetRef(site.RefLive), s.GetRef(site.RefDraft))
	err := removeFeature(root, built.Package.Name, asAdmin("dana"))
	t.Logf("remove: %v", err)
	t.Logf("section remove: %v", cmdSection(root, []string{"remove", "contact", "0"}))
	t.Logf("publish: %v", cmdPublish(root, []string{"--templates", design}))
	t.Logf("remove: %v", removeFeature(root, built.Package.Name, asAdmin("dana")))
	t.Logf("publish: %v", cmdPublish(root, []string{"--templates", design}))
}
