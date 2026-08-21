package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
)

// cfgWith builds a config carrying just these settings.
func cfgWith(t *testing.T, kv ...string) *config.Config {
	t.Helper()
	c := config.New()
	for i := 0; i+1 < len(kv); i += 2 {
		if err := c.Set(kv[i], kv[i+1], "test", "test"); err != nil {
			t.Fatalf("cannot set %s: %v", kv[i], err)
		}
	}
	return c
}

// The bug this exists for.
//
// internal/public had a complete, tested RSL and TDMRep implementation, and
// nothing ever set Site.Licence — so /license.xml and /.well-known/tdmrep.json
// returned 404 on every deployment there has ever been, while the README said
// the feature shipped. Code reachable from its tests and from nowhere else.
//
// Both halves had passing tests. The document builder was tested against what
// it writes, and nothing was tested against whether anything called it.
func TestConfiguredTermsProduceALicence(t *testing.T) {
	cfg := cfgWith(t,
		"licence.permits", "search",
		"licence.prohibits", "train,ai-summarize",
		"licence.contact", "rights@example.test")

	lic, err := licenceFrom(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if lic == nil {
		t.Fatal("terms are configured and no licence was built, so " +
			"/license.xml would 404")
	}
	if len(lic.Permits) != 1 || lic.Permits[0] != "search" {
		t.Errorf("permits is %v, want [search]", lic.Permits)
	}
	// Separate grants, which is the whole point: from 15 September 2026
	// Cloudflare stops treating search indexing and AI training as one
	// permission, and a site with one undivided answer is answering a question
	// that has become two.
	if len(lic.Prohibits) != 2 {
		t.Errorf("prohibits is %v, want train and ai-summarize separately",
			lic.Prohibits)
	}
}

// No terms means no document, not an empty one. An RSL file with no grants
// does not read as "no terms" — it reads as terms permitting nothing, and a
// crawler honouring it would stop indexing a site whose operator never made
// that decision.
func TestNoTermsPublishesNothingRatherThanAnEmptyLicence(t *testing.T) {
	lic, err := licenceFrom(cfgWith(t))
	if err != nil {
		t.Fatal(err)
	}
	if lic != nil {
		t.Errorf("an unconfigured site produced a licence: %+v", lic)
	}
}

// A use in both lists is a contradiction, and a reader resolving it either way
// is guessing. Refused at startup where somebody is watching, rather than
// served to a crawler that acts on whichever half it read first.
func TestContradictoryTermsAreRefused(t *testing.T) {
	_, err := licenceFrom(cfgWith(t,
		"licence.permits", "search,train",
		"licence.prohibits", "train"))
	if err == nil {
		t.Fatal("published terms that permit and prohibit the same use")
	}
	if !strings.Contains(err.Error(), "train") {
		t.Errorf("the error does not name the contradicting term: %v", err)
	}
}

// A closed vocabulary, because the value is published to third parties who act
// on it. In an open list a typo becomes a grant nobody notices: "trian" in the
// prohibits list is a site that believes it refused training and did not.
func TestATypoInTheVocabularyIsRefused(t *testing.T) {
	_, err := licenceFrom(cfgWith(t, "licence.prohibits", "trian"))
	if err == nil {
		t.Fatal("accepted \"trian\" as an automated use, so a site could " +
			"believe it refused training while permitting it")
	}
	if !strings.Contains(err.Error(), "trian") {
		t.Errorf("the error does not quote the bad term: %v", err)
	}
	// And it has to say what the acceptable values are, or the operator's next
	// move is to guess again.
	for _, want := range []string{"search", "train", "ai-summarize"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not offer %q as a valid use: %v", want, err)
		}
	}
}

// Attribution and a contact describe terms. With no terms to attach them to
// the licence is half-configured, and publishing it asserts something the
// operator did not finish choosing.
func TestAHalfConfiguredLicenceIsRefused(t *testing.T) {
	for _, k := range []string{
		"licence.attribution", "licence.contact", "licence.standard",
	} {
		if _, err := licenceFrom(cfgWith(t, k, "something")); err == nil {
			t.Errorf("%s alone produced no error; a licence nobody finished "+
				"choosing would be published", k)
		}
	}
}

// Whitespace and trailing separators are what people actually type.
func TestTermsAreParsedTheWayPeopleWriteThem(t *testing.T) {
	lic, err := licenceFrom(cfgWith(t, "licence.permits", " search , train ,"))
	if err != nil {
		t.Fatal(err)
	}
	if lic == nil {
		t.Fatal("no licence was built")
	}
	if len(lic.Permits) != 2 ||
		lic.Permits[0] != "search" || lic.Permits[1] != "train" {
		t.Errorf("parsed %v, want [search train]", lic.Permits)
	}
}
