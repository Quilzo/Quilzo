package provenance

import (
	"encoding/json"
	"strings"
	"testing"
)

// The failure that matters here is not a missing mark. It is a missing mark that
// reads as human authorship — content the law says must be labelled, presented
// as if a person wrote it. So most of these check that absence stays visible.

func TestAIContentRequiresAMarkAndHumanContentDoesNot(t *testing.T) {
	cases := []struct {
		st   SourceType
		mark bool
	}{
		{HumanEdits, false},
		{TrainedAlgorithmicMedia, true},
		{CompositeWithTrainedAlgorithmicMedia, true},
		// A template expansion or a database import is not AI. Marking it would
		// devalue the mark that matters.
		{AlgorithmicMedia, false},
	}
	for _, c := range cases {
		if got := c.st.RequiresDisclosure(); got != c.mark {
			t.Errorf("%s: RequiresDisclosure() = %v, want %v", c.st, got, c.mark)
		}
	}
}

func TestUnknownSourceTypeIsRefused(t *testing.T) {
	idx := NewIndex()
	err := idx.Set("p", Record{
		ContentHash: "abc", SourceType: SourceType("magic"), Author: "sam"})
	if err == nil {
		t.Fatal("an unrecognised digitalSourceType should be refused")
	}
}

func TestARecordNeedsAnAccountableAuthor(t *testing.T) {
	idx := NewIndex()
	err := idx.Set("p", Record{
		ContentHash: "abc", SourceType: TrainedAlgorithmicMedia, Model: "gpt-oss"})
	if err == nil {
		t.Fatal("provenance with no author should be refused")
	}
	// Article 50 binds a provider or deployer. "The model did it" is not a party.
	if !strings.Contains(err.Error(), "never on the tool") {
		t.Errorf("the refusal should say why, got %q", err)
	}
}

// The hash binding, which is the reason this is not just metadata.
func TestEditingContentMakesTheRecordStale(t *testing.T) {
	idx := NewIndex()
	must(t, idx.Set("home", Record{
		ContentHash: "hash-of-v1", SourceType: TrainedAlgorithmicMedia,
		Model: "gpt-oss:20b", Author: "sam"}))

	// Same page, new content.
	got := Check(idx, map[string]string{"home": "hash-of-v2"})
	if len(got) != 1 {
		t.Fatalf("expected one status, got %d", len(got))
	}
	if !got[0].Stale {
		t.Error("a record naming different bytes must be reported stale")
	}
	if len(Unmarked(got)) != 1 {
		t.Error("stale provenance counts as unmarked; it describes an older version")
	}
}

// The dangerous case: content with no record must not read as human-authored.
func TestMissingProvenanceIsAGapNotAClaim(t *testing.T) {
	idx := NewIndex()
	got := Check(idx, map[string]string{"mystery": "some-hash"})

	if got[0].Have {
		t.Fatal("there is no record")
	}
	if got[0].Record.SourceType == HumanEdits {
		t.Error("absent provenance must not default to human authorship")
	}
	if got[0].Disclosure != "" {
		t.Error("no record means no disclosure to make, not a claim of authorship")
	}
	if len(Unmarked(got)) != 1 {
		t.Error("a page with no provenance should be listed as needing attention")
	}
}

func TestDisclosureDistinguishesReviewedFromNot(t *testing.T) {
	unreviewed := Record{
		ContentHash: "h", SourceType: TrainedAlgorithmicMedia,
		Model: "gpt-oss:20b", Author: "sam"}
	if !strings.Contains(unreviewed.Disclosure(), "has not been reviewed") {
		t.Errorf("unreviewed AI content should say so, got %q", unreviewed.Disclosure())
	}

	reviewed := unreviewed
	reviewed.ReviewedBy = "dana"
	d := reviewed.Disclosure()
	if !strings.Contains(d, "reviewed by dana") {
		t.Errorf("a review should be named, got %q", d)
	}
	if strings.Contains(d, "has not been reviewed") {
		t.Error("reviewed content should not also claim it was unreviewed")
	}

	human := Record{ContentHash: "h", SourceType: HumanEdits, Author: "sam"}
	if human.Disclosure() != "" {
		t.Errorf("human content needs no disclosure, got %q", human.Disclosure())
	}
}

func TestMetaTagsCarryTheMachineReadableMark(t *testing.T) {
	r := Record{
		ContentHash: "abc123", SourceType: TrainedAlgorithmicMedia,
		Model: "gpt-oss:20b", Author: "sam"}
	tags := r.MetaTags()

	// The value other tools actually read. OpenAI, Google, Meta and Amazon emit
	// this vocabulary, so a private scheme would be unreadable by all of them.
	if !strings.Contains(tags, `name="c2pa:digitalSourceType" content="trainedAlgorithmicMedia"`) {
		t.Errorf("missing the C2PA marking, got %q", tags)
	}
	if !strings.Contains(tags, `name="ai-human-reviewed" content="false"`) {
		t.Error("the mark should say whether a person reviewed it")
	}

	human := Record{ContentHash: "x", SourceType: HumanEdits, Author: "sam"}
	if strings.Contains(human.MetaTags(), `name="ai-generated"`) {
		t.Error("human content must not be marked AI-generated")
	}
}

// The compliance feature must not itself become an injection vector. Model names
// and instructions are attacker-influenced in the threat model this project
// assumes throughout.
func TestProvenanceValuesCannotBreakOutOfAnAttribute(t *testing.T) {
	r := Record{
		ContentHash: "abc",
		SourceType:  TrainedAlgorithmicMedia,
		Model:       `evil" onload="alert(1)`,
		Author:      "sam",
	}
	tags := r.MetaTags()
	if strings.Contains(tags, `onload="alert`) {
		t.Fatalf("a model name escaped its attribute: %q", tags)
	}
	if !strings.Contains(tags, "&quot;") {
		t.Error("the quote should have been escaped")
	}
}

func TestJSONLDIsValidAndDisclosesWhenItShould(t *testing.T) {
	r := Record{
		ContentHash: "abc", SourceType: TrainedAlgorithmicMedia,
		Model: "gpt-oss:20b", Author: "sam", At: 1_760_000_000}
	out, err := r.JSONLD()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("JSON-LD did not parse: %v", err)
	}
	if doc["digitalSourceType"] != "trainedAlgorithmicMedia" {
		t.Errorf("wrong source type in JSON-LD: %v", doc["digitalSourceType"])
	}
	if _, ok := doc["disclaimer"]; !ok {
		t.Error("AI content should carry a disclaimer")
	}

	// A fresh map. Unmarshalling into a non-nil map adds keys without clearing
	// the ones already there, so reusing `doc` carried the previous document's
	// disclaimer into this assertion and made it pass for the wrong reason —
	// which is to say, fail.
	human := Record{ContentHash: "x", SourceType: HumanEdits, Author: "sam"}
	out, _ = human.JSONLD()
	var humanDoc map[string]any
	if err := json.Unmarshal([]byte(out), &humanDoc); err != nil {
		t.Fatalf("JSON-LD did not parse: %v", err)
	}
	if _, ok := humanDoc["disclaimer"]; ok {
		t.Error("human content should not carry an AI disclaimer")
	}
	if _, ok := humanDoc["creator"]; ok {
		t.Error("human content should not credit a model as creator")
	}
}

func TestDigestChangesWithTheRecords(t *testing.T) {
	a := NewIndex()
	must(t, a.Set("p", Record{ContentHash: "h1", SourceType: HumanEdits, Author: "sam"}))
	first := a.Digest()

	must(t, a.Set("p", Record{ContentHash: "h2", SourceType: HumanEdits, Author: "sam"}))
	if a.Digest() == first {
		t.Error("the digest should change when a record does")
	}
	if a.Digest() == "" {
		t.Error("the digest should not be empty")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
