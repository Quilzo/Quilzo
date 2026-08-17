package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/schema"
)

// gate_test.go proves every write surface calls gateWrite. This proves gateWrite
// refuses. The pair matters: neutering the refusal broke no test until this
// existed, so the source check alone would have passed a gate that let
// everything through.
func gated(t *testing.T) string {
	t.Helper()
	w = out.New(false)
	dir := t.TempDir()

	st, err := schema.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Registry.Add(schema.Type{
		Name: "article",
		Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true},
			{Name: "body", Kind: schema.LongText, Required: true},
			{Name: "link", Kind: schema.URL},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Bind("news", "article"); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGateWriteRefusesInvalidContent(t *testing.T) {
	dir := gated(t)

	_, err := gateWrite(dir, map[string]any{
		"news": map[string]any{"title": "no body", "link": "javascript:alert(1)"},
	})
	if err == nil {
		t.Fatal("gateWrite accepted content that fails its type")
	}

	// It has to be a refusal, not a failure. The two exit differently, and a
	// script that treats "your content is wrong" as "the tool broke" retries
	// something that will never succeed.
	var blocked errBlocked
	if !errors.As(err, &blocked) {
		t.Errorf("a type failure should be a refusal, got %T", err)
	}
	for _, want := range []string{"body", "link", "article"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %s: %v", want, err)
		}
	}
}

func TestGateWriteAllowsValidContentAndRecordsIt(t *testing.T) {
	dir := gated(t)
	content := map[string]any{"title": "A title", "body": "Prose."}

	st, err := gateWrite(dir, map[string]any{"news": content})
	if err != nil {
		t.Fatalf("valid content was refused: %v", err)
	}
	if !st.Validated("news", content) {
		t.Error("a passing write left no record, so nothing can later show " +
			"which type this content satisfied")
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	back, err := schema.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Validated("news", content) {
		t.Error("the record did not survive being written")
	}
}

// A site with no types must not be harder to use than one without the feature.
func TestGateWriteIsInvisibleWhenNoTypesAreDefined(t *testing.T) {
	w = out.New(false)
	if _, err := gateWrite(t.TempDir(), map[string]any{
		"index": map[string]any{"anything": "at all", "nested": map[string]any{"x": 1}},
	}); err != nil {
		t.Errorf("an untyped site was refused: %v", err)
	}
}

// A refused write must record nothing. Otherwise a record would exist for
// content that was never stored, and Validated would vouch for a page that does
// not exist.
func TestARefusedWriteRecordsNothing(t *testing.T) {
	dir := gated(t)
	bad := map[string]any{"title": "no body"}

	if _, err := gateWrite(dir, map[string]any{"news": bad}); err == nil {
		t.Fatal("expected a refusal")
	}
	st, err := schema.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Records) != 0 {
		t.Errorf("a refused write left %d record(s)", len(st.Records))
	}
}
