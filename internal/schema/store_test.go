package schema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loaded(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Registry.Add(article()); err != nil {
		t.Fatal(err)
	}
	if err := s.Bind("news", "article"); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func valid() map[string]any {
	return map[string]any{"title": "A title", "body": "Prose.", "slug": "a-title"}
}

func TestAnEmptySiteHasNoTypesAndIsNotAnError(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("a site with no types file should load: %v", err)
	}
	if f := s.Gate(map[string]any{"index": map[string]any{"anything": "goes"}}); len(f) != 0 {
		t.Errorf("an unbound page was refused: %v", f)
	}
}

func TestGateRefusesContentThatDoesNotSatisfyItsType(t *testing.T) {
	s, _ := loaded(t)
	f := s.Gate(map[string]any{
		"news":  map[string]any{"title": "no body or slug"},
		"about": map[string]any{"free": "form"},
	})
	if len(f) != 1 {
		t.Fatalf("expected exactly the bound page to fail, got %d: %v", len(f), f)
	}
	if f[0].Page != "news" {
		t.Errorf("the wrong page failed: %s", f[0].Page)
	}
	if !strings.Contains(f[0].String(), "body") {
		t.Errorf("the failure should name the missing field: %s", f[0])
	}
}

// A binding whose type has been deleted must fail closed. If it read as
// "unbound", deleting a type would be a way to switch validation off for every
// page that used it — a control removable by the person it constrains.
func TestABindingToADeletedTypeFailsClosed(t *testing.T) {
	s, _ := loaded(t)
	delete(s.Registry.Types, "article")

	f := s.Gate(map[string]any{"news": valid()})
	if len(f) == 0 {
		t.Fatal("deleting the type made the page unconstrained")
	}
	if !strings.Contains(f[0].String(), "no longer exists") {
		t.Errorf("the failure should say why: %s", f[0])
	}
}

// A page bound to a type but holding a string, a list or a number is not
// "valid because there are no fields to check" — it cannot satisfy the type at
// all, and Validate never sees it.
func TestANonObjectPageCannotSatisfyAType(t *testing.T) {
	s, _ := loaded(t)
	for _, body := range []any{"just text", []any{1, 2}, float64(7), nil} {
		if f := s.Gate(map[string]any{"news": body}); len(f) == 0 {
			t.Errorf("a %T page satisfied an object type", body)
		}
	}
}

// The gate looks at the whole page set, not the pages being written. A write
// that leaves an already-broken page in place still produces a broken site, and
// checking only what changed is an exception people route around by changing
// something else.
func TestGateChecksEveryBoundPageNotJustTheChangedOne(t *testing.T) {
	s, _ := loaded(t)
	if err := s.Registry.Add(article()); err != nil {
		t.Fatal(err)
	}
	if err := s.Bind("archive", "article"); err != nil {
		t.Fatal(err)
	}
	f := s.Gate(map[string]any{
		"news":    valid(),
		"archive": map[string]any{"title": "broken"},
	})
	if len(f) != 1 || f[0].Page != "archive" {
		t.Errorf("an untouched broken page was not reported: %v", f)
	}
}

// -- content addressing ------------------------------------------------------

func TestATypeHashChangesWithItsShape(t *testing.T) {
	a := article()
	b := article()
	b.Fields[0].MaxLen = 200

	if Hash(a) == Hash(b) {
		t.Fatal("two different types share an address")
	}
	if Hash(a) != Hash(article()) {
		t.Error("the same type hashes differently twice")
	}
	// Field order is part of the type: it is the order the editor presents.
	c := article()
	c.Fields[0], c.Fields[1] = c.Fields[1], c.Fields[0]
	if Hash(a) == Hash(c) {
		t.Error("reordering fields left the address unchanged, so the editor " +
			"could change without the type appearing to")
	}
}

// The payoff of addressing both sides: a record says this content passed that
// type, and stays true when the type is edited afterwards.
func TestEditingATypeDoesNotInvalidateWhatAlreadyPassed(t *testing.T) {
	s, _ := loaded(t)
	content := valid()
	s.Record("news", content, time.Unix(1000, 0))

	if !s.Validated("news", content) {
		t.Fatal("content that was just recorded does not read as validated")
	}
	before := s.Records[0].TypeHash

	// Tighten the type. The published claim is about the old address.
	tighter := article()
	tighter.Fields = append(tighter.Fields, Field{
		Name: "summary", Kind: Text, Required: true})
	if err := s.Registry.Add(tighter); err != nil {
		t.Fatal(err)
	}

	if s.Records[0].TypeHash != before {
		t.Error("editing a type rewrote history")
	}
	if Hash(tighter) == before {
		t.Fatal("the tightened type kept the old address")
	}
	// And the content no longer passes the current type, which is the correct
	// present-tense answer alongside the correct past-tense one.
	if len(s.Gate(map[string]any{"news": content})) == 0 {
		t.Error("content missing a newly required field still passes")
	}
	if s.Validated("news", content) {
		t.Error("Validated must compare against the current type's address, " +
			"or it reports a stale pass as a current one")
	}
}

func TestValidatedRequiresBothHashesToMatch(t *testing.T) {
	s, _ := loaded(t)
	content := valid()
	s.Record("news", content, time.Unix(1000, 0))

	changed := valid()
	changed["title"] = "Something else"
	if s.Validated("news", changed) {
		t.Error("different content matched a record for other content")
	}
	if s.Validated("about", content) {
		t.Error("a record for one page vouched for another")
	}
}

// -- persistence -------------------------------------------------------------

func TestTypesSurviveARoundTrip(t *testing.T) {
	s, dir := loaded(t)
	s.Record("news", valid(), time.Unix(1000, 0))
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	back, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := back.Registry.Get("article"); !ok {
		t.Fatal("the type did not survive")
	}
	if back.Bound["news"] != "article" {
		t.Error("the binding did not survive")
	}
	if !back.Validated("news", valid()) {
		t.Error("the validation record did not survive")
	}
	if len(back.Gate(map[string]any{"news": map[string]any{"title": "x"}})) == 0 {
		t.Error("a reloaded store does not enforce")
	}
}

// The file is the one thing an attacker with disk access can reach, and a type
// that got there by any route other than Add has never been through Compile.
// Trusting it because it is ours is how the bounds become advisory.
func TestATypeThatBypassedCompileIsRefusedOnLoad(t *testing.T) {
	dir := t.TempDir()

	// A hand-written file with a field kind that does not exist. If Load
	// accepted this, Validate would skip the field entirely and the type would
	// silently check less than it claims.
	raw := `{"types":{"types":{"evil":{"name":"evil","fields":[
		{"name":"payload","kind":"exec"}]}}},"bound":{"news":"evil"}}`
	if err := os.WriteFile(filepath.Join(dir, "types.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("a type with an unknown field kind loaded without complaint")
	}
}

func TestACorruptFileIsAnErrorNotAnEmptySite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "types.json"),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("a corrupt types file read as a site with no types, which " +
			"would make corrupting it a way to switch validation off")
	}
}

func TestTheStoredFileIsNotWorldReadable(t *testing.T) {
	s, dir := loaded(t)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "types.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("types.json is %v; the shape of a site is reconnaissance",
			info.Mode().Perm())
	}
}

// A type arriving as JSON must not be able to smuggle a regex or a reference in
// under a key the struct ignores. The CLI refuses unknown keys outright; this
// checks the struct itself has nowhere to put them.
func TestJSONCannotIntroduceKeywordsTheDesignExcludes(t *testing.T) {
	raw := `{"name":"t","fields":[{"name":"a","kind":"text",
		"pattern":"(a+)+$","$ref":"http://169.254.169.254/","maxItems":99999999}]}`
	var typ Type
	if err := json.Unmarshal([]byte(raw), &typ); err != nil {
		t.Fatal(err)
	}
	// Unmarshalling drops them, because the struct has no such fields. Assert
	// the round trip does not carry them either.
	out, err := json.Marshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"pattern", "$ref", "maxItems", "169.254"} {
		if strings.Contains(string(out), gone) {
			t.Errorf("%q survived into the stored type", gone)
		}
	}
}
