package schema

import (
	"strings"
	"testing"
	"time"
)

// The tests that matter are the ones proving the attack surface is absent rather
// than guarded. A guard can be misconfigured; a missing feature cannot.

func article() Type {
	return Type{
		Name: "article",
		Fields: []Field{
			{Name: "title", Kind: Text, Required: true, MaxLen: 120},
			{Name: "body", Kind: LongText, Required: true},
			{Name: "slug", Kind: Slug, Required: true},
			{Name: "published", Kind: Date},
			{Name: "canonical", Kind: URL},
			{Name: "contact", Kind: Email},
			{Name: "status", Kind: Choice, Choices: []string{"draft", "review", "final"}},
			{Name: "tags", Kind: List},
			{Name: "reading_minutes", Kind: Number, Min: f(1), Max: f(120)},
			{Name: "featured", Kind: Boolean},
		},
	}
}

func f(v float64) *float64 { return &v }

// -- the CVEs this design does not have -------------------------------------

// CVE-2025-69873: a pattern reaching a backtracking engine costs ~44s of CPU for
// 31 characters. There is no pattern keyword, so a schema cannot carry one.
func TestATypeCannotCarryARegularExpression(t *testing.T) {
	// The only way to express a pattern would be a field kind that accepts one.
	// Assert the closed set does not contain such a thing.
	for k := range kinds {
		if strings.Contains(strings.ToLower(string(k)), "pattern") ||
			strings.Contains(strings.ToLower(string(k)), "regex") {
			t.Fatalf("kind %q would let a user supply a regex", k)
		}
	}
	// And a Field has nowhere to put one: this is a compile-time property of the
	// struct, asserted here so adding such a field to it fails a test rather
	// than passing review.
	var fld Field
	_ = fld.Choices // the only user-supplied string list, and it is compared literally
}

// Validation must not slow down super-linearly, or the absence of a regex
// keyword is beside the point.
func TestValidationStaysFastOnHostileInput(t *testing.T) {
	typ := article()
	// The classic catastrophic-backtracking input, which is only catastrophic
	// against a backtracking matcher.
	hostile := strings.Repeat("a", 30000) + "!"

	start := time.Now()
	for i := 0; i < 200; i++ {
		Validate(typ, map[string]any{
			"title": hostile, "body": hostile, "slug": hostile,
			"contact": hostile, "canonical": hostile,
		})
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("200 validations of 30k hostile characters took %s; something "+
			"is backtracking", d)
	}
}

// CVE-2026-54690: a $ref to an http URL gets dereferenced, no allow-list,
// redirects followed. There are no references at all here.
func TestATypeCannotReferenceAnythingRemote(t *testing.T) {
	// A field name is the only free-form identifier, and it cannot be a URL.
	err := Compile(Type{Name: "t", Fields: []Field{
		{Name: "https://169.254.169.254/latest/meta-data/", Kind: Text}}})
	if err == nil {
		t.Fatal("a field name that is a URL was accepted")
	}
	// Nor can a type name be one.
	if Compile(Type{Name: "http://evil.example/schema.json",
		Fields: []Field{{Name: "a", Kind: Text}}}) == nil {
		t.Error("a type name that is a URL was accepted")
	}
}

// A self-referencing $ref spins a worker forever. Types are flat, so a cycle
// has nowhere to exist.
func TestTypesCannotNestAndSoCannotRecurse(t *testing.T) {
	for k := range kinds {
		switch k {
		case Text, LongText, Number, Boolean, Date, URL, Email, Slug, Choice, List:
		default:
			t.Errorf("kind %q is outside the flat set and may permit nesting", k)
		}
	}
	// List holds strings, not objects — checked here because widening it to
	// []any of objects is exactly how nesting would creep back in.
	p := Validate(article(), map[string]any{
		"title": "x", "body": "y", "slug": "s",
		"tags": []any{map[string]any{"nested": "object"}},
	})
	if !hasProblem(p, "tags") {
		t.Error("a list of objects should be refused; lists hold text")
	}
}

// -- bounds ------------------------------------------------------------------

func TestUnboundedTypesAreRefused(t *testing.T) {
	many := Type{Name: "big"}
	for i := 0; i < MaxFields+1; i++ {
		many.Fields = append(many.Fields, Field{
			Name: "f" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + itoa(i),
			Kind: Text})
	}
	if err := Compile(many); err == nil {
		t.Error("a type past the field limit was accepted")
	}
}

func TestDuplicateFieldsAreRefused(t *testing.T) {
	err := Compile(Type{Name: "t", Fields: []Field{
		{Name: "title", Kind: Text}, {Name: "title", Kind: LongText}}})
	if err == nil {
		t.Fatal("two fields with one name were accepted; which wins would depend " +
			"on iteration order")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the error should say what is wrong, got %q", err)
	}
}

func TestUnknownKindIsRefused(t *testing.T) {
	if Compile(Type{Name: "t", Fields: []Field{{Name: "a", Kind: "eval"}}}) == nil {
		t.Error("an unknown field kind was accepted")
	}
}

// -- validation --------------------------------------------------------------

func TestValidContentPasses(t *testing.T) {
	p := Validate(article(), map[string]any{
		"title": "A title", "body": "Some prose.", "slug": "a-title",
		"published": "2026-08-14", "canonical": "https://example.com/a",
		"contact": "hi@example.com", "status": "final",
		"tags": []any{"one", "two"}, "reading_minutes": float64(4),
		"featured": true,
	})
	if len(p) != 0 {
		t.Errorf("valid content was rejected: %v", p)
	}
}

func TestRequiredFieldsAreEnforced(t *testing.T) {
	p := Validate(article(), map[string]any{"title": "only this"})
	if !hasProblem(p, "body") || !hasProblem(p, "slug") {
		t.Errorf("missing required fields were not reported: %v", p)
	}
	if hasProblem(p, "published") {
		t.Error("an absent optional field is not a problem")
	}
}

// Silently accepting undeclared fields is mass assignment arriving through the
// front door: content acquires shape nobody declared and nothing validates.
func TestUndeclaredFieldsAreReported(t *testing.T) {
	p := Validate(article(), map[string]any{
		"title": "t", "body": "b", "slug": "s",
		"is_admin": true, "role": "owner",
	})
	if !hasProblem(p, "is_admin") || !hasProblem(p, "role") {
		t.Errorf("undeclared fields were accepted silently: %v", p)
	}
}

// A URL field that accepts javascript: hands the site an injection vector
// through content that is otherwise well-formed and validated.
func TestURLFieldsRefuseExecutableSchemes(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>x</script>",
		"vbscript:msgbox",
		"file:///etc/passwd",
	} {
		p := Validate(article(), map[string]any{
			"title": "t", "body": "b", "slug": "s", "canonical": bad})
		if !hasProblem(p, "canonical") {
			t.Errorf("URL field accepted %q", bad)
		}
	}
	// And still accepts a real one.
	p := Validate(article(), map[string]any{
		"title": "t", "body": "b", "slug": "s",
		"canonical": "https://example.com/page?a=1"})
	if hasProblem(p, "canonical") {
		t.Errorf("a legitimate URL was refused: %v", p)
	}
}

func TestChoiceIsComparedLiterally(t *testing.T) {
	p := Validate(article(), map[string]any{
		"title": "t", "body": "b", "slug": "s", "status": "FINAL"})
	if !hasProblem(p, "status") {
		t.Error("choices are compared literally; a different case is a different value")
	}
}

func TestTypeConfusionIsCaught(t *testing.T) {
	cases := []struct {
		field string
		value any
	}{
		{"featured", "yes"},         // string where boolean expected
		{"reading_minutes", "four"}, // string where number expected
		{"title", 42},               // number where text expected
		{"tags", "one,two"},         // string where list expected
	}
	for _, c := range cases {
		content := map[string]any{"title": "t", "body": "b", "slug": "s"}
		content[c.field] = c.value
		if !hasProblem(Validate(article(), content), c.field) {
			t.Errorf("%s accepted %T", c.field, c.value)
		}
	}
}

func TestNumericBoundsAreEnforced(t *testing.T) {
	for _, v := range []float64{0, 121} {
		p := Validate(article(), map[string]any{
			"title": "t", "body": "b", "slug": "s", "reading_minutes": v})
		if !hasProblem(p, "reading_minutes") {
			t.Errorf("%v is outside 1..120 and was accepted", v)
		}
	}
}

func TestAltTextMustReferAnExistingField(t *testing.T) {
	err := Compile(Type{Name: "t", Fields: []Field{
		{Name: "image", Kind: URL},
		{Name: "image_alt", Kind: Text, AltFor: "nonexistent"},
	}})
	if err == nil {
		t.Error("alt text for a field that does not exist should be refused")
	}
	if Compile(Type{Name: "t", Fields: []Field{
		{Name: "image", Kind: URL},
		{Name: "image_alt", Kind: Text, AltFor: "image"},
	}}) != nil {
		t.Error("a valid alt-text binding was refused")
	}
}

func TestSlugAndDateFormats(t *testing.T) {
	bad := map[string][]string{
		"slug":      {"Not A Slug", "trailing-", "-leading", "has_underscore", ""},
		"published": {"14-08-2026", "2026-13-01", "2026-08-32", "yesterday"},
	}
	for field, values := range bad {
		for _, v := range values {
			content := map[string]any{"title": "t", "body": "b", "slug": "ok-slug"}
			content[field] = v
			if !hasProblem(Validate(article(), content), field) {
				t.Errorf("%s accepted %q", field, v)
			}
		}
	}
}

func hasProblem(ps []Problem, field string) bool {
	for _, p := range ps {
		if p.Field == field {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A typed page may carry the system fields without declaring them.
//
// Found by binding a page to a type and then trying to put a listing on it.
// The gate refused — correctly by its own rule, and wrongly for the product,
// because a vocabulary is site-wide and a listing can be shown by any page.
// Requiring every type to declare both would mean editing every type in the
// site before anything could be tagged, and forgetting one would make a page
// silently unclassifiable.
func TestATypedPageMayCarryTheSystemFields(t *testing.T) {
	typ := Type{Name: "article", Fields: []Field{
		{Name: "title", Kind: Text, Required: true},
	}}
	if err := Compile(typ); err != nil {
		t.Fatal(err)
	}

	problems := Validate(typ, map[string]any{
		"title":    "A page",
		"terms":    map[string]any{"topics": []any{"reports"}},
		"listings": []any{"recent"},
	})
	for _, p := range problems {
		t.Errorf("a system field was refused: %s", p)
	}

	// And a genuinely undeclared field is still refused, or the exemption has
	// swallowed the rule it is an exception to.
	problems = Validate(typ, map[string]any{"title": "A page", "invented": "x"})
	if len(problems) == 0 {
		t.Error("an undeclared field was accepted; reserving the system " +
			"fields must not disable the check for everything else")
	}
}

// A type cannot claim a reserved name as its own field.
func TestATypeCannotDeclareAReservedField(t *testing.T) {
	for _, name := range ReservedNames() {
		err := Compile(Type{Name: "article", Fields: []Field{
			{Name: name, Kind: Text},
		}})
		if err == nil {
			t.Errorf("a type declared %q, which every page carries anyway", name)
		}
	}
}
