// Package schema is content types, deliberately not JSON Schema.
//
// # Why not JSON Schema
//
// A CMS whose users define content types is accepting schemas from the people
// using it, and the guidance on that is blunt: data should never be validated
// against schemas from untrusted sources without sandboxing. The reasons are not
// theoretical.
//
//	pattern    ReDoS. CVE-2025-69873 — a 31-character regex reaching a backtracking
//	           engine costs about 44 seconds of CPU, doubling per added character.
//	           One request is a complete denial of service.
//	$ref       SSRF. CVE-2026-54690 — a $ref to an http URL is dereferenced with no
//	           scheme allow-list and redirects followed, so a schema can be pointed
//	           at a metadata endpoint and the response ends up embedded.
//	$ref       Unbounded recursion. A self-referencing $ref with no cycle detection
//	           spins a worker until it is killed.
//	depth      Stack overflow while compiling a sufficiently nested schema.
//
// Every one of those is a consequence of the language being powerful. This is the
// same argument the template engine rests on, and it lands the same way: do not
// harden something expressive, use something with nothing in it to exploit.
//
// So there is no regex, no reference of any kind, no recursion, and no
// combinators. Formats are a closed set implemented here in linear time. A type
// is a flat list of fields with bounded constraints, which is enough for content
// and not enough for an attack.
//
// # What is given up, and why that is the right trade
//
// You cannot express "matches this regular expression". That is the feature that
// carries the CVE, and a CMS that needs an arbitrary pattern for a content field
// is usually modelling something that belongs in code.
//
// You cannot nest a type inside a type. Editors that permit arbitrary nesting
// produce content nobody can edit and interfaces nobody can navigate with a
// screen reader, and the flat model is the one the admin can present honestly.
//
// # The part that is not just a safer subset
//
// A type is content, so it is immutable and addressed by the hash of its own
// bytes like everything else here. Content records the hash of the type it was
// validated against, and two things follow that a conventional CMS cannot offer.
//
// Editing a type cannot retroactively invalidate published content: the old type
// still exists at its own address, and the content still points at it. What
// changed is that new content validates against something else.
//
// And conformance becomes checkable rather than assumed. "This page was valid
// under this exact type" is a statement about two hashes, verifiable by anyone,
// long after both have moved on.
package schema

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Limits, all fixed. None of these is configurable, because a bound somebody can
// raise is a bound an attacker can raise.
const (
	MaxFields      = 64
	MaxNameLen     = 64
	MaxTextLen     = 4096
	MaxLongTextLen = 256 * 1024
	MaxListItems   = 256
	MaxChoices     = 128
)

// Kind is a field type. A closed set: there is no mechanism for adding one at
// runtime, which is what keeps the validator's cost knowable.
type Kind string

const (
	Text     Kind = "text"     // a single line
	LongText Kind = "longtext" // a body of prose
	Number   Kind = "number"
	Boolean  Kind = "boolean"
	Date     Kind = "date" // YYYY-MM-DD
	URL      Kind = "url"  // http or https only
	Email    Kind = "email"
	Slug     Kind = "slug"   // url-safe identifier
	Choice   Kind = "choice" // one of a fixed list
	List     Kind = "list"   // several short strings
)

var kinds = map[Kind]bool{
	Text: true, LongText: true, Number: true, Boolean: true, Date: true,
	URL: true, Email: true, Slug: true, Choice: true, List: true,
}

func (k Kind) Valid() bool { return kinds[k] }

// KindList names every kind, for error messages and for the editor. It is short
// on purpose: each entry is a validator someone has to be able to reason about,
// and a long list is how a bounded checker becomes an unbounded one.
func KindList() string {
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, string(k))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// Field is one field in a type.
type Field struct {
	Name     string   `json:"name"`
	Kind     Kind     `json:"kind"`
	Required bool     `json:"required,omitempty"`
	Label    string   `json:"label,omitempty"`
	Help     string   `json:"help,omitempty"`
	Choices  []string `json:"choices,omitempty"`
	MinLen   int      `json:"min_len,omitempty"`
	MaxLen   int      `json:"max_len,omitempty"`
	Min      *float64 `json:"min,omitempty"`
	Max      *float64 `json:"max,omitempty"`
	// Alt marks a field as the alternative text for another field, so the
	// accessibility checks and the editor both know an image has a description
	// attached rather than inferring it from a naming convention.
	AltFor string `json:"alt_for,omitempty"`
}

// Type is a content type: a flat, bounded list of fields.
type Type struct {
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Fields      []Field `json:"fields"`
}

var (
	reName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	reSlug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	reDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

// reserved names the fields every page may carry, whatever its type.
//
// These are not content. They are how a page is classified and what it
// composes, and both are cross-cutting: a vocabulary is site-wide, and a
// listing can be shown by any page. Requiring a type to declare them would
// mean adding two fields to every type in the site before anything could be
// tagged or could show a query, and forgetting one would make a page silently
// unclassifiable.
//
// Found by binding a page to a type and then trying to put a listing on it.
// The gate refused, correctly by its own rule and wrongly for the product, and
// nothing had noticed because no test had a typed page carrying a system field.
//
// The list is closed and short on purpose. Every name here is one an author
// cannot use for their own field, so each one costs something.
var reserved = map[string]bool{
	// taxonomy.Field — the terms a page carries, per vocabulary.
	"terms": true,
	// listing.Field — the declared queries a page shows.
	"listings": true,
	// How the page is arranged, rather than what it is about.
	//
	// A layout name, a hero and a list of sections are the same kind of
	// cross-cutting as a listing: any content can be laid out, and which
	// section kinds exist is a property of this build rather than of anybody's
	// content model. A type declaring them would have to be updated whenever a
	// layout learns a kind, in every site.
	//
	// This is also what made typing a page impossible. The shipped layouts want
	// a hero object and a list of section objects; the type system is flat by
	// design; so no page built the recommended way could satisfy any type, and
	// `posture scan` reported every page as untyped under a rule nothing could
	// pass. The arrangement is checked by section.Validate against the
	// catalogue instead, which is a stricter check than a flat type could have
	// made: it knows which kinds exist.
	"layout":   true,
	"hero":     true,
	"sections": true,
	// Navigation a page carries for itself: the trail above it and the filters
	// across the top of a listing. Both are arrangement — the same class as
	// menus, which the system already supplies — and both are lists of objects,
	// which a flat type cannot describe and should not try to.
	"breadcrumbs": true,
	"filters":     true,
	// form.Field — which declared form this page carries. Cross-cutting for
	// the same reason a listing is: an enquiry form belongs on a product page,
	// a contact page and a workshop page, none of which are the same type of
	// content. The questions come from the declaration, so a page carries the
	// name and nothing else.
	"form": true,
	// site.Starts and site.Expires — when a page is public. Cross-cutting for
	// the same reason: an embargo applies to any kind of content, and a type
	// that had to declare it would be a type somebody forgot to.
	"starts":  true,
	"expires": true,
}

// Reserved reports whether a field name belongs to the system.
//
// Exported so the editor can show these separately from an author's own fields
// rather than listing them as undeclared extras.
func Reserved(name string) bool { return reserved[name] }

// ReservedNames lists them, for help text and for the editor.
func ReservedNames() []string {
	out := make([]string, 0, len(reserved))
	for k := range reserved {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Compile checks a type definition and refuses anything unusable.
//
// Every rejection here is a bound the validator later relies on, so this is the
// only place limits are enforced: a Type that compiles has already been proved
// safe to run.
func Compile(t Type) error {
	if !reName.MatchString(t.Name) {
		return fmt.Errorf(
			"%q is not a usable type name: lowercase letters, digits and "+
				"underscore, starting with a letter", t.Name)
	}
	if len(t.Fields) == 0 {
		return fmt.Errorf("a type with no fields cannot describe anything")
	}
	if len(t.Fields) > MaxFields {
		return fmt.Errorf("%d fields, limit is %d", len(t.Fields), MaxFields)
	}

	seen := map[string]bool{}
	names := map[string]bool{}
	for _, f := range t.Fields {
		names[f.Name] = true
	}

	for _, f := range t.Fields {
		if !reName.MatchString(f.Name) {
			return fmt.Errorf("field %q: names are lowercase letters, digits and "+
				"underscore, starting with a letter", f.Name)
		}
		if seen[f.Name] {
			// Two fields with one name means the later silently wins, and which
			// one that is depends on map ordering somewhere.
			return fmt.Errorf("field %q appears twice", f.Name)
		}
		seen[f.Name] = true

		if Reserved(f.Name) {
			return fmt.Errorf(
				"field %q is a reserved name: every page may carry it "+
					"whatever its type, so a type declaring it would be "+
					"describing something it does not own", f.Name)
		}
		if !f.Kind.Valid() {
			return fmt.Errorf("field %q: %q is not a field kind. The kinds are "+
				"%s, and the list is closed — that is what keeps validation "+
				"cheap and bounded", f.Name, f.Kind, KindList())
		}
		if f.Kind == Choice {
			if len(f.Choices) == 0 {
				return fmt.Errorf("field %q is a choice with nothing to choose", f.Name)
			}
			if len(f.Choices) > MaxChoices {
				return fmt.Errorf("field %q has %d choices, limit is %d",
					f.Name, len(f.Choices), MaxChoices)
			}
		}
		if f.MinLen < 0 || f.MaxLen < 0 {
			return fmt.Errorf("field %q: lengths cannot be negative", f.Name)
		}
		if f.MaxLen > 0 && f.MinLen > f.MaxLen {
			return fmt.Errorf("field %q: min_len %d exceeds max_len %d",
				f.Name, f.MinLen, f.MaxLen)
		}
		if f.Min != nil && f.Max != nil && *f.Min > *f.Max {
			return fmt.Errorf("field %q: min exceeds max", f.Name)
		}
		if f.AltFor != "" && !names[f.AltFor] {
			return fmt.Errorf("field %q is alt text for %q, which does not exist",
				f.Name, f.AltFor)
		}
	}
	return nil
}

// Problem is one validation failure, named so it can be shown beside the field.
type Problem struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func (p Problem) String() string { return p.Field + ": " + p.Reason }

// Validate checks content against a type.
//
// Terminates in time linear in the size of the content, for every input. There
// is no backtracking anywhere: the format checks below are hand-written scans
// rather than regular expressions over user input, precisely because a regex
// over untrusted text is where the denial of service lives.
func Validate(t Type, content map[string]any) []Problem {
	var out []Problem
	known := map[string]Field{}
	for _, f := range t.Fields {
		known[f.Name] = f
	}

	// Unknown fields are reported rather than ignored. Silently accepting them
	// is how content acquires shape nobody declared and nothing validates —
	// mass assignment, arriving through the front door.
	extra := make([]string, 0)
	for k := range content {
		if _, ok := known[k]; !ok && !Reserved(k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, Problem{k, "not a field on type " + t.Name})
	}

	for _, f := range t.Fields {
		v, present := content[f.Name]
		// An empty string is the absence of a value, not a malformed one.
		//
		// The editor already drops blank optional fields before storing them,
		// so this agrees with what the browser does — and the two disagreeing
		// is what made a normal workflow impossible: write a page, then give it
		// a type, and every optional field left blank before the type existed
		// was reported as badly formatted rather than empty. The page could not
		// then be saved, and the message pointed at the format of a value
		// nobody had typed.
		//
		// It also fixes what a required field says when it is blank. "must
		// include http://" describes a URL somebody got wrong; "required"
		// describes the actual situation, which is that the box is empty.
		if !present || v == nil || v == "" {
			if f.Required {
				out = append(out, Problem{f.Name, "required"})
			}
			continue
		}
		out = append(out, checkField(f, v)...)
	}
	return out
}

func checkField(f Field, v any) []Problem {
	switch f.Kind {
	case Boolean:
		if _, ok := v.(bool); !ok {
			return []Problem{{f.Name, "must be true or false"}}
		}
	case Number:
		n, ok := toFloat(v)
		if !ok {
			return []Problem{{f.Name, "must be a number"}}
		}
		if f.Min != nil && n < *f.Min {
			return []Problem{{f.Name, fmt.Sprintf("must be at least %v", *f.Min)}}
		}
		if f.Max != nil && n > *f.Max {
			return []Problem{{f.Name, fmt.Sprintf("must be at most %v", *f.Max)}}
		}
	case List:
		items, ok := v.([]any)
		if !ok {
			return []Problem{{f.Name, "must be a list"}}
		}
		if len(items) > MaxListItems {
			return []Problem{{f.Name, fmt.Sprintf("more than %d items", MaxListItems)}}
		}
		for i, item := range items {
			s, ok := item.(string)
			if !ok {
				return []Problem{{f.Name, fmt.Sprintf("item %d is not text", i+1)}}
			}
			if utf8.RuneCountInString(s) > MaxTextLen {
				return []Problem{{f.Name, fmt.Sprintf("item %d is too long", i+1)}}
			}
		}
	default:
		s, ok := v.(string)
		if !ok {
			return []Problem{{f.Name, "must be text"}}
		}
		return checkString(f, s)
	}
	return nil
}

func checkString(f Field, s string) []Problem {
	n := utf8.RuneCountInString(s)

	limit := MaxTextLen
	if f.Kind == LongText {
		limit = MaxLongTextLen
	}
	if n > limit {
		return []Problem{{f.Name, fmt.Sprintf("longer than %d characters", limit)}}
	}
	if f.MinLen > 0 && n < f.MinLen {
		return []Problem{{f.Name, fmt.Sprintf("shorter than %d characters", f.MinLen)}}
	}
	if f.MaxLen > 0 && n > f.MaxLen {
		return []Problem{{f.Name, fmt.Sprintf("longer than %d characters", f.MaxLen)}}
	}

	switch f.Kind {
	case Slug:
		if !reSlug.MatchString(s) {
			return []Problem{{f.Name, "must be lowercase words joined by hyphens"}}
		}
	case Date:
		if !reDate.MatchString(s) || !plausibleDate(s) {
			return []Problem{{f.Name, "must be a date as YYYY-MM-DD"}}
		}
	case Email:
		if !looksLikeEmail(s) {
			return []Problem{{f.Name, "does not look like an email address"}}
		}
	case URL:
		if reason := badURL(s); reason != "" {
			return []Problem{{f.Name, reason}}
		}
	case Choice:
		for _, c := range f.Choices {
			if s == c {
				return nil
			}
		}
		return []Problem{{f.Name, "must be one of: " + strings.Join(f.Choices, ", ")}}
	}
	return nil
}

// looksLikeEmail is a scan rather than a pattern.
//
// The usual email regex is both wrong and a ReDoS candidate, and the ones that
// are correct are unreadable. This checks the properties that matter for a
// content field and terminates in one pass.
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.IndexByte(s[at+1:], '@') >= 0 {
		return false
	}
	domain := s[at+1:]
	dot := strings.IndexByte(domain, '.')
	if dot <= 0 || dot == len(domain)-1 {
		return false
	}
	return !strings.ContainsAny(s, " \t\r\n<>\"")
}

// badURL rejects anything that is not plainly a web address.
//
// The scheme allow-list is the point. `javascript:` in a content field reaches a
// template, and a URL field that accepts it hands the site an injection vector
// through validated, well-formed content — the renderer catches it, and a field
// that admits it should not have.
func badURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return "is not a usable URL"
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	case "":
		return "must include http:// or https://"
	default:
		return fmt.Sprintf("scheme %q is not allowed; use http or https", u.Scheme)
	}
	if u.Host == "" {
		return "has no host"
	}
	return ""
}

func plausibleDate(s string) bool {
	// Already known to be \d{4}-\d{2}-\d{2}.
	mo := (int(s[5]-'0'))*10 + int(s[6]-'0')
	d := (int(s[8]-'0'))*10 + int(s[9]-'0')
	return mo >= 1 && mo <= 12 && d >= 1 && d <= 31
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// Binding records that content was valid against a type at a moment.
//
// Both halves are hashes, which is what makes the claim checkable later: the
// type still exists at its own address whatever anyone does to the current
// version, so "this was valid under that" stays verifiable after both have moved
// on. Editing a type cannot retroactively invalidate published content, because
// the content points at the type it actually passed.
type Binding struct {
	Page        string `json:"page"`
	TypeName    string `json:"type"`
	TypeHash    string `json:"type_hash"`
	ContentHash string `json:"content_hash"`
	ValidatedAt int64  `json:"validated_at"`
}

// Registry holds the types a site uses.
type Registry struct {
	Types map[string]Type `json:"types"`
}

func NewRegistry() *Registry { return &Registry{Types: map[string]Type{}} }

// Add compiles and stores a type.
func (r *Registry) Add(t Type) error {
	if err := Compile(t); err != nil {
		return err
	}
	if r.Types == nil {
		r.Types = map[string]Type{}
	}
	r.Types[t.Name] = t
	return nil
}

func (r *Registry) Get(name string) (Type, bool) {
	t, ok := r.Types[name]
	return t, ok
}

func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.Types))
	for n := range r.Types {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Kinds lists every field kind, so the CLI and the editor can show them
// without keeping their own copy that drifts.
func Kinds() []string {
	return []string{
		string(Text), string(LongText), string(Number), string(Boolean),
		string(Date), string(URL), string(Email), string(Slug),
		string(Choice), string(List),
	}
}
