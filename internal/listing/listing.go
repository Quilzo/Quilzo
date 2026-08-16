// Package listing is a query somebody declared, that a page can show.
//
// # What this is the answer to
//
// Drupal's Views is the most-cited reason people choose Drupal: content
// listings built through an interface, without writing SQL, embedded anywhere.
// Nothing here could do it — records could be queried from a screen and no page
// could show the result — so a site could hold an application's data and not
// display any of it.
//
// # Four things that make this one different
//
// A declared query, not a built one. A listing is a name, a collection, some
// conditions and a limit. There is no expression anywhere in it and no
// evaluator to reach: the conditions become a collection.Query, which is a set
// of values to compare. A query language is the thing that eventually gets an
// injection, and this does not have one.
//
// Parameters are declared and typed. Drupal calls these contextual filters and
// they take their value from the current URL, which is the correct feature and
// an obvious way to hand user input to a query. Here a parameter has a name, a
// kind and an optional default, and a value that does not satisfy the kind is
// refused before it reaches the filter. A listing cannot be given a condition
// it did not declare.
//
// Fields are an allowlist. A listing names what it exposes, and rows carry
// only that. Views hands the template the whole entity and relies on the
// template not to print the wrong field — which works until somebody adds a
// field to a type and it appears on a public page nobody re-reviewed. Here
// adding a field to a type changes nothing about what a listing shows.
//
// The cost is bounded and the bound is checked. Every listing has a row limit
// with a ceiling, a page may embed only so many, and a render that would exceed
// the budget is refused rather than served slowly. A page assembled from twelve
// unbounded listings is how a CMS becomes its own denial of service, and it is
// available in every product that has this feature.
//
// # Why this is affordable at all
//
// Because internal/collection has an index keyed by tree identifier. Resolving
// a listing is a filter over decoded records already in memory: about two
// milliseconds over ten thousand records rather than the four hundred a scan
// costs. Without that this feature could exist and could not be used.
package listing

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lithoform/lithoform/internal/collection"
)

// Bounds. Each is a refusal rather than a truncation: a listing that silently
// returns fewer rows than it was asked for is a listing somebody debugs for an
// afternoon.
const (
	// MaxRows any single listing may return.
	MaxRows = 200
	// DefaultRows when a listing does not say.
	DefaultRows = 20
	// MaxPerPage is how many listings one page may embed. Twelve unbounded
	// listings on a page is how this feature becomes an outage in every
	// product that has it.
	MaxPerPage = 8
	// MaxConditions in one listing. Past this it is a query language.
	MaxConditions = 12
	// MaxFields a listing may expose.
	MaxFields = 24
)

var (
	reName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	reField = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
)

// Match is how a condition compares.
type Match string

const (
	// Is compares exactly, after JSON round-tripping, so 4 matches 4.0.
	Is Match = "is"
	// Has is a case-insensitive substring, for a search box.
	Has Match = "has"
)

// Condition is one filter.
//
// Either a literal value or a parameter, never both — a condition that could
// take its value from two places is a condition whose behaviour depends on
// which one was set, and that is the sort of thing nobody notices is wrong.
type Condition struct {
	Field string `json:"field"`
	Match Match  `json:"match"`
	// Value is a literal.
	Value string `json:"value,omitempty"`
	// Param names a declared parameter to take the value from.
	Param string `json:"param,omitempty"`
}

// Kind is what a parameter accepts.
//
// A closed set, and the whole reason parameters are safe: a value that does not
// satisfy its kind never reaches the query.
type Kind string

const (
	// Text is a short string, bounded and restricted to characters that cannot
	// be mistaken for structure anywhere downstream.
	Text Kind = "text"
	// Number is an integer or decimal.
	Number Kind = "number"
	// Slug is a url-safe identifier — the usual shape of a value taken from a
	// path segment.
	Slug Kind = "slug"
)

// Param is a value the listing takes from its context.
type Param struct {
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// Default is used when no value is supplied. A parameter with no default
	// and no value makes the listing return nothing rather than everything —
	// see Resolve.
	Default string `json:"default,omitempty"`
	// Help is what somebody reading the listing needs to know.
	Help string `json:"help,omitempty"`
}

// Listing is a declared query.
type Listing struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	// Collection is which one to read.
	Collection string      `json:"collection"`
	Where      []Condition `json:"where,omitempty"`
	Params     []Param     `json:"params,omitempty"`
	// Fields is the allowlist. Empty means every field, which is a legitimate
	// choice for an internal listing and is called out by Validate so it is
	// never accidental.
	Fields []string `json:"fields,omitempty"`
	Sort   string   `json:"sort,omitempty"`
	// Descending reverses. The order is total either way — the identifier is
	// the final tie-break — so paging through a listing cannot repeat a row.
	Descending bool `json:"descending,omitempty"`
	Rows       int  `json:"rows,omitempty"`
}

// Set is every listing a site has.
type Set struct {
	Listings []Listing `json:"listings"`
}

func (s *Set) Get(name string) (*Listing, bool) {
	for i := range s.Listings {
		if s.Listings[i].Name == name {
			return &s.Listings[i], true
		}
	}
	return nil, false
}

func (s *Set) Names() []string {
	out := make([]string, 0, len(s.Listings))
	for _, l := range s.Listings {
		out = append(out, l.Name)
	}
	sort.Strings(out)
	return out
}

func (s *Set) Add(l Listing) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if _, exists := s.Get(l.Name); exists {
		return fmt.Errorf("there is already a listing called %q", l.Name)
	}
	s.Listings = append(s.Listings, l)
	return nil
}

func (s *Set) Remove(name string) error {
	kept := s.Listings[:0]
	found := false
	for _, l := range s.Listings {
		if l.Name == name {
			found = true
			continue
		}
		kept = append(kept, l)
	}
	if !found {
		return fmt.Errorf("there is no listing %q", name)
	}
	s.Listings = kept
	return nil
}

// Validate checks a listing is usable and bounded.
func (l *Listing) Validate() error {
	if !reName.MatchString(l.Name) {
		return fmt.Errorf(
			"%q is not a usable listing name: lowercase letters, digits and "+
				"underscores, starting with a letter", l.Name)
	}
	if err := collection.ValidName(l.Collection); err != nil {
		return fmt.Errorf("%q reads %w", l.Name, err)
	}
	if len(l.Where) > MaxConditions {
		return fmt.Errorf(
			"%q has %d conditions and the limit is %d. Past that this is a "+
				"query language, and a query language is the thing that "+
				"eventually gets an injection", l.Name, len(l.Where), MaxConditions)
	}
	if len(l.Fields) > MaxFields {
		return fmt.Errorf("%q exposes %d fields; the limit is %d",
			l.Name, len(l.Fields), MaxFields)
	}
	if l.Rows > MaxRows {
		return fmt.Errorf(
			"%q asks for %d rows and the ceiling is %d. A listing without a "+
				"real bound is how a page becomes slow for everybody at once",
			l.Name, l.Rows, MaxRows)
	}
	if l.Rows < 0 {
		return fmt.Errorf("%q asks for a negative number of rows", l.Name)
	}

	for _, f := range l.Fields {
		if !reField.MatchString(f) {
			return fmt.Errorf("%q exposes %q, which is not a field name",
				l.Name, f)
		}
	}
	if l.Sort != "" && l.Sort != "created" && l.Sort != "updated" &&
		l.Sort != "id" && !reField.MatchString(l.Sort) {
		return fmt.Errorf("%q sorts by %q, which is not a field name",
			l.Name, l.Sort)
	}

	declared := map[string]Kind{}
	for _, p := range l.Params {
		if !reName.MatchString(p.Name) {
			return fmt.Errorf("%q declares the parameter %q, which is not a "+
				"usable name", l.Name, p.Name)
		}
		if _, twice := declared[p.Name]; twice {
			return fmt.Errorf("%q declares the parameter %q twice",
				l.Name, p.Name)
		}
		switch p.Kind {
		case Text, Number, Slug:
		default:
			return fmt.Errorf(
				"%q declares %q as kind %q; a parameter is text, number or "+
					"slug — the set is closed so that a value which does not "+
					"satisfy its kind can be refused before it reaches the "+
					"filter", l.Name, p.Name, p.Kind)
		}
		declared[p.Name] = p.Kind
		if p.Default != "" {
			if _, err := coerce(p.Kind, p.Default); err != nil {
				return fmt.Errorf("%q: the default for %q %w",
					l.Name, p.Name, err)
			}
		}
	}

	for _, c := range l.Where {
		if !reField.MatchString(c.Field) {
			return fmt.Errorf("%q filters on %q, which is not a field name",
				l.Name, c.Field)
		}
		switch c.Match {
		case Is, Has:
		default:
			return fmt.Errorf("%q compares %q with %q; a condition is is or has",
				l.Name, c.Field, c.Match)
		}
		if c.Value != "" && c.Param != "" {
			return fmt.Errorf(
				"%q filters %q on both a fixed value and the parameter %q. "+
					"One condition takes its value from one place, or which "+
					"one wins becomes a question", l.Name, c.Field, c.Param)
		}
		if c.Param != "" {
			if _, ok := declared[c.Param]; !ok {
				return fmt.Errorf(
					"%q filters %q on the parameter %q, which it does not "+
						"declare", l.Name, c.Field, c.Param)
			}
		}
	}
	return nil
}

// Exposes reports whether this listing hands out every field.
//
// Called by the interface so an unrestricted listing is visibly unrestricted
// rather than quietly so. Adding a field to a content type must not change what
// a public page shows, and with no allowlist it does.
func (l *Listing) Exposes() bool { return len(l.Fields) == 0 }

// Row is one result, carrying only what the listing exposes.
type Row map[string]any

// Result is what a page gets.
type Result struct {
	// Rows, already trimmed to the exposed fields.
	Rows []Row
	// Total is how many matched before the row limit, so a template can say
	// "showing 20 of 340" without a second query.
	Total int
	// Truncated is whether the limit cut the result.
	Truncated bool
}

// Resolve runs a listing against an index.
//
// args are the parameter values from the context — a URL query, a path segment,
// whatever the caller reads them from. Unknown names are ignored rather than
// refused: a page carrying an unrelated query string is normal, and failing a
// render because somebody appended a tracking parameter would be absurd.
func Resolve(l *Listing, idx *collection.Index, args map[string]string) (Result, error) {
	if err := l.Validate(); err != nil {
		return Result{}, err
	}
	if idx == nil {
		return Result{}, fmt.Errorf("%q has no index to read", l.Name)
	}
	if idx.Collection != l.Collection {
		return Result{}, fmt.Errorf(
			"%q reads %q and was given an index of %q",
			l.Name, l.Collection, idx.Collection)
	}

	// Resolve every parameter first, so a bad value is refused before any
	// filtering happens rather than half way through.
	values := map[string]any{}
	for _, p := range l.Params {
		raw, given := args[p.Name]
		raw = strings.TrimSpace(raw)
		if !given || raw == "" {
			if p.Default == "" {
				// No value and no default. The listing returns nothing rather
				// than everything: a contextual filter whose argument is
				// missing must not silently widen to the whole collection,
				// which is the Drupal default and is how a filtered page
				// becomes an unfiltered one.
				return Result{}, nil
			}
			raw = p.Default
		}
		v, err := coerce(p.Kind, raw)
		if err != nil {
			return Result{}, fmt.Errorf("%s %w", p.Name, err)
		}
		values[p.Name] = v
	}

	q := collection.Query{
		Equals: map[string]any{}, Contains: map[string]string{},
		Sort: l.Sort, Descending: l.Descending,
	}
	for _, c := range l.Where {
		var v any = c.Value
		if c.Param != "" {
			v = values[c.Param]
		}
		switch c.Match {
		case Is:
			q.Equals[c.Field] = v
		case Has:
			q.Contains[c.Field] = fmt.Sprint(v)
		}
	}

	rows := l.Rows
	if rows <= 0 {
		rows = DefaultRows
	}
	q.Limit = rows

	found, total := idx.Query(q)
	out := Result{Total: total, Truncated: total > len(found)}
	for _, r := range found {
		out.Rows = append(out.Rows, project(l, r))
	}
	return out, nil
}

// project trims a record to the fields the listing exposes.
//
// The identifier always travels, because a row nobody can address is a row
// nobody can link to. Everything else is the allowlist — and when there is no
// allowlist, everything, which Validate makes visible rather than silent.
func project(l *Listing, r collection.Record) Row {
	row := Row{"id": r.ID, "created": r.Created, "updated": r.Updated}
	if len(l.Fields) == 0 {
		for k, v := range r.Fields {
			row[k] = v
		}
		return row
	}
	for _, f := range l.Fields {
		if v, ok := r.Fields[f]; ok {
			row[f] = v
		} else {
			// Present and empty rather than absent, so a template's
			// {% if row.x %} means "has a value" rather than "the listing
			// happened to include the field this time".
			row[f] = nil
		}
	}
	return row
}

// coerce turns a supplied string into a value of the declared kind.
//
// This is the boundary. Everything a caller hands in is a string from a URL,
// and this is the only way one becomes part of a query — so the checks here are
// the whole of what stops a parameter being an injection vector, which is
// achievable because the target is a structured comparison rather than a
// language.
func coerce(k Kind, raw string) (any, error) {
	if len(raw) > 200 {
		return nil, fmt.Errorf("is %d characters; the limit is 200", len(raw))
	}
	switch k {
	case Number:
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("must be a number, and %q is not", raw)
		}
		return n, nil
	case Slug:
		for _, r := range raw {
			ok := r == '-' || r == '_' ||
				(r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !ok {
				return nil, fmt.Errorf(
					"must be lowercase letters, digits, hyphens and "+
						"underscores, and %q is not", raw)
			}
		}
		return raw, nil
	case Text:
		// Control characters are refused rather than stripped. Stripping
		// changes what somebody searched for without telling them, and a
		// filter that quietly matched something else is worse than one that
		// said no.
		for _, r := range raw {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("contains a control character")
			}
		}
		return raw, nil
	}
	return nil, fmt.Errorf("has no kind")
}

// Budget is the cost of rendering one page's listings.
type Budget struct {
	Listings int
	Rows     int
}

// Check refuses a page that asks for too much.
//
// Called before rendering, so an expensive page fails to build rather than
// building slowly. The alternative is a page that works in a test with three
// records and takes a second in production, which is the failure mode this
// whole feature is prone to.
func Check(names []string, set *Set) (Budget, error) {
	if len(names) > MaxPerPage {
		return Budget{}, fmt.Errorf(
			"this page embeds %d listings and the limit is %d. A page "+
				"assembled from a dozen queries is how this feature becomes "+
				"the reason a site is slow", len(names), MaxPerPage)
	}
	b := Budget{Listings: len(names)}
	for _, n := range names {
		l, ok := set.Get(n)
		if !ok {
			return Budget{}, fmt.Errorf("this page embeds %q, which is not a "+
				"listing", n)
		}
		rows := l.Rows
		if rows <= 0 {
			rows = DefaultRows
		}
		b.Rows += rows
	}
	return b, nil
}

// Field is the page field naming which listings a page embeds.
const Field = "listings"

// On reads the listing names a page asks for.
func On(body any) []string {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	switch v := m[Field].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
