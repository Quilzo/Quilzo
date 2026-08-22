package section

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Editing what is inside a section, without a JSON textarea.
//
// # The problem this solves
//
// A section is a nested object: a features section has a title and a list of
// items, each with a title and a body. The page editor submits a flat form, so
// a page with sections could be reordered in the browser and not *edited* in
// it — somebody could add a features section and had no way to change what the
// cards said. That is the half of the page builder that decides whether the
// other half is worth having.
//
// # Why a dotted path and not a JSON field
//
// The obvious answer is a textarea holding the section's JSON. It works, and it
// makes editing a card's title a task that can produce a parse error — so the
// people this screen exists for are exactly the people it fails. A flat form
// over dotted paths gives every value its own labelled input, which is also the
// only version a screen reader can announce.
//
// # Why only paths that already exist may be written
//
// The form is a list of names an attacker can choose. If Apply accepted any
// path it was given, a post could invent `items.0.href` on a section that never
// had one, or write a hundred thousand keys. So Apply walks the section it
// already has and takes a value only where a leaf is already there; adding and
// removing entries are separate, explicit operations with their own bounds.
//
// That is stricter than a form usually is, and it is the same argument as the
// closed token list in internal/theme: a shape somebody can extend by posting
// to it is a shape nobody can reason about.

const (
	// maxFields bounds one section's form. A section with more inputs than this
	// is not a section anybody is editing on a screen.
	maxFields = 250
	// maxDepth bounds the walk. Two levels covers every shipped kind — a
	// section, its items, and their fields — and the third is slack.
	maxDepth = 3
	// maxItems bounds a list somebody is adding to from a screen.
	maxItems = 60
)

// A path segment is a field name or a list index. Matched rather than trusted:
// it arrives from a form, and it is used to walk a structure.
var reSegment = regexp.MustCompile(`^([a-z][a-z0-9_]*|[0-9]{1,3})$`)

// Editable is one value inside a section that a form can change.
//
// Named for what it is rather than "Field", which in this package is already the
// key a page's sections live under — two things called Field in one package is
// one of them being read as the other.
type Editable struct {
	// Path is the dotted route to it: "title", "items.0.body".
	Path string `json:"path"`
	// Label is the path written for a person: "items 1 · body".
	Label string `json:"label"`
	// Value is what it holds now, as text.
	Value string `json:"value"`
	// Long is true for values that want a textarea rather than an input,
	// decided by what is in them rather than by the field's name — a "body"
	// holding four words does not need three rows.
	Long bool `json:"long,omitempty"`
	// Group is the list entry this field belongs to, or empty for a field on
	// the section itself. Screens use it to draw one block per entry.
	Group string `json:"group,omitempty"`
	// Number is true when the current value is a number, so it is written back
	// as one — a percentage that becomes the string "72" stops working with the
	// filter that guarantees charts are numeric.
	Number bool `json:"number,omitempty"`
}

// Fields lists everything editable in one section of a page, in a stable order.
//
// Scalars first, then each list entry as its own group. That is the order the
// values appear on the rendered page, which is the only ordering somebody
// editing can check their work against.
func Fields(body any, at int) ([]Editable, error) {
	inner, err := innerOf(body, at)
	if err != nil {
		return nil, err
	}
	var out []Editable
	walkFields(inner, "", "", 0, &out)
	if len(out) > maxFields {
		out = out[:maxFields]
	}
	return out, nil
}

func walkFields(v any, prefix, group string, depth int, out *[]Editable) {
	if depth > maxDepth || len(*out) >= maxFields {
		return
	}
	m, isMap := v.(map[string]any)
	if !isMap {
		return
	}

	// Scalars before containers, so the section's own title is above its items
	// rather than below them.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var containers []string
	for _, k := range keys {
		switch inner := m[k].(type) {
		case map[string]any, []any:
			containers = append(containers, k)
			_ = inner
		default:
			text, number, ok := scalar(m[k])
			if !ok {
				continue
			}
			*out = append(*out, Editable{
				Path:   join(prefix, k),
				Label:  labelFor(join(prefix, k)),
				Value:  text,
				Long:   len(text) > 80,
				Group:  group,
				Number: number,
			})
		}
	}

	for _, k := range containers {
		switch t := m[k].(type) {
		case []any:
			for i, entry := range t {
				path := join(prefix, k) + "." + strconv.Itoa(i)
				switch entry.(type) {
				case map[string]any:
					walkFields(entry, path, path, depth+1, out)
				default:
					text, number, ok := scalar(entry)
					if !ok {
						continue
					}
					*out = append(*out, Editable{
						Path: path, Label: labelFor(path), Value: text,
						Group: join(prefix, k), Number: number,
					})
				}
			}
		case map[string]any:
			walkFields(t, join(prefix, k), group, depth+1, out)
		}
	}
}

// scalar renders a leaf as text and says whether it was a number.
//
// int as well as float64, because a value can arrive from two places: decoded
// JSON, where every number is a float64, and a stub declared in Go, where 72 is
// an int. Handling only the first is why a percentage typed into the form came
// back as the string "72" — which still renders and then fails the filter that
// makes a chart's custom property provably numeric.
func scalar(v any) (text string, number bool, ok bool) {
	switch t := v.(type) {
	case string:
		return t, false, true
	case bool:
		return strconv.FormatBool(t), false, true
	case int:
		return strconv.Itoa(t), true, true
	case int64:
		return strconv.FormatInt(t, 10), true, true
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true, true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true, true
	default:
		return "", false, false
	}
}

// coerce turns a submitted string back into the shape the existing value had.
//
// The existing value decides, not the field name. A number stays a number, a
// boolean stays a boolean, and a value that no longer parses as either is kept
// as text — because a field that held a number and now holds a label is a
// legitimate edit, and the chart filter refuses it loudly at render time rather
// than this refusing it quietly here.
func coerce(existing any, value string) (any, bool) {
	switch existing.(type) {
	case map[string]any, []any:
		// A container is not a leaf, so a post naming one changes nothing.
		return nil, false
	case int, int64, float64:
		if n, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			return n, true
		}
		return value, true
	case bool:
		if b, err := strconv.ParseBool(strings.TrimSpace(value)); err == nil {
			return b, true
		}
		return value, true
	default:
		return value, true
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// labelFor writes a path the way somebody reads it: items.0.body becomes
// "items 1 · body", counting from one because the person is looking at a list
// of cards rather than at an array.
func labelFor(path string) string {
	parts := strings.Split(path, ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, strconv.Itoa(n+1))
			continue
		}
		out = append(out, strings.ReplaceAll(p, "_", " "))
	}
	return strings.Join(out, " · ")
}

// Apply writes form values back into one section.
//
// Only where a leaf already exists. A path the section does not have is ignored
// rather than created: the form's field names arrive from whoever posted them,
// and a shape somebody can extend by posting to it is a shape nobody can reason
// about. Adding an entry is AddItem, which has its own bound.
func Apply(body any, at int, values map[string]string) (map[string]any, error) {
	page, list := copyOf(body)
	if at < 0 || at >= len(list) {
		return nil, fmt.Errorf("there is no section %d; this page has %d",
			at, len(list))
	}
	entry, ok := list[at].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("section %d is not editable", at)
	}
	kind, inner := discriminator(entry)
	if inner == nil {
		return nil, fmt.Errorf("section %d carries nothing to edit", at)
	}

	updated := cloneValue(inner).(map[string]any)
	paths := make([]string, 0, len(values))
	for path := range values {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		segments := strings.Split(path, ".")
		if len(segments) > maxDepth+1 {
			continue
		}
		usable := true
		for _, seg := range segments {
			if !reSegment.MatchString(seg) {
				usable = false
				break
			}
		}
		if !usable {
			continue
		}
		setLeaf(updated, segments, values[path])
	}

	next := make([]any, len(list))
	copy(next, list)
	replacement := map[string]any{kind: updated}
	for k, v := range entry {
		if k != kind {
			replacement[k] = v
		}
	}
	next[at] = replacement
	page[Field] = next
	return page, nil
}

// setLeaf writes one value where a leaf of the same shape already is.
//
// Both parents, because a leaf sits inside a map ("title") and inside a slice
// ("paragraphs.0", "rows.0.cells.1") — the second is how a table's cells and a
// plan's feature list are written, and handling only the first meant those were
// shown on the screen and silently ignored on save.
func setLeaf(node any, segments []string, value string) {
	if len(segments) == 0 {
		return
	}
	key := segments[0]

	if len(segments) == 1 {
		switch parent := node.(type) {
		case map[string]any:
			existing, present := parent[key]
			if !present {
				return
			}
			if next, ok := coerce(existing, value); ok {
				parent[key] = next
			}
		case []any:
			i, err := strconv.Atoi(key)
			if err != nil || i < 0 || i >= len(parent) {
				return
			}
			if next, ok := coerce(parent[i], value); ok {
				parent[i] = next
			}
		}
		return
	}

	switch t := node.(type) {
	case map[string]any:
		child, present := t[key]
		if !present {
			return
		}
		setLeaf(child, segments[1:], value)
	case []any:
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(t) {
			return
		}
		setLeaf(t[i], segments[1:], value)
	}
}

// AddItem appends an entry to a list inside a section, copied from the last one
// with its text cleared.
//
// Copied rather than invented, because the shape of an entry is whatever this
// section's entries already are — a features card and a pricing plan hold
// different fields, and a screen that had to know which would be a second
// catalogue to keep in step. Cleared rather than duplicated, because a list with
// the same card twice is a list somebody has to edit twice.
func AddItem(body any, at int, list string) (map[string]any, error) {
	return editList(body, at, list, func(entries []any) ([]any, error) {
		if len(entries) >= maxItems {
			return nil, fmt.Errorf(
				"this list already has %d entries, which is the limit for "+
					"editing one on a screen", len(entries))
		}
		if len(entries) == 0 {
			return nil, fmt.Errorf(
				"there is nothing here to copy the shape of. Add the section " +
					"again to start from its example content")
		}
		last := entries[len(entries)-1]
		fresh := cloneValue(last)
		if m, ok := fresh.(map[string]any); ok {
			for k, v := range m {
				if _, isText := v.(string); isText {
					m[k] = ""
				}
			}
		} else if _, isText := fresh.(string); isText {
			fresh = ""
		}
		return append(entries, fresh), nil
	})
}

// RemoveItem takes one entry out of a list inside a section.
func RemoveItem(body any, at int, list string, index int) (map[string]any, error) {
	return editList(body, at, list, func(entries []any) ([]any, error) {
		if index < 0 || index >= len(entries) {
			return nil, fmt.Errorf("there is no entry %d in %s", index, list)
		}
		out := make([]any, 0, len(entries)-1)
		out = append(out, entries[:index]...)
		out = append(out, entries[index+1:]...)
		return out, nil
	})
}

// editList is the read, change, put back that both list operations share.
func editList(body any, at int, list string,
	change func([]any) ([]any, error)) (map[string]any, error) {

	if !reSegment.MatchString(list) {
		return nil, fmt.Errorf("%q is not a list on this section", list)
	}
	page, sections := copyOf(body)
	if at < 0 || at >= len(sections) {
		return nil, fmt.Errorf("there is no section %d; this page has %d",
			at, len(sections))
	}
	entry, ok := sections[at].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("section %d is not editable", at)
	}
	kind, inner := discriminator(entry)
	if inner == nil {
		return nil, fmt.Errorf("section %d carries nothing to edit", at)
	}
	updated := cloneValue(inner).(map[string]any)
	entries, isList := updated[list].([]any)
	if !isList {
		return nil, fmt.Errorf("%s has no %s to change", kind, list)
	}
	changed, err := change(entries)
	if err != nil {
		return nil, err
	}
	updated[list] = changed

	next := make([]any, len(sections))
	copy(next, sections)
	replacement := map[string]any{kind: updated}
	for k, v := range entry {
		if k != kind {
			replacement[k] = v
		}
	}
	next[at] = replacement
	page[Field] = next
	return page, nil
}

// Lists names the lists inside a section, so a screen can offer to add to them.
func Lists(body any, at int) []string {
	inner, err := innerOf(body, at)
	if err != nil {
		return nil
	}
	var out []string
	for k, v := range inner {
		if entries, ok := v.([]any); ok && len(entries) > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// KindAt names the kind of one section.
func KindAt(body any, at int) (string, bool) {
	_, list := copyOf(body)
	if at < 0 || at >= len(list) {
		return "", false
	}
	m, ok := list[at].(map[string]any)
	if !ok {
		return "", false
	}
	kind, _ := discriminator(m)
	return kind, true
}

func innerOf(body any, at int) (map[string]any, error) {
	_, list := copyOf(body)
	if at < 0 || at >= len(list) {
		return nil, fmt.Errorf("there is no section %d; this page has %d",
			at, len(list))
	}
	m, ok := list[at].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("section %d is not editable", at)
	}
	_, inner := discriminator(m)
	if inner == nil {
		return nil, fmt.Errorf("section %d carries nothing to edit", at)
	}
	return inner, nil
}
