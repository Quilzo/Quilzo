package tmpl

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Filters are the answer to the thing competitors solve with a scripting
// language in the template.
//
// Velocity, Freemarker, Twig and the rest exist because authors need a value
// formatted, truncated, dated or defaulted, and a template that can only
// substitute cannot do it. The usual response is to embed a language — and then
// the template layer can call methods, reach objects it was never meant to, and
// the CVE list for every one of those engines is a list of server-side template
// injections ending in remote code execution. The capability is genuine; the
// mechanism is what goes wrong.
//
// So: the capability without the mechanism. A filter is a name from a fixed
// list, taking at most one literal argument, applied to a value that has
// already been looked up. There is no way to write a new one from a template,
// no way to call a method, no way to reach anything the template was not
// given, and no way to loop except the bounded `for` that already exists. It is
// not a language and cannot become one, which is the property that matters.
//
//	{{ page.title | upper }}
//	{{ page.summary | truncate:60 }}
//	{{ page.published | date:"2 January 2006" }}
//	{{ page.author | default:"Anonymous" }}
//	{{ page.tags | join:", " }}
//
// Escaping still happens afterwards, on the result, in the context the value
// lands in. A filter cannot opt out of it — that is what `{% raw %}` is for,
// and it is visible in a way a `| safe` at the end of a pipeline is not.
//
// Everything here is a pure function of its input. No filter reads a file,
// makes a request, or looks at anything but the value and its literal
// argument, which is what makes the whole set safe to apply to attacker-
// controlled content.

// Filter is one transformation.
type Filter struct {
	Name string
	// Arg describes the argument, empty when the filter takes none. Shown by
	// `quilzo template filters`.
	Arg     string
	Summary string
	Apply   func(v any, arg string) (any, error)
}

var filters = map[string]Filter{
	// -- text ------------------------------------------------------------------
	"upper": {Summary: "uppercase", Apply: func(v any, _ string) (any, error) {
		return strings.ToUpper(stringify(v)), nil
	}},
	"lower": {Summary: "lowercase", Apply: func(v any, _ string) (any, error) {
		return strings.ToLower(stringify(v)), nil
	}},
	"title": {Summary: "Capitalise Each Word", Apply: func(v any, _ string) (any, error) {
		prev := ' '
		return strings.Map(func(r rune) rune {
			out := r
			if unicode.IsSpace(prev) || prev == '-' {
				out = unicode.ToUpper(r)
			}
			prev = r
			return out
		}, strings.ToLower(stringify(v))), nil
	}},
	"trim": {Summary: "remove surrounding whitespace",
		Apply: func(v any, _ string) (any, error) {
			return strings.TrimSpace(stringify(v)), nil
		}},
	"truncate": {
		Arg: "length", Summary: "shorten to a length, on a word boundary",
		Apply: func(v any, arg string) (any, error) {
			n, err := strconv.Atoi(arg)
			if err != nil || n < 1 {
				return nil, errf("truncate needs a positive length, not %q", arg)
			}
			s := stringify(v)
			if len(s) <= n {
				return s, nil
			}
			cut := s[:n]
			// Back to a word boundary, so a truncated headline does not end
			// mid-word. Only if one is reasonably close, or a long unbroken
			// string would truncate to nothing.
			if i := strings.LastIndexAny(cut, " \t\n"); i > n/2 {
				cut = cut[:i]
			}
			return strings.TrimRight(cut, " \t\n.,;:") + "…", nil
		}},
	"slug": {Summary: "url-safe form", Apply: func(v any, _ string) (any, error) {
		var b strings.Builder
		dash := false
		for _, r := range strings.ToLower(stringify(v)) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				b.WriteRune(r)
				dash = false
			default:
				if !dash && b.Len() > 0 {
					b.WriteByte('-')
					dash = true
				}
			}
		}
		return strings.Trim(b.String(), "-"), nil
	}},
	"replace": {
		Arg: "old,new", Summary: "replace text",
		Apply: func(v any, arg string) (any, error) {
			old, new, ok := strings.Cut(arg, ",")
			if !ok {
				return nil, errf("replace needs old,new — got %q", arg)
			}
			return strings.ReplaceAll(stringify(v), old, new), nil
		}},

	// -- presence ---------------------------------------------------------------
	"default": {
		Arg: "value", Summary: "use this when the value is empty",
		Apply: func(v any, arg string) (any, error) {
			if isEmpty(v) {
				return arg, nil
			}
			return v, nil
		}},

	// -- numbers ----------------------------------------------------------------
	"round": {
		Arg: "places", Summary: "round a number",
		Apply: func(v any, arg string) (any, error) {
			f, ok := toFloat(v)
			if !ok {
				return nil, errf("round needs a number, got %T", v)
			}
			places := 0
			if arg != "" {
				n, err := strconv.Atoi(arg)
				if err != nil || n < 0 || n > 10 {
					return nil, errf("round needs 0 to 10 places, not %q", arg)
				}
				places = n
			}
			return strconv.FormatFloat(f, 'f', places, 64), nil
		}},

	// -- dates ------------------------------------------------------------------
	"date": {
		Arg: "layout", Summary: "format a date (Go layout, or iso/rfc822/human)",
		Apply: func(v any, arg string) (any, error) {
			t, err := parseWhen(stringify(v))
			if err != nil {
				return nil, err
			}
			switch arg {
			case "", "human":
				return t.Format("2 January 2006"), nil
			case "iso":
				return t.Format("2006-01-02"), nil
			case "rfc822":
				return t.Format(time.RFC822), nil
			case "rfc3339":
				return t.Format(time.RFC3339), nil
			}
			return t.Format(arg), nil
		}},

	// -- lists ------------------------------------------------------------------
	"join": {
		Arg: "separator", Summary: "join a list into text",
		Apply: func(v any, arg string) (any, error) {
			items, ok := v.([]any)
			if !ok {
				return stringify(v), nil
			}
			parts := make([]string, 0, len(items))
			for _, it := range items {
				parts = append(parts, stringify(it))
			}
			if arg == "" {
				arg = ", "
			}
			return strings.Join(parts, arg), nil
		}},
	"count": {Summary: "how many items", Apply: func(v any, _ string) (any, error) {
		switch t := v.(type) {
		case []any:
			return len(t), nil
		case map[string]any:
			return len(t), nil
		case string:
			return len([]rune(t)), nil
		case nil:
			return 0, nil
		}
		return 1, nil
	}},
	"first": {Summary: "the first item", Apply: func(v any, _ string) (any, error) {
		if items, ok := v.([]any); ok && len(items) > 0 {
			return items[0], nil
		}
		return nil, nil
	}},
	"last": {Summary: "the last item", Apply: func(v any, _ string) (any, error) {
		if items, ok := v.([]any); ok && len(items) > 0 {
			return items[len(items)-1], nil
		}
		return nil, nil
	}},
	"sort": {Summary: "sort a list", Apply: func(v any, _ string) (any, error) {
		items, ok := v.([]any)
		if !ok {
			return v, nil
		}
		out := append([]any(nil), items...)
		sort.SliceStable(out, func(i, j int) bool {
			return stringify(out[i]) < stringify(out[j])
		})
		return out, nil
	}},
	"take": {
		Arg: "n", Summary: "the first n items",
		Apply: func(v any, arg string) (any, error) {
			n, err := strconv.Atoi(arg)
			if err != nil || n < 0 {
				return nil, errf("take needs a count, not %q", arg)
			}
			items, ok := v.([]any)
			if !ok {
				return v, nil
			}
			if n > len(items) {
				n = len(items)
			}
			// Copied, not sliced. items[:n] shares its backing array with the
			// page data this template is rendering, and templates render
			// repeatedly against data the server holds — so a later filter
			// that reordered in place would change the content itself for
			// every subsequent request. None currently does. The one that
			// gets added next would, and it would be a very confusing bug.
			return append([]any(nil), items[:n]...), nil
		}},
}

// maxFilters bounds a pipeline.
//
// Each filter is cheap and bounded, but `| upper | upper | upper ...` repeated
// enough times is work an author can ask for by typing. Eight is more than any
// real pipeline and small enough that the total is never interesting.
const maxFilters = 8

// applyFilters runs a parsed pipeline over a value.
func applyFilters(v any, pipe []pipeStep) (any, error) {
	if len(pipe) > maxFilters {
		return nil, errf("%d filters in one expression; the limit is %d",
			len(pipe), maxFilters)
	}
	for _, step := range pipe {
		f, ok := filters[step.name]
		if !ok {
			return nil, errf(
				"there is no filter called %q. Available: %s",
				step.name, strings.Join(FilterNames(), ", "))
		}
		out, err := f.Apply(v, step.arg)
		if err != nil {
			return nil, err
		}
		v = out
	}
	return v, nil
}

// pipeStep is one filter and its literal argument.
type pipeStep struct {
	name string
	arg  string
}

// parseExpr splits a value expression into a path and its filters.
//
// The argument is a literal — a quoted string or a bare word — and never a
// path. That is the line that keeps this from becoming a language: a filter
// argument that could name another value would need evaluation, evaluation
// needs an evaluator, and an evaluator is the thing every template-injection
// advisory is about.
func parseExpr(expr string) (path string, pipe []pipeStep, err error) {
	parts := splitPipe(expr)
	path = strings.TrimSpace(parts[0])
	for _, raw := range parts[1:] {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return "", nil, errf("empty filter in %q", expr)
		}
		name, arg, _ := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		arg = strings.TrimSpace(arg)
		if len(arg) >= 2 && (arg[0] == '"' && arg[len(arg)-1] == '"' ||
			arg[0] == '\'' && arg[len(arg)-1] == '\'') {
			arg = arg[1 : len(arg)-1]
		}
		if !reFilterName.MatchString(name) {
			return "", nil, errf("%q is not a filter name", name)
		}
		pipe = append(pipe, pipeStep{name: name, arg: arg})
	}
	return path, pipe, nil
}

// splitPipe splits on | outside quotes, so a separator containing a pipe —
// `join:"|"` — does not split the expression it appears in.
func splitPipe(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			cur.WriteRune(r)
		case r == '|':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}

// FilterNames lists every filter, for the error message and the CLI.
func FilterNames() []string {
	out := make([]string, 0, len(filters))
	for name := range filters {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Filters returns every filter with its documentation.
func Filters() []Filter {
	out := make([]Filter, 0, len(filters))
	for name, f := range filters {
		f.Name = name
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	case bool:
		return !t
	case float64:
		return t == 0
	case int:
		return t == 0
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

// parseWhen accepts the date shapes content actually carries.
func parseWhen(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{
		time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05",
		"2006-01-02", "02/01/2006", time.RFC1123,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, errf("%q is not a date this understands", s)
}

var _ = fmt.Sprintf

// reFilterName is deliberately narrower than a path: lowercase letters only,
// so a filter name cannot be confused for anything else and a typo fails
// loudly rather than resolving to something unexpected.
var reFilterName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,20}$`)
