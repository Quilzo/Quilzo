package foreign

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The construct-by-construct translation.
//
// Three dialect families reach the same four constructs:
//
//	{% if %} / {% endif %}          →  {% if %} / {% end %}
//	{% for x in y %} / {% endfor %} →  {% for x in y %} / {% end %}
//	{{#if x}} / {{/if}}             →  {% if x %} / {% end %}
//	{{ if .X }} / {{ end }}         →  {% if page.x %} / {% end %}
//
// What does not reach them is the interesting part, and each one is reported
// with the shape it should become rather than as a failure. The two that come up
// constantly:
//
//	{% else %}     two sibling ifs, on a field and its negation. The renderer
//	               derives the common negations — see internal/render/derive.go —
//	               so most elses become {% if x %}…{% end %}{% if x_absent %}.
//	{% include %}  a layout, or a section kind. There are no partials, because a
//	               partial is a name resolved at render time and this language
//	               resolves nothing at render time.

var (
	reStmt      = regexp.MustCompile(`\{%-?\s*([\s\S]*?)\s*-?%\}`)
	reHBOpenIf  = regexp.MustCompile(`\{\{#if\s+([^}]+?)\s*\}\}`)
	reHBEach    = regexp.MustCompile(`\{\{#each\s+([^}]+?)\s*\}\}`)
	reHBWith    = regexp.MustCompile(`\{\{#with\s+([^}]+?)\s*\}\}`)
	reHBUnless  = regexp.MustCompile(`\{\{#unless\s+([^}]+?)\s*\}\}`)
	reHBClose   = regexp.MustCompile(`\{\{/(if|each|with|unless)\s*\}\}`)
	reHBElse    = regexp.MustCompile(`\{\{\s*else\s*\}\}`)
	reGoTag     = regexp.MustCompile(`\{\{-?\s*([\s\S]*?)\s*-?\}\}`)
	reExpr      = regexp.MustCompile(`\{\{\s*([^{}%]*?)\s*\}\}`)
	rePath      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$`)
	reTripleRaw = regexp.MustCompile(`\{\{\{\s*([^{}]+?)\s*\}\}\}`)
)

// convertHandlebars rewrites the block helpers.
//
// Handlebars is worth handling separately because its blocks are spelled inside
// {{ }}, so leaving them for the value pass would turn {{#if x}} into an escaped
// value called "#if x" — visible angle-bracket noise on the page rather than a
// conversion failure anybody notices.
func (r *Result) convertHandlebars(src string) string {
	if !strings.Contains(src, "{{#") && !strings.Contains(src, "{{/") {
		return src
	}
	out := reTripleRaw.ReplaceAllStringFunc(src, func(m string) string {
		inner := reTripleRaw.FindStringSubmatch(m)[1]
		r.Changes = append(r.Changes, fmt.Sprintf(
			"{{{%s}}} became {%% raw %s %%}. Triple braces mean unescaped in "+
				"Handlebars and `raw` means it here — the difference is that "+
				"`raw` is a keyword rather than a punctuation mark, so every "+
				"place a template extends trust can be listed", inner, inner))
		return "{% raw " + inner + " %}"
	})

	// Each loop needs a variable, because this language names the item rather
	// than rebinding the context. `this` inside the block becomes that name.
	loop := 0
	out = reHBEach.ReplaceAllStringFunc(out, func(m string) string {
		subject := strings.TrimSpace(reHBEach.FindStringSubmatch(m)[1])
		loop++
		name := loopName(subject, loop)
		r.Changes = append(r.Changes, fmt.Sprintf(
			"{{#each %s}} became {%% for %s in %s %%}. Handlebars rebinds the "+
				"context inside a block and this language does not, so the "+
				"item has a name — `this` inside the block became `%s`",
			subject, name, subject, name))
		return "{% for " + name + " in " + subject + " %}"
	})
	out = strings.ReplaceAll(out, "{{this}}", "{{ item }}")
	out = strings.ReplaceAll(out, "{{ this }}", "{{ item }}")
	out = strings.ReplaceAll(out, "{{this.", "{{ item.")
	out = strings.ReplaceAll(out, "{{ this.", "{{ item.")

	out = reHBOpenIf.ReplaceAllString(out, "{% if $1 %}")
	out = reHBUnless.ReplaceAllStringFunc(out, func(m string) string {
		subject := strings.TrimSpace(reHBUnless.FindStringSubmatch(m)[1])
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"{{#unless %s}} has no equivalent: there is no negation in this "+
				"language, because a condition that can be inverted is a "+
				"condition that can be computed. The renderer derives the "+
				"common ones — a thing with no href gets `unlinked`, a thing "+
				"with no image gets `no_image` — so write {%% if %s_absent %%} "+
				"and put that field on the content, or use the derived name",
			subject, subject))
		return "{% if " + subject + "_absent %}"
	})
	out = reHBWith.ReplaceAllStringFunc(out, func(m string) string {
		subject := strings.TrimSpace(reHBWith.FindStringSubmatch(m)[1])
		r.Changes = append(r.Changes, fmt.Sprintf(
			"{{#with %s}} became {%% if %s %%}: the block still only renders "+
				"when the value is there, but names inside it are not "+
				"shortened, so they read %s.field", subject, subject, subject))
		return "{% if " + subject + " %}"
	})
	out = reHBElse.ReplaceAllStringFunc(out, func(string) string {
		r.Unsupported = append(r.Unsupported, elseAdvice("{{else}}"))
		return "{% end %}{% if TODO_else %}"
	})
	out = reHBClose.ReplaceAllString(out, "{% end %}")
	return out
}

// convertGoTemplate rewrites Go and Hugo actions.
//
// Hugo's variables are the part worth translating properly: .Title is the page's
// title, .Params.x is a field somebody defined, .Site.Title is the site name.
// Left alone they would all resolve to nothing, and a page that renders with
// every value missing looks like a template that works on empty content.
func (r *Result) convertGoTemplate(src string) string {
	if !reGoAction.MatchString(src) {
		return src
	}
	return reGoTag.ReplaceAllStringFunc(src, func(m string) string {
		inner := strings.TrimSpace(reGoTag.FindStringSubmatch(m)[1])
		switch {
		case inner == "end":
			return "{% end %}"
		case strings.HasPrefix(inner, "if "):
			return "{% if " + hugoPath(strings.TrimSpace(inner[3:])) + " %}"
		case strings.HasPrefix(inner, "range "):
			subject := hugoPath(strings.TrimSpace(inner[6:]))
			name := loopName(subject, 1)
			r.Changes = append(r.Changes, fmt.Sprintf(
				"{{ range %s }} became {%% for %s in %s %%}; a `.` inside the "+
					"block refers to %s now", subject, name, subject, name))
			return "{% for " + name + " in " + subject + " %}"
		case strings.HasPrefix(inner, "with "):
			return "{% if " + hugoPath(strings.TrimSpace(inner[5:])) + " %}"
		case strings.HasPrefix(inner, "partial "),
			strings.HasPrefix(inner, "template "),
			strings.HasPrefix(inner, "block "),
			strings.HasPrefix(inner, "define "):
			r.Unsupported = append(r.Unsupported, includeAdvice(m))
			return ""
		case strings.HasPrefix(inner, "$"), strings.Contains(inner, ":="):
			r.Unsupported = append(r.Unsupported, assignAdvice(m))
			return ""
		case strings.HasPrefix(inner, "else"):
			r.Unsupported = append(r.Unsupported, elseAdvice(m))
			return "{% end %}{% if TODO_else %}"
		default:
			return "{{ " + hugoPath(inner) + " }}"
		}
	})
}

// hugoPath maps a Go template path onto this context.
func hugoPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "$")
	switch {
	case s == ".", s == "":
		return "item"
	case strings.HasPrefix(s, ".Site.Title"):
		return "site.name"
	case strings.HasPrefix(s, ".Site."):
		return "site." + lowerFirst(strings.TrimPrefix(s, ".Site."))
	case strings.HasPrefix(s, ".Params."):
		return "page." + lowerFirst(strings.TrimPrefix(s, ".Params."))
	case strings.HasPrefix(s, "."):
		return "page." + lowerFirst(strings.TrimPrefix(s, "."))
	}
	return s
}

func lowerFirst(s string) string {
	parts := strings.Split(s, ".")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToLower(p[:1]) + p[1:]
	}
	return strings.Join(parts, ".")
}

// convertStatements rewrites the {% %} family.
//
// # Why this keeps a stack instead of replacing each tag independently
//
// A regex pass over the tags reads each one alone, and that is wrong for exactly
// the constructs Twig and Jinja templates are built out of. {% block content %}
// has no equivalent here, so it is dropped — and its {% endblock %} then becomes
// an {% end %} with nothing open, which does not parse. The template is refused
// as a whole, and the message names a line that is not the problem.
//
// So the openers are tracked. A closer emits {% end %} when the block it closes
// emitted something, and disappears when the block it closes disappeared. Found
// by adopting a real Twig layout: the conversion reported four constructs
// correctly and produced a file that could not be parsed.
func (r *Result) convertStatements(src string) string {
	var out strings.Builder
	// opened records, for each block still open, whether its opening tag
	// produced a construct in the output.
	var opened []bool
	pos := 0

	for _, m := range reStmt.FindAllStringSubmatchIndex(src, -1) {
		out.WriteString(src[pos:m[0]])
		pos = m[1]

		whole := src[m[0]:m[1]]
		inner := strings.TrimSpace(src[m[2]:m[3]])
		head, rest, _ := strings.Cut(inner, " ")
		head = strings.ToLower(strings.TrimSpace(head))
		rest = strings.TrimSpace(rest)

		switch head {
		case "if":
			out.WriteString("{% if " + r.condition(rest, whole) + " %}")
			opened = append(opened, true)
		case "for":
			out.WriteString(r.forStatement(rest, whole))
			opened = append(opened, true)
		case "unless":
			r.Unsupported = append(r.Unsupported, fmt.Sprintf(
				"%s has no equivalent: there is no negation, because a "+
					"condition that can be inverted can be computed instead. "+
					"The renderer derives the common negations (`unlinked`, "+
					"`no_image`, `no_slug`); for anything else put the boolean "+
					"on the content", excerpt(whole)))
			out.WriteString("{% if TODO_unless %}")
			opened = append(opened, true)

		case "endif", "endfor", "endunless", "endwith", "endblock",
			"endcomment", "endraw", "endcapture", "endverbatim", "endembed",
			"endapply", "endautoescape", "endspaceless", "end":
			// Close whatever this closes, in the form that block took. A closer
			// with nothing open is left out rather than emitted: the source was
			// already unbalanced, and adding an {% end %} would turn somebody
			// else's bug into a parse failure attributed to this converter.
			if len(opened) == 0 {
				r.Changes = append(r.Changes, fmt.Sprintf(
					"%s closes a block that was never opened in the source, so "+
						"it was dropped", excerpt(whole)))
				break
			}
			emitted := opened[len(opened)-1]
			opened = opened[:len(opened)-1]
			if emitted {
				out.WriteString("{% end %}")
			}

		case "else", "elsif", "elif":
			r.Unsupported = append(r.Unsupported, elseAdvice(whole))
			// The open block is closed and a new one opened, so the stack depth
			// is unchanged and the output still balances.
			if len(opened) > 0 && opened[len(opened)-1] {
				out.WriteString("{% end %}{% if TODO_else %}")
			} else {
				out.WriteString("{% if TODO_else %}")
				if len(opened) > 0 {
					opened[len(opened)-1] = true
				}
			}

		case "block", "embed", "apply", "autoescape", "spaceless", "capture",
			"comment", "raw", "verbatim", "with":
			// Blocks with no equivalent. Dropped, and the stack remembers that
			// nothing was emitted so the matching closer also disappears.
			r.note(head, whole)
			opened = append(opened, false)

		case "include", "extends", "use", "import", "render", "section",
			"layout", "partial", "yield":
			r.Unsupported = append(r.Unsupported, includeAdvice(whole))
		case "assign", "set", "increment", "decrement", "let":
			r.Unsupported = append(r.Unsupported, assignAdvice(whole))
		case "cycle", "tablerow", "paginate", "form", "schema", "javascript",
			"stylesheet", "liquid", "echo":
			r.Unsupported = append(r.Unsupported, fmt.Sprintf(
				"%s is a platform tag with no equivalent here — it belongs to "+
					"the system this template came from, not to a template "+
					"language. Whatever it produced has to arrive as content",
				excerpt(whole)))
		default:
			r.Unsupported = append(r.Unsupported, fmt.Sprintf(
				"%s is not a construct this language has. It has four — a "+
					"value, if, for and raw — and no way to add a fifth",
				excerpt(whole)))
		}
	}
	out.WriteString(src[pos:])

	if len(opened) > 0 {
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"%d block(s) are left open at the end of the source, so it was "+
				"already unbalanced before anything was converted",
			len(opened)))
	}
	return out.String()
}

// note explains a block that is dropped along with its closing tag.
func (r *Result) note(head, whole string) {
	switch head {
	case "block", "embed":
		r.Unsupported = append(r.Unsupported, includeAdvice(whole))
	case "capture":
		r.Unsupported = append(r.Unsupported, assignAdvice(whole))
	case "raw", "verbatim":
		// Liquid's raw means "do not process what follows" — the opposite of
		// this language's raw, which means "do not escape this value". A
		// converter that passed the word through would silently turn a block of
		// literal text into an unescaped field.
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"%s was removed. In Liquid and Twig `raw` means do not process the "+
				"block; here {%% raw x %%} means emit one value without "+
				"escaping it. They are opposites, so this one is not "+
				"translated — if the block is literal text it can simply stay "+
				"as text", excerpt(whole)))
	case "comment":
		r.Changes = append(r.Changes,
			"a template comment was removed; HTML comments are kept")
	case "with":
		r.Changes = append(r.Changes, fmt.Sprintf(
			"%s was dropped: it shortens names inside a block and this "+
				"language does not, so the names inside it stay as they are",
			excerpt(whole)))
	default:
		r.Changes = append(r.Changes, fmt.Sprintf(
			"%s was dropped; it has no equivalent and nothing it wrapped was "+
				"changed", excerpt(whole)))
	}
}

// condition translates what a template tests.
//
// Only presence and truthiness translate, because that is all {% if %} does. A
// comparison is reported rather than approximated: `{% if price > 100 %}`
// rewritten as `{% if price %}` would render the block for every price, which is
// the kind of wrong that ships.
func (r *Result) condition(expr, original string) string {
	e := strings.TrimSpace(expr)
	for _, op := range []string{"==", "!=", ">=", "<=", " > ", " < ", " and ",
		" or ", " not ", "!", " contains ", " in "} {
		if !strings.Contains(e, op) {
			continue
		}
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"%s compares or combines values, and {%% if %%} only asks whether "+
				"one is present and truthy. Compute the answer where the "+
				"content is written — a field like `expensive` or `in_stock` — "+
				"and test that. It is the same argument as prices: the "+
				"language has no arithmetic on purpose", excerpt(original)))
		return "TODO_condition"
	}
	return qualify(e)
}

// forStatement translates a loop.
func (r *Result) forStatement(rest, original string) string {
	body := rest
	// Liquid modifiers: `for x in y limit: 3 offset: 2 reversed`.
	for _, modifier := range []string{" limit:", " offset:", " reversed"} {
		if i := strings.Index(body, modifier); i >= 0 {
			r.Changes = append(r.Changes, fmt.Sprintf(
				"%s was simplified: a loop here iterates a list as it stands. "+
					"`limit` is the `take` filter on the list, and order is "+
					"decided where the content or the listing is written",
				excerpt(original)))
			body = body[:i]
		}
	}
	name, subject, ok := strings.Cut(body, " in ")
	if !ok {
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"%s is a loop this converter could not read. The shape here is "+
				"{%% for item in list %%}", excerpt(original)))
		return "{% for item in TODO_list %}"
	}
	name = strings.TrimSpace(name)
	subject = qualify(strings.TrimSpace(subject))
	if strings.Contains(name, ".") || name == "" {
		name = "item"
	}
	if strings.Contains(subject, "..") {
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"%s loops over a numeric range. Loops here iterate data, never a "+
				"counter — which is what makes rendering terminate for every "+
				"input. A range has to be a list in the content",
			excerpt(original)))
		return "{% for " + name + " in TODO_list %}"
	}
	return "{% for " + name + " in " + subject + " %}"
}

// convertExpressions rewrites values and their filters.
func (r *Result) convertExpressions(src string) string {
	return reExpr.ReplaceAllStringFunc(src, func(m string) string {
		inner := strings.TrimSpace(reExpr.FindStringSubmatch(m)[1])
		if inner == "" {
			return ""
		}
		// A statement that an earlier pass already produced. Leaving it alone
		// matters: re-qualifying `{% if page.x %}` would produce page.page.x.
		if strings.HasPrefix(inner, "%") || strings.HasSuffix(inner, "%") {
			return m
		}
		parts := strings.Split(inner, "|")
		path := qualify(strings.TrimSpace(parts[0]))
		if path == "" {
			return ""
		}
		out := path
		for _, raw := range parts[1:] {
			f := strings.TrimSpace(raw)
			if f == "" {
				continue
			}
			name, arg, _ := strings.Cut(f, ":")
			name = strings.ToLower(strings.TrimSpace(name))
			arg = strings.Trim(strings.TrimSpace(arg), `"'`)
			// Some dialects separate a filter from its argument with a space.
			if arg == "" {
				if n, a, found := strings.Cut(name, " "); found {
					name, arg = strings.TrimSpace(n), strings.Trim(strings.TrimSpace(a), `"'`)
				}
			}
			if why, dropped := dropFilters[name]; dropped {
				r.Changes = append(r.Changes, fmt.Sprintf(
					"the %q filter was dropped from {{ %s }}: %s", name, inner, why))
				continue
			}
			mapped, known := filterMap[name]
			if !known {
				r.Unsupported = append(r.Unsupported, fmt.Sprintf(
					"{{ %s }} uses the %q filter, which this language does not "+
						"have. The filters are a closed list, each taking at "+
						"most one literal argument, so anything else has to be "+
						"computed where the content is written", inner, name))
				continue
			}
			if arg != "" {
				out += " | " + mapped + ":" + arg
			} else {
				out += " | " + mapped
			}
		}
		return "{{ " + out + " }}"
	})
}

// aliases map the names other platforms use onto the ones this context has.
//
// Small and specific on purpose. These are not guesses: {{ shop.name }} in a
// Shopify theme and {{ .Site.Title }} in a Hugo layout are both the site's name,
// and a converted template that read them as content would render a blank
// heading — which looks like a template that works and content that is empty.
var aliases = map[string]string{
	"shop.name":          "site.name",
	"site.title":         "site.name",
	"blog.title":         "site.name",
	"page_title":         "page.title",
	"page_description":   "page.description",
	"post.title":         "page.title",
	"content":            "page.body",
	"content_for_layout": "page.body",
	"the_title":          "page.title",
	"the_content":        "page.body",
}

// qualify points an unqualified name at the page.
//
// A foreign template says {{ title }} and means the page's title. Left alone
// that is a lookup that misses, and a miss renders as nothing — so the page
// would come out empty and look like a template problem rather than a naming
// one. Known roots and loop variables are left as they are.
func qualify(path string) string {
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, ".")
	if p == "" || strings.HasPrefix(p, "TODO_") {
		return p
	}
	// A literal, not a path. Left alone so a default filter's argument or a
	// quoted string survives unchanged.
	if strings.ContainsAny(p, `"'`) || !rePath.MatchString(p) {
		return p
	}
	if mapped, known := aliases[strings.ToLower(p)]; known {
		return mapped
	}
	root, _, _ := strings.Cut(p, ".")
	if roots[root] || loopVars[root] {
		return p
	}
	return "page." + p
}

// loopVars are the names this converter introduces for loop items, so a later
// pass does not prefix them with page.
var loopVars = map[string]bool{
	"item": true, "row": true, "entry": true, "f": true, "s": true,
}

// loopName picks a readable name for a loop variable.
func loopName(subject string, n int) string {
	base := subject
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(strings.TrimSuffix(base, "s"), "e")
	if base == "" || !rePath.MatchString(base) {
		if n > 1 {
			return fmt.Sprintf("item%d", n)
		}
		return "item"
	}
	name := strings.ToLower(base)
	loopVars[name] = true
	return name
}

func elseAdvice(what string) string {
	return fmt.Sprintf(
		"%s has no equivalent: an if here has one exit, so a template's shape "+
			"can be read off its source. Most elses become two sibling ifs — "+
			"{%% if x %%}…{%% end %%}{%% if x_missing %%}…{%% end %%} — and the "+
			"renderer already derives the common negations, so a card with an "+
			"href tests `href` and one without tests `unlinked`. Where the two "+
			"branches are genuinely different content, that is a field",
		excerpt(what))
}

func includeAdvice(what string) string {
	return fmt.Sprintf(
		"%s cannot be converted: there are no partials, includes or "+
			"inheritance, because each of those resolves a name at render time "+
			"and this language resolves nothing at render time. Two things "+
			"replace them — a layout of its own, which a page names in its "+
			"`layout` field, and a section kind in the sections layout, which "+
			"is one block chosen by the content", excerpt(what))
}

func assignAdvice(what string) string {
	return fmt.Sprintf(
		"%s cannot be converted: there is no assignment. A value a template "+
			"would have computed belongs in the content, written when the "+
			"content is written — which is also what makes it reviewable and "+
			"what puts it in the audit trail", excerpt(what))
}

// checkDocument reports the things a layout needs and this one lacks.
func (r *Result) checkDocument(src string) {
	low := strings.ToLower(src)
	if !strings.Contains(low, "<html") {
		r.Changes = append(r.Changes,
			"this is a fragment rather than a whole document. A layout has to "+
				"be the whole page: <!doctype html>, <html lang>, <head> with "+
				"a <title>, and a <body>")
		return
	}
	if !strings.Contains(low, "lang=") {
		r.Unsupported = append(r.Unsupported,
			"the <html> element has no lang attribute. The publish gate refuses "+
				"a page without one, because a screen reader has no way to "+
				"choose a voice for text in an unnamed language (WCAG 3.1.1)")
	}
	if !strings.Contains(low, "<title") {
		r.Unsupported = append(r.Unsupported,
			"there is no <title>. It is the first thing announced and the gate "+
				"refuses a page without one (WCAG 2.4.2)")
	}
	if !strings.Contains(low, "/site.css") {
		r.Changes = append(r.Changes,
			"nothing links /site.css, so this layout will render without the "+
				"theme or the components. Add "+
				`<link rel="stylesheet" href="/site.css"> to the head`)
	}
	if strings.Contains(low, "<img") && !strings.Contains(low, "alt=") {
		r.Unsupported = append(r.Unsupported,
			"an <img> has no alt attribute. The gate refuses that — use alt=\"\" "+
				"if the image is decorative, or read the text from a field "+
				"beside the image (WCAG 1.1.1)")
	}
	if !strings.Contains(low, "skip") && strings.Contains(low, "<nav") {
		r.Changes = append(r.Changes,
			"there is no skip link. Every shipped layout starts with "+
				`<a class="skip" href="#main">Skip to main content</a>, which `+
				"is how a keyboard user gets past the navigation on every page")
	}
}

// fieldsRead lists the content keys the converted template reads.
func fieldsRead(src string) []string {
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`page\.([A-Za-z][A-Za-z0-9_]*)`).
		FindAllStringSubmatch(src, -1) {
		seen[m[1]] = true
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// excerpt shortens a construct for a message, on one line.
func excerpt(s string) string {
	flat := strings.Join(strings.Fields(s), " ")
	if len(flat) > 90 {
		flat = flat[:90] + "…"
	}
	return "`" + flat + "`"
}
