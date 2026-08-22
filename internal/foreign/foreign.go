// Package foreign converts a template written for another system into one this
// renderer can run.
//
// # Why this exists
//
// Everything else in this program is built so that a template cannot execute.
// That is worth a great deal and it costs one thing: nobody's existing template
// works here. A studio with a Liquid theme, an agency with fifty Twig files, a
// developer with a Hugo layout they like — all of them are told to start again,
// and starting again is the reason people do not move.
//
// So the language stays as small as it is and the conversion happens once, in
// front of it, with a report. This is not a compatibility layer: nothing here
// runs at render time, there is no interpreter for anybody else's dialect, and
// the output is ordinary Quilzo markup somebody can read. It is a translation,
// and like every translation it is lossy in places — which is why the losses are
// printed rather than absorbed.
//
// # Why the report is the product
//
// The dangerous version of this feature is the one that succeeds quietly. A
// converter that drops an {% else %} and says nothing produces a template that
// renders the wrong half of every conditional, and the person who ran it has no
// reason to look. So every construct that could not be translated is named, with
// the shape it should become, and by default the layout is not written at all
// while any remain. Refuse rather than warn, applied to an import.
//
// # What is removed rather than translated
//
// Script, event handlers and executable URLs are removed unconditionally. They
// are not features this renderer lacks — they are the vulnerability class this
// program is built to not have, arriving inside a file somebody downloaded. A
// converted template that kept them would be the supply chain the embedded
// starters exist to avoid, reintroduced through a different door.
//
// External origins are reported and left alone. An <img> pointing at a CDN is
// somebody's real content decision, not an attack, and the policy this program
// builds from content is where that gets settled — so the honest move is to say
// which hosts a page will need and let the operator decide, rather than silently
// breaking their images or silently widening their policy.
package foreign

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Result is a conversion and everything that happened during it.
type Result struct {
	// Dialect is what the source appeared to be written for.
	Dialect string `json:"dialect"`
	// Template is the converted markup.
	Template string `json:"template"`
	// Changes are translations that succeeded but are worth knowing about.
	Changes []string `json:"changes,omitempty"`
	// Removed are things taken out because they cannot exist here.
	Removed []string `json:"removed,omitempty"`
	// Unsupported are constructs with no equivalent, each naming the shape it
	// should become. While any remain, the layout is not written by default.
	Unsupported []string `json:"unsupported,omitempty"`
	// Fields are the content keys the converted template reads, so somebody can
	// see what a page has to carry before they publish one.
	Fields []string `json:"fields,omitempty"`
}

// roots are the names the render context actually has. An unqualified variable
// that is not one of these is content, so it is prefixed with page — which is
// what makes a converted template read from somewhere real instead of from a
// name that resolves to nothing and renders a gap.
var roots = map[string]bool{
	"page": true, "site": true, "menus": true, "listings": true,
	"feeds": true, "record": true,
}

// filterMap translates the filters other dialects spell differently.
//
// Only the ones that mean the same thing. A filter that almost matches is worse
// than one that does not: `escape` in Liquid is a no-op here because everything
// is escaped already, and mapping it to something would imply the escaping is
// optional.
var filterMap = map[string]string{
	"upcase": "upper", "upper": "upper", "uppercase": "upper",
	"downcase": "lower", "lower": "lower", "lowercase": "lower",
	"capitalize": "title", "title": "title", "titlecase": "title",
	"strip": "trim", "trim": "trim",
	"truncate": "truncate", "truncatewords": "truncate",
	"date": "date", "date_to_string": "date",
	"slugify": "slug", "slug": "slug", "urlize": "slug",
	"join": "join", "size": "count", "length": "count", "count": "count",
	"first": "first", "last": "last", "sort": "sort",
	"default": "default", "replace": "replace", "round": "round",
	"limit": "take", "take": "take",
}

// dropFilters are filters that exist because the other system does not escape
// by default. Dropping them is correct and worth saying: somebody reading the
// converted file should not think the escaping went with them.
var dropFilters = map[string]string{
	"escape":      "everything is escaped here, in the context it lands in",
	"e":           "everything is escaped here, in the context it lands in",
	"escape_once": "everything is escaped here, in the context it lands in",
	"safe":        "there is no way to mark a value safe; use {% raw %} deliberately if the field really is markup",
	"raw":         "there is no way to mark a value safe; use {% raw %} deliberately if the field really is markup",
	"striptags":   "tags in a value are escaped rather than executed, so there is nothing to strip",
	"h":           "everything is escaped here, in the context it lands in",
}

// LayoutNameFor turns a filename into a usable layout name.
func LayoutNameFor(path string) string {
	base := filepath.Base(path)
	for _, ext := range []string{".html", ".htm", ".liquid", ".twig", ".jinja",
		".jinja2", ".j2", ".hbs", ".handlebars", ".mustache", ".erb", ".ejs",
		".njk", ".tmpl", ".gohtml", ".php"} {
		base = strings.TrimSuffix(base, ext)
	}
	var b strings.Builder
	lastHyphen := true
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastHyphen = false
		case !lastHyphen:
			b.WriteRune('-')
			lastHyphen = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" || out[0] < 'a' || out[0] > 'z' {
		return "adopted"
	}
	return out
}

// Adopt converts a template.
//
// The order is deliberate: dangerous markup is removed first, so nothing later
// can be fooled into translating it into something that survives; then the
// dialect's own constructs; then the value expressions, which is the only step
// that needs to know what a variable means.
func Adopt(src string) *Result {
	r := &Result{Dialect: detect(src)}
	out := src

	out = r.stripExecutable(out)
	out = r.stripScript(out)
	out = r.stripHandlers(out)
	out = r.neutraliseURLs(out)
	out = r.noteExternal(out)
	out = r.noteFrames(out)
	out = r.noteInlineStyle(out)

	out = r.convertHandlebars(out)
	out = r.convertGoTemplate(out)
	out = r.convertStatements(out)
	out = r.convertExpressions(out)

	r.checkDocument(out)
	r.Fields = fieldsRead(out)

	r.Template = out
	sort.Strings(r.Fields)
	return r
}

// detect names the dialect, which decides which conversions run and is worth
// reporting even when it changes nothing: somebody adopting a Handlebars file
// that was detected as Liquid has found a bug, and they can only find it if the
// guess is printed.
func detect(src string) string {
	switch {
	case strings.Contains(src, "<?php"), strings.Contains(src, "<?="):
		return "PHP"
	case reERB.MatchString(src):
		return "ERB or EJS"
	case strings.Contains(src, "{{#if"), strings.Contains(src, "{{#each"),
		strings.Contains(src, "{{/if"), strings.Contains(src, "{{/each"):
		return "Handlebars or Mustache"
	case reGoAction.MatchString(src):
		return "Go template or Hugo"
	case strings.Contains(src, "{% extends"), strings.Contains(src, "{% block"):
		return "Twig, Jinja or Django"
	case strings.Contains(src, "{% assign"), strings.Contains(src, "{% endunless"),
		strings.Contains(src, "{{ content }}"):
		return "Liquid"
	case strings.Contains(src, "{%"):
		return "Liquid, Twig or Jinja"
	case strings.Contains(src, "{{"):
		return "Mustache-style"
	default:
		return "plain HTML"
	}
}

var (
	rePHP        = regexp.MustCompile(`(?s)<\?(?:php|=).*?(?:\?>|$)`)
	reERB        = regexp.MustCompile(`<%[-=#]?[\s\S]*?%>`)
	reScript     = regexp.MustCompile(`(?is)<script\b[^>]*>[\s\S]*?</script\s*>`)
	reScriptOpen = regexp.MustCompile(`(?is)<script\b[^>]*/?>`)
	reGoAction   = regexp.MustCompile(`\{\{-?\s*(?:if|range|end|with|block|template|define|partial)\b`)
	// One pattern per tag: RE2 has no backreferences, which is what keeps
	// matching linear in the input — so the pairing is written out rather than
	// referred to.
	reFrames = []*regexp.Regexp{
		regexp.MustCompile(`(?is)<iframe\b[^>]*>(?:[\s\S]*?</iframe\s*>)?`),
		regexp.MustCompile(`(?is)<object\b[^>]*>(?:[\s\S]*?</object\s*>)?`),
		regexp.MustCompile(`(?is)<embed\b[^>]*/?>`),
	}
	reStyleTag = regexp.MustCompile(`(?is)<style\b[^>]*>[\s\S]*?</style\s*>`)
	reHandler  = regexp.MustCompile(`(?is)\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)`)
	reJSURL    = regexp.MustCompile(`(?is)((?:href|src|action|formaction|xlink:href)\s*=\s*["']?)\s*(?:javascript|vbscript|data)\s*:[^"'\s>]*`)
	// A subresource from another origin, which the policy will not permit.
	reExternalStyle = regexp.MustCompile(
		`(?is)<link\b[^>]*\b(?:rel\s*=\s*["']?(?:stylesheet|preload|prefetch|preconnect)[^>]*href|href)\s*=\s*["']?(?:https?:)?//[^>]*>`)
	// Media, which is left alone and reported. Only src, never href: an
	// ordinary outbound link is a link.
	reExternalSrc = regexp.MustCompile(`(?is)\b(src|poster|srcset)\s*=\s*["']?((?:https?:)?//[^"'\s>]+)`)
	reInlineCSS   = regexp.MustCompile(`(?is)\sstyle\s*=\s*["'][^"']*["']`)
)

// stripExecutable removes server-side code.
//
// Not converted, because there is nothing to convert it to: a PHP block or an
// ERB tag is a program, and the whole basis of this renderer is that a template
// is not one. Removing it leaves a hole somebody has to fill with a field, which
// is the correct amount of work — the alternative is a template that looks
// converted and silently lost its logic.
func (r *Result) stripExecutable(src string) string {
	out := rePHP.ReplaceAllStringFunc(src, func(m string) string {
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"a PHP block was removed: %s. There is no way to run code in a "+
				"template here. Whatever it produced has to arrive as a field "+
				"on the page, computed before the render", excerpt(m)))
		return ""
	})
	out = reERB.ReplaceAllStringFunc(out, func(m string) string {
		r.Unsupported = append(r.Unsupported, fmt.Sprintf(
			"an ERB or EJS tag was removed: %s. Same reason: it is code. A "+
				"value belongs in the content; a loop or a condition maps to "+
				"{%% for %%} or {%% if %%}", excerpt(m)))
		return ""
	})
	return out
}

// stripScript removes script elements.
func (r *Result) stripScript(src string) string {
	out := reScript.ReplaceAllStringFunc(src, func(m string) string {
		r.Removed = append(r.Removed, fmt.Sprintf(
			"a <script> element was removed: %s. The policy this program builds "+
				"is script-src 'none' for a site that has no scripts, and a "+
				"published page that runs script is the half of the "+
				"vulnerability class this design exists without", excerpt(m)))
		return ""
	})
	out = reScriptOpen.ReplaceAllStringFunc(out, func(m string) string {
		r.Removed = append(r.Removed, fmt.Sprintf(
			"a script reference was removed: %s", excerpt(m)))
		return ""
	})
	return out
}

// stripHandlers removes inline event handlers.
func (r *Result) stripHandlers(src string) string {
	return reHandler.ReplaceAllStringFunc(src, func(m string) string {
		r.Removed = append(r.Removed, fmt.Sprintf(
			"an event handler was removed:%s. Interaction here is CSS: "+
				"details/summary for a disclosure, :has() and :target for "+
				"state, @view-transition for navigation", excerpt(m)))
		return ""
	})
}

// neutraliseURLs removes executable URL schemes.
func (r *Result) neutraliseURLs(src string) string {
	return reJSURL.ReplaceAllStringFunc(src, func(m string) string {
		r.Removed = append(r.Removed, fmt.Sprintf(
			"an executable URL was removed: %s. javascript:, vbscript: and "+
				"data: are the three that turn a link into script", excerpt(m)))
		// The attribute is kept and emptied rather than deleted, so the markup
		// stays well-formed and the hole is visible where it was.
		i := strings.IndexAny(m, `"'`)
		if i < 0 {
			return `href="#"`
		}
		return m[:i+1]
	})
}

// noteExternal handles references to other origins, which divide in three.
//
// A stylesheet, a font or a preload from another host is removed. Not as a
// policy judgement — the policy this program builds is style-src 'self' and
// font-src 'self', so the browser would refuse to load it and the page would
// render with its design missing and nothing in the output saying why. Removing
// it and reporting it is the same outcome, arrived at where somebody can read it.
//
// An image, a video or an audio file is left exactly as it is and reported. That
// is somebody's real content decision rather than an attack, and the policy is
// built from what the content references — so the honest move is to name the
// host and let the operator add it, instead of silently breaking the picture or
// silently widening the directive.
//
// An ordinary link to another site is not mentioned at all. It is a link. A
// converter that reported every outbound href would bury the two findings that
// matter under fifty that do not.
func (r *Result) noteExternal(src string) string {
	out := reExternalStyle.ReplaceAllStringFunc(src, func(m string) string {
		host := hostOf(hrefIn(m))
		if host == "" {
			return m
		}
		r.Removed = append(r.Removed, fmt.Sprintf(
			"a stylesheet or font from %s was removed: %s. The policy this "+
				"program builds is style-src 'self' and font-src 'self', so a "+
				"browser would refuse it and the page would render with its "+
				"design missing. A typeface belongs in templates/fonts, where "+
				"this origin serves it; colours and type belong in the theme",
			host, excerpt(m)))
		return ""
	})

	seen := map[string]bool{}
	for _, m := range reExternalSrc.FindAllStringSubmatch(out, -1) {
		host := hostOf(m[2])
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		r.Changes = append(r.Changes, fmt.Sprintf(
			"this template loads media from %s and it was left alone. The "+
				"policy names only the hosts your content uses, so either add "+
				"it — `quilzo config set site.csp.extra_img %s` — or put the "+
				"file in the media library and point at /media/, which needs "+
				"no exception at all", host, host))
	}
	return out
}

// hrefIn pulls the URL out of one tag, for the message.
func hrefIn(tag string) string {
	for _, attr := range []string{"href", "src"} {
		i := indexFold(tag, attr+"=")
		if i < 0 {
			continue
		}
		rest := strings.TrimSpace(tag[i+len(attr)+1:])
		if rest == "" {
			continue
		}
		if rest[0] == '"' || rest[0] == '\'' {
			quote := rest[0]
			if end := strings.IndexByte(rest[1:], quote); end >= 0 {
				return rest[1 : 1+end]
			}
			continue
		}
		value, _, _ := strings.Cut(rest, " ")
		return strings.TrimSuffix(value, ">")
	}
	return ""
}

func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sub))
}

// noteFrames removes embedded documents.
func (r *Result) noteFrames(src string) string {
	out := src
	for _, re := range reFrames {
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			r.Unsupported = append(r.Unsupported, fmt.Sprintf(
				"an embedded document was removed: %s. A frame needs a "+
					"frame-src host in the policy, which is built from what "+
					"the content references rather than from the template — "+
					"so put the URL in a field and let the policy see it",
				excerpt(m)))
			return ""
		})
	}
	return out
}

// noteInlineStyle keeps inline CSS and says where it ought to live.
func (r *Result) noteInlineStyle(src string) string {
	if blocks := reStyleTag.FindAllString(src, -1); len(blocks) > 0 {
		r.Changes = append(r.Changes, fmt.Sprintf(
			"%d inline <style> block(s) were kept. They work — the policy "+
				"permits inline styles — but a colour written here is outside "+
				"the theme, so it is not covered by the contrast check that "+
				"refuses an unreadable palette. Moving the colours to "+
				"templates/theme.json puts them back inside it", len(blocks)))
	}
	if attrs := reInlineCSS.FindAllString(src, -1); len(attrs) > 8 {
		r.Changes = append(r.Changes, fmt.Sprintf(
			"%d style attributes were kept. Where one interpolates a value, "+
				"put the value through a numeric filter — style=\"--pct:{{ x | "+
				"round }}\" — because HTML escaping is not CSS escaping and "+
				"`round` refuses anything that is not a number", len(attrs)))
	}
	return src
}

// hostOf reads the host out of a reference, protocol-relative or absolute.
//
// Parsed by hand rather than with net/url because a template's attribute is not
// necessarily a valid URL — it often has a template expression in the middle of
// it — and a parse error would drop a reference that is really there.
func hostOf(ref string) string {
	s := strings.TrimSpace(ref)
	for _, prefix := range []string{"https://", "http://", "//"} {
		if rest, found := strings.CutPrefix(s, prefix); found {
			host, _, _ := strings.Cut(rest, "/")
			host, _, _ = strings.Cut(host, "?")
			host, _, _ = strings.Cut(host, "{")
			if strings.ContainsAny(host, " \"'<>") {
				return ""
			}
			return strings.ToLower(host)
		}
	}
	return ""
}
