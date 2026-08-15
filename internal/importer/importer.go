// Package importer brings content in from other systems.
//
// # XML, and the bug this does not have
//
// WordPress exports are XML, and XML import is where CMS platforms get hurt.
// CVE-2021-29447 was XXE reached through WordPress parsing the ID3 tag of an
// uploaded audio file; WordPress 5.7 had another. The standard mitigation is a
// one-line parser setting that disables external entity resolution, which works
// exactly as long as nobody forgets it in the next parser they add.
//
// Go's encoding/xml does not process DTD entity declarations at all. A document
// declaring <!ENTITY xxe SYSTEM "file:///etc/passwd"> and referencing &xxe;
// fails with "invalid character entity" — the reference is never resolved
// because the declaration was never read. The same is true of the billion
// laughs expansion. This is verified in the tests rather than assumed, because
// "the standard library is safe" is the kind of belief that survives the
// library changing.
//
// So there is no setting to forget here. The capability is absent.
//
// # HTML arrives as text
//
// A WordPress post body is HTML. The template engine escapes everything it
// emits, which means imported markup would render as visible angle brackets —
// so the choice is to strip it to text or to route it through `raw`, and `raw`
// on content from another system is trusting a database somebody else
// administered.
//
// Tags are stripped, links and images are pulled out into their own fields, and
// the report says how much was dropped. Lossy and visible beats faithful and
// dangerous: an import that silently produces a page full of markup is one
// people fix by reaching for raw.
//
// # Nothing is fetched during an import
//
// A WordPress export names attachment URLs. Following them would make importing
// a file somebody sent you into a request from inside your network to a host
// they chose — server-side request forgery with an import button. So the URLs
// are collected and reported, and pulling them down is a separate, explicit
// step through the fetch package, which validates at connect time.
package importer

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/seo"
)

// Source is a format that can be imported.
type Source string

const (
	// WordPress WXR, which Drupal and several others can also produce.
	WordPress Source = "wordpress"
	// Markdown with front matter: Jekyll, Hugo, Eleventy, Astro.
	Markdown Source = "markdown"
	// A JSON array or object of pages, for headless systems.
	JSON Source = "json"
)

// MaxBytes bounds an import. A document larger than this is not an export, it
// is a way to exhaust memory during parsing.
const MaxBytes = 256 << 20

// MaxPages bounds how many pages one import may create.
const MaxPages = 20000

// Page is one imported page, in scrivet's own shape.
type Page struct {
	Name    string         `json:"name"`
	Fields  map[string]any `json:"fields"`
	Dropped []string       `json:"dropped,omitempty"`
}

// Report is what an import produced and, as importantly, what it did not.
type Report struct {
	Source Source `json:"source"`
	Pages  []Page `json:"pages"`
	// Media are URLs referenced by the imported content. Collected, never
	// fetched: following them during an import turns a file somebody sent you
	// into a request from inside your network to a host they chose.
	Media []string `json:"media,omitempty"`
	// Skipped records what was not imported and why. An importer that quietly
	// drops half an export is worse than one that refuses, because the loss is
	// discovered months later by a reader.
	Skipped []string `json:"skipped,omitempty"`
	// Notes are things the operator has to decide about.
	Notes []string `json:"notes,omitempty"`
	// Redirects map every URL the content had in the old system to its new
	// path. This is the artefact that decides whether a migration keeps its
	// search rankings, and the export already contains everything needed to
	// build it — so leaving it to be typed by hand afterwards is leaving the
	// most valuable output on the floor.
	Redirects []seo.Redirect `json:"redirects,omitempty"`
}

// Import reads an export and returns pages.
func Import(src Source, r io.Reader, now time.Time) (*Report, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > MaxBytes {
		return nil, fmt.Errorf("the export is larger than %d bytes", MaxBytes)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("the export is empty")
	}

	switch src {
	case WordPress:
		return importWXR(body, now)
	case Markdown:
		return importMarkdown(body, now)
	case JSON:
		return importJSON(body, now)
	}
	return nil, fmt.Errorf("unknown source %q; try wordpress, markdown or json", src)
}

// Detect guesses the format from the bytes, so the common case needs no flag.
func Detect(body []byte) (Source, bool) {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	s := string(head)
	switch {
	case strings.Contains(s, "<rss") && strings.Contains(s, "wp:"):
		return WordPress, true
	case strings.HasPrefix(strings.TrimSpace(s), "---"):
		return Markdown, true
	case strings.HasPrefix(strings.TrimSpace(s), "{"),
		strings.HasPrefix(strings.TrimSpace(s), "["):
		return JSON, true
	}
	return "", false
}

// -- WordPress ---------------------------------------------------------------

type wxr struct {
	Channel struct {
		Title string    `xml:"title"`
		Items []wxrItem `xml:"item"`
	} `xml:"channel"`
}

type wxrItem struct {
	Title    string `xml:"title"`
	Link     string `xml:"link"`
	PostName string `xml:"post_name"`
	PostType string `xml:"post_type"`
	Status   string `xml:"status"`
	PostDate string `xml:"post_date"`
	Creator  string `xml:"creator"`
	// Namespaced explicitly. WXR has both content:encoded and excerpt:encoded,
	// and an unqualified `encoded` tag matches whichever appears first — which
	// silently imports excerpts as bodies on exports that order them the other
	// way.
	Content    string `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
	Excerpt    string `xml:"http://wordpress.org/export/1.2/excerpt/ encoded"`
	AttachURL  string `xml:"attachment_url"`
	Categories []struct {
		Domain string `xml:"domain,attr"`
		Value  string `xml:",chardata"`
	} `xml:"category"`
}

func importWXR(body []byte, now time.Time) (*Report, error) {
	rep := &Report{Source: WordPress}

	var doc wxr
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	// Strict is the default and stays on. It is what makes an undeclared entity
	// an error rather than something passed through as literal text — and a
	// parser that passes &xxe; through is a parser handing the payload to
	// whatever reads its output next.
	dec.Strict = true
	if err := dec.Decode(&doc); err != nil {
		if strings.Contains(err.Error(), "invalid character entity") {
			return nil, fmt.Errorf("the export declares XML entities, which are "+
				"not resolved here. If this file is a legitimate export, the "+
				"entities are being used for text and can be replaced; if it is "+
				"not, this is the attack that has hit WordPress twice: %w", err)
		}
		return nil, fmt.Errorf("this does not parse as a WordPress export: %w", err)
	}

	seen := map[string]bool{}
	unchanged := 0
	for _, item := range doc.Channel.Items {
		if len(rep.Pages) >= MaxPages {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf(
				"stopped at %d pages, which is the limit", MaxPages))
			break
		}
		// Attachments are references, not pages. Their URLs are collected so
		// the operator can decide whether to pull them down.
		if item.PostType == "attachment" {
			if item.AttachURL != "" {
				rep.Media = append(rep.Media, item.AttachURL)
			}
			continue
		}
		switch item.PostType {
		case "nav_menu_item", "revision", "custom_css", "customize_changeset",
			"wp_global_styles", "wp_template", "wp_template_part", "wp_block":
			rep.Skipped = append(rep.Skipped, fmt.Sprintf(
				"%q (%s) — a WordPress internal, not content", item.Title, item.PostType))
			continue
		}
		if item.Status == "trash" {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf(
				"%q — in the trash", item.Title))
			continue
		}

		name := slug(item.PostName)
		if name == "" {
			name = slug(item.Title)
		}
		if name == "" {
			rep.Skipped = append(rep.Skipped, "an item with no title or slug")
			continue
		}
		for n := 2; seen[name]; n++ {
			name = fmt.Sprintf("%s-%d", name, n)
		}
		seen[name] = true

		text, links, images, dropped := flattenHTML(item.Content)
		rep.Media = append(rep.Media, images...)

		fields := map[string]any{
			"title": strings.TrimSpace(item.Title),
			"body":  text,
			"slug":  name,
		}
		if d := wpDate(item.PostDate); d != "" {
			fields["published"] = d
		}
		if item.Creator != "" {
			fields["byline"] = item.Creator
		}
		if len(links) > 0 {
			fields["links"] = links
		}
		var tags []any
		for _, c := range item.Categories {
			if v := strings.TrimSpace(c.Value); v != "" {
				tags = append(tags, v)
			}
		}
		if len(tags) > 0 {
			fields["tags"] = tags
		}
		if item.Status != "publish" {
			fields["status"] = "draft"
		}

		rep.Pages = append(rep.Pages, Page{Name: name, Fields: fields, Dropped: dropped})

		// The old URL, so the link somebody published in 2019 still resolves.
		// Permanent, because the content genuinely moved and a temporary
		// redirect does not transfer ranking.
		//
		// Pages whose path is unchanged are skipped rather than emitted. Most
		// of them are: WordPress serves /about-us/ and this serves /about-us,
		// which is the same place. Emitting those as redirects would make every
		// real import produce a map full of self-references, and NewMap refuses
		// those — correctly, since a page redirecting to itself is a loop. The
		// first version did exactly that and generated no redirects at all.
		if item.Link != "" {
			if from, err := seo.SourcePath(item.Link); err == nil {
				if from != "/"+name {
					rep.Redirects = append(rep.Redirects, seo.Redirect{
						From: item.Link, To: "/" + name, Permanent: true,
						Note: "imported from WordPress",
					})
				} else {
					unchanged++
				}
			}
		}
	}

	if unchanged > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%d page(s) kept the same path, so they need no redirect.", unchanged))
	}

	// Validated here rather than at write time, so a contradictory or looping
	// map is a failed import instead of a site that redirects in circles.
	if len(rep.Redirects) > 0 {
		m, err := seo.NewMap(rep.Redirects)
		if err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf(
				"the old URLs could not be turned into a redirect map (%v), so "+
					"no redirects were generated. Existing links to this "+
					"content will break.", err))
			rep.Redirects = nil
		} else {
			rep.Redirects = m.Redirects
			rep.Notes = append(rep.Notes, fmt.Sprintf(
				"%d redirects were generated from the old URLs, so links "+
					"published before the migration keep working. Google asks "+
					"for at least a year, and there is rarely a reason to "+
					"remove them.",
				len(rep.Redirects)))
		}
	}

	rep.Media = dedupe(rep.Media)
	if len(rep.Media) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"%d media URLs were found and NOT downloaded. Fetching them during "+
				"an import would make this file a way to make requests from "+
				"inside your network. Fetch the ones you want with "+
				"`scrivet media get <url>`, which validates the address at "+
				"connect time rather than before it.",
			len(rep.Media)))
	}
	if len(rep.Pages) == 0 {
		return nil, fmt.Errorf("no importable content found; %d items were skipped",
			len(rep.Skipped))
	}
	return rep, nil
}

func wpDate(s string) string {
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' {
		if s[:10] == "0000-00-00" {
			return ""
		}
		return s[:10]
	}
	return ""
}

// -- Markdown ----------------------------------------------------------------

func importMarkdown(body []byte, now time.Time) (*Report, error) {
	rep := &Report{Source: Markdown}
	text := string(body)

	fields := map[string]any{}
	rest := text

	// YAML front matter, but only the flat key: value subset. A full YAML
	// parser is a large attack surface — anchors and aliases give a billion
	// laughs equivalent, and several parsers construct arbitrary types from
	// tags. Front matter in practice is flat keys, so that is all that is read
	// and anything else is reported rather than guessed at.
	if strings.HasPrefix(strings.TrimSpace(text), "---") {
		trimmed := strings.TrimSpace(text)
		if end := strings.Index(trimmed[3:], "\n---"); end >= 0 {
			front := trimmed[3 : 3+end]
			rest = strings.TrimSpace(trimmed[3+end+4:])
			for i, line := range strings.Split(front, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "*") {
					rep.Skipped = append(rep.Skipped, fmt.Sprintf(
						"front matter line %d is a list item; only flat "+
							"key: value pairs are read", i+1))
					continue
				}
				key, value, ok := strings.Cut(line, ":")
				if !ok {
					rep.Skipped = append(rep.Skipped, fmt.Sprintf(
						"front matter line %d is not key: value", i+1))
					continue
				}
				key = strings.TrimSpace(key)
				value = strings.TrimSpace(value)

				// Quoting is decided before anything else, because it decides
				// everything else. A quoted scalar cannot be an anchor, an
				// alias or a tag whatever it starts with — and the previous
				// version stripped the quotes first and then judged the
				// contents, so a legitimately quoted "&notreal" was refused as
				// an anchor. That is not a theoretical case: it is what this
				// tool's own exporter writes, since quoting everything is what
				// stops YAML reinterpreting `no` as false.
				if quoted, ok := unquoteYAML(value); ok {
					if key != "" {
						fields[key] = quoted
					}
					continue
				}

				if strings.HasPrefix(value, "&") || strings.HasPrefix(value, "*") ||
					strings.HasPrefix(value, "!") {
					// Anchors, aliases and tags, unquoted. Refused rather than
					// interpreted, since interpreting them is the whole class
					// of YAML deserialisation bugs.
					rep.Skipped = append(rep.Skipped, fmt.Sprintf(
						"front matter key %q uses a YAML anchor, alias or tag, "+
							"which are not interpreted", key))
					continue
				}
				if key != "" && value != "" {
					fields[key] = value
				}
			}
		}
	}

	if fields["title"] == nil {
		// The first heading, if the front matter had none.
		for _, line := range strings.Split(rest, "\n") {
			if t, ok := strings.CutPrefix(strings.TrimSpace(line), "# "); ok {
				fields["title"] = strings.TrimSpace(t)
				break
			}
		}
	}
	fields["body"] = rest

	name := slug(str(fields["slug"]))
	if name == "" {
		name = slug(str(fields["title"]))
	}
	if name == "" {
		name = "imported"
	}
	fields["slug"] = name

	rep.Pages = []Page{{Name: name, Fields: fields}}
	return rep, nil
}

// -- JSON --------------------------------------------------------------------

func importJSON(body []byte, now time.Time) (*Report, error) {
	rep := &Report{Source: JSON}

	var asArray []map[string]any
	if err := json.Unmarshal(body, &asArray); err == nil {
		for i, item := range asArray {
			if len(rep.Pages) >= MaxPages {
				rep.Skipped = append(rep.Skipped, "stopped at the page limit")
				break
			}
			p, err := jsonPage(item, fmt.Sprintf("page-%d", i+1))
			if err != nil {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("item %d: %v", i+1, err))
				continue
			}
			rep.Pages = append(rep.Pages, p)
		}
		if len(rep.Pages) == 0 {
			return nil, fmt.Errorf("the array contained no importable pages")
		}
		return rep, nil
	}

	var asMap map[string]any
	if err := json.Unmarshal(body, &asMap); err != nil {
		return nil, fmt.Errorf("this is not JSON: %w", err)
	}
	// A map of name -> page is the other common shape.
	for name, v := range asMap {
		item, ok := v.(map[string]any)
		if !ok {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf(
				"%q is a %T, not a page object", name, v))
			continue
		}
		p, err := jsonPage(item, name)
		if err != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%q: %v", name, err))
			continue
		}
		rep.Pages = append(rep.Pages, p)
	}
	sort.Slice(rep.Pages, func(i, j int) bool {
		return rep.Pages[i].Name < rep.Pages[j].Name
	})
	if len(rep.Pages) == 0 {
		return nil, fmt.Errorf("no importable pages found")
	}
	return rep, nil
}

func jsonPage(item map[string]any, fallback string) (Page, error) {
	fields := map[string]any{}
	var dropped []string
	for k, v := range item {
		switch v.(type) {
		case string, float64, bool, nil:
			fields[k] = v
		case []any:
			fields[k] = v
		default:
			// A nested object has nowhere to go: content types are flat, which
			// is what keeps validation bounded. Reported rather than flattened
			// into keys nobody declared.
			dropped = append(dropped, k+" (nested object)")
		}
	}
	name := slug(str(fields["slug"]))
	if name == "" {
		name = slug(str(fields["name"]))
	}
	if name == "" {
		name = slug(str(fields["title"]))
	}
	if name == "" {
		name = slug(fallback)
	}
	if name == "" {
		return Page{}, fmt.Errorf("no usable name")
	}
	sort.Strings(dropped)
	return Page{Name: name, Fields: fields, Dropped: dropped}, nil
}

// -- shared ------------------------------------------------------------------

// flattenHTML turns markup into text, pulling out what is worth keeping.
//
// A hand-written scanner rather than a parser or a regex. A regex over HTML is
// wrong in ways that matter here — `<a href="x">` inside an attribute value,
// comments containing tags, script bodies — and a full parser is a dependency
// for something that only needs to find angle brackets. The scanner tracks
// whether it is inside a tag and inside a quoted attribute, which is the same
// distinction the attribute checks elsewhere in this project make.
func flattenHTML(in string) (text string, links, images []string, dropped []string) {
	var out strings.Builder
	var tag strings.Builder
	inTag, inQuote := false, byte(0)
	tagCount := 0
	// skipping names the element whose *content* is being discarded, not just
	// its tags. Removing <script> and keeping what was between it turns the
	// script body into visible page text — which is how an import produces a
	// page that reads "alert(1)" in the middle of a paragraph.
	skipping := ""

	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case inTag:
			if inQuote != 0 {
				tag.WriteByte(c)
				if c == inQuote {
					inQuote = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				inQuote = c
				tag.WriteByte(c)
				continue
			}
			if c == '>' {
				inTag = false
				tagCount++
				raw := tag.String()
				name, attrs := parseTag(raw)
				closing := strings.HasPrefix(strings.TrimSpace(raw), "/")

				if skipping != "" {
					// Inside a discarded element: the only tag that matters is
					// its own closing one.
					if closing && name == skipping {
						skipping = ""
					}
					tag.Reset()
					continue
				}
				switch name {
				case "a":
					if h := attrs["href"]; h != "" {
						links = append(links, h)
					}
				case "img":
					if s := attrs["src"]; s != "" {
						images = append(images, s)
					}
					if a := attrs["alt"]; a != "" {
						out.WriteString(" [" + a + "] ")
					}
				case "p", "br", "div", "li", "h1", "h2", "h3", "h4", "tr":
					out.WriteString("\n")
				case "script", "style", "iframe", "object", "embed", "noscript",
					"template", "svg":
					if !closing {
						skipping = name
						dropped = append(dropped, "<"+name+"> and its contents")
					}
				}
				tag.Reset()
				continue
			}
			tag.WriteByte(c)
		case c == '<':
			inTag = true
			tag.Reset()
		case skipping != "":
			// Discarded: the body of a script or style element is not prose.
		default:
			out.WriteByte(c)
		}
	}

	// Entities are decoded once, after tags are gone. Doing it before would
	// turn &lt;script&gt; into a tag the scanner then honours, which is the
	// classic double-decode bug.
	text = html.UnescapeString(out.String())
	text = collapse(text)

	if skipping != "" {
		dropped = append(dropped, fmt.Sprintf(
			"an unclosed <%s> swallowed the rest of the page", skipping))
	}
	if tagCount > 0 {
		dropped = append(dropped, fmt.Sprintf("%d HTML tags flattened to text",
			tagCount))
	}
	return text, dedupe(links), dedupe(images), dropped
}

func parseTag(s string) (name string, attrs map[string]string) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "/"))
	attrs = map[string]string{}
	name = s
	if i := strings.IndexAny(s, " \t\n"); i >= 0 {
		name, s = s[:i], s[i:]
		for _, part := range splitAttrs(s) {
			k, v, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			attrs[strings.ToLower(strings.TrimSpace(k))] =
				strings.Trim(strings.TrimSpace(v), `"'`)
		}
	} else {
		s = ""
	}
	return strings.ToLower(strings.TrimSuffix(name, "/")), attrs
}

func splitAttrs(s string) []string {
	var out []string
	var cur strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			cur.WriteByte(c)
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func collapse(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	blank := 0
	for _, l := range lines {
		l = strings.TrimRight(l, " \t\r")
		if strings.TrimSpace(l) == "" {
			blank++
			if blank > 1 {
				continue
			}
			out = append(out, "")
			continue
		}
		blank = 0
		out = append(out, strings.TrimSpace(l))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// slug produces a name that is safe as a page name and readable as a URL.
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == ' ' || r == '_' || r == '/' || r == '.':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 80 {
		out = strings.Trim(out[:80], "-")
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// unquoteYAML reads a quoted scalar, returning false if the value is not one.
//
// Only the escapes a flat scalar can carry, and only inside double quotes —
// single-quoted YAML has no escapes at all except a doubled quote. Anything
// beyond that is a full YAML parser, which is the thing this deliberately is
// not.
func unquoteYAML(v string) (string, bool) {
	if len(v) < 2 {
		return "", false
	}
	q := v[0]
	if (q != '"' && q != '\'') || v[len(v)-1] != q {
		return "", false
	}
	inner := v[1 : len(v)-1]

	if q == '\'' {
		// Single quotes: the only escape is a doubled quote.
		return strings.ReplaceAll(inner, "''", "'"), true
	}

	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if inner[i] != '\\' || i+1 >= len(inner) {
			b.WriteByte(inner[i])
			continue
		}
		i++
		switch inner[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		default:
			// An escape this does not know is kept literally rather than
			// guessed at, so nothing is silently altered.
			b.WriteByte('\\')
			b.WriteByte(inner[i])
		}
	}
	return b.String(), true
}
