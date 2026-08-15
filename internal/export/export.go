// Package export gets content out, in formats other systems already read.
//
// # Why this is a property and not a feature
//
// Every CMS has an export button. Most of them produce something only that CMS
// can read, or something that loses half the content, and nobody finds out
// until the day they try to leave — which is the day the vendor's incentive to
// have fixed it was lowest.
//
// So export here is checked the only way that means anything: a round trip.
// Export a site, import what came out, and the result must be the same site.
// The test does exactly that, on every format, and it fails if a single field
// changes. An export that cannot be re-imported is not an export.
//
// GDPR Article 20 asks for "a structured, commonly used and machine-readable
// format", which is the legal floor. The bar this aims at is higher and
// simpler: somebody should be able to leave without asking us for help.
//
// # The formats, and why these three
//
// Markdown with front matter is the universal escape hatch. Hugo, Eleventy,
// Astro, Jekyll and Eleventy read it directly; every other CMS has an importer
// for it. It is the format with the most destinations.
//
// WXR is WordPress's own export format, and WordPress is where most people go.
// Producing it means "move to WordPress" is a file copy rather than a project.
// There is something faintly absurd about writing an exporter for a competitor,
// which is the point: a tool that makes leaving hard is a tool that has to keep
// earning nothing.
//
// JSON is the round trip. It is what this tool's own importer reads, so it is
// the format that carries everything with no loss at all.
//
// # No bundle format
//
// The output is a directory of ordinary files. Not a zip, not a proprietary
// archive with a manifest nobody else parses. Somebody should be able to read
// an export with `ls` and `cat`, and recover a single page from it without
// running anything.
package export

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Format is an export format.
type Format string

const (
	// Markdown with flat front matter: the most destinations.
	Markdown Format = "markdown"
	// JSON: lossless, and what this tool's own importer reads.
	JSON Format = "json"
	// WXR: WordPress's own format, so leaving for WordPress is a file copy.
	WXR Format = "wxr"
)

// Formats lists what can be produced.
func Formats() []Format { return []Format{Markdown, JSON, WXR} }

// File is one output file. Paths are relative and always use forward slashes.
type File struct {
	Path string
	Body []byte
}

// Site is what gets exported.
type Site struct {
	// Pages maps a page name to its fields.
	Pages map[string]any
	// Name and BaseURL describe the site, for formats that carry them.
	Name    string
	BaseURL string
	// Changed is when each page's content last actually changed. Carried into
	// the export because it is real information that most systems cannot
	// reconstruct, and losing it on the way out would make the destination's
	// sitemap wrong from its first day.
	Changed map[string]time.Time
	// Redirects are carried so old URLs keep working after the move. An export
	// without them hands somebody a site that loses its rankings on arrival.
	Redirects []Redirect
}

// Redirect is carried through an export unchanged.
type Redirect struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Permanent bool   `json:"permanent"`
	Note      string `json:"note,omitempty"`
}

// Export renders a site into files.
func Export(f Format, s Site, now time.Time) ([]File, error) {
	if len(s.Pages) == 0 {
		return nil, fmt.Errorf("there is nothing published to export")
	}
	switch f {
	case Markdown:
		return exportMarkdown(s)
	case JSON:
		return exportJSON(s)
	case WXR:
		return exportWXR(s, now)
	}
	return nil, fmt.Errorf("unknown format %q; try markdown, json or wxr", f)
}

func names(s Site) []string {
	out := make([]string, 0, len(s.Pages))
	for n := range s.Pages {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// -- markdown ----------------------------------------------------------------

// exportMarkdown writes one file per page.
//
// Front matter is flat key: value, matching exactly what this tool's importer
// reads. Emitting nested YAML would produce files that look richer and that
// this tool could not read back — an export that fails its own round trip.
func exportMarkdown(s Site) ([]File, error) {
	var out []File
	for _, name := range names(s) {
		fields, ok := s.Pages[name].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("page %q is not an object", name)
		}

		var body string
		var front []string
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			// `body` becomes the document, which is what every consumer of
			// Markdown expects. Leaving it in the front matter would produce a
			// file with an empty document and a very long metadata block.
			if k == "body" {
				body, _ = fields[k].(string)
				continue
			}
			v, err := yamlScalar(fields[k])
			if err != nil {
				return nil, fmt.Errorf("page %q field %q: %w", name, k, err)
			}
			front = append(front, k+": "+v)
		}
		if t, ok := s.Changed[name]; ok && !t.IsZero() {
			front = append(front, "date: "+t.UTC().Format("2006-01-02"))
		}

		var b strings.Builder
		b.WriteString("---\n")
		for _, line := range front {
			b.WriteString(line + "\n")
		}
		b.WriteString("---\n\n")
		b.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			b.WriteString("\n")
		}
		out = append(out, File{Path: "content/" + name + ".md", Body: []byte(b.String())})
	}

	out = append(out, readme(Markdown, s))
	if f, ok := redirectFile(s); ok {
		out = append(out, f)
	}
	return out, nil
}

// yamlScalar renders a value as a quoted YAML scalar.
//
// Always quoted, always double, with the two characters that matter escaped.
// Unquoted YAML scalars are a minefield — `no` is false, `1.0` is a float,
// `12:30` is a sexagesimal integer in YAML 1.1, and a leading `&` is an anchor.
// Quoting everything makes the output boring, which is the goal.
func yamlScalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return quoteYAML(t), nil
	case bool:
		return fmt.Sprintf("%t", t), nil
	case float64:
		return fmt.Sprintf("%v", t), nil
	case nil:
		return `""`, nil
	case []any:
		// A flow sequence keeps it on one line, which keeps the front matter
		// flat — the subset this tool reads back.
		parts := make([]string, 0, len(t))
		for _, item := range t {
			s, err := yamlScalar(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	}
	return "", fmt.Errorf("%T cannot be written as flat front matter", v)
}

func quoteYAML(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// -- json --------------------------------------------------------------------

func exportJSON(s Site) ([]File, error) {
	// A map of name to fields, which is one of the two shapes the importer
	// reads. Chosen over an array because it makes a page recoverable by name
	// with a text editor.
	body, err := json.MarshalIndent(s.Pages, "", "  ")
	if err != nil {
		return nil, err
	}
	out := []File{{Path: "content/pages.json", Body: append(body, '\n')}}

	if len(s.Changed) > 0 {
		when := map[string]string{}
		for name, t := range s.Changed {
			if !t.IsZero() {
				when[name] = t.UTC().Format(time.RFC3339)
			}
		}
		b, err := json.MarshalIndent(when, "", "  ")
		if err != nil {
			return nil, err
		}
		// Beside content/ rather than inside it. A directory called content
		// should hold content: this sat next to pages.json, so the obvious
		// `scrivet import content/*.json` failed on a file this tool wrote
		// itself, which reads as the importer being broken.
		out = append(out, File{Path: "last-changed.json", Body: append(b, '\n')})
	}

	out = append(out, readme(JSON, s))
	if f, ok := redirectFile(s); ok {
		out = append(out, f)
	}
	return out, nil
}

// -- wxr ---------------------------------------------------------------------

// exportWXR produces a WordPress import file.
//
// There is something faintly absurd about writing an exporter for a competitor,
// and that is the point. A tool that makes leaving hard is a tool that has
// stopped needing to be good.
func exportWXR(s Site, now time.Time) ([]File, error) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<rss version="2.0"` + "\n")
	b.WriteString(`  xmlns:content="http://purl.org/rss/1.0/modules/content/"` + "\n")
	b.WriteString(`  xmlns:dc="http://purl.org/dc/elements/1.1/"` + "\n")
	b.WriteString(`  xmlns:wp="http://wordpress.org/export/1.2/">` + "\n")
	b.WriteString("<channel>\n")
	b.WriteString("  <title>" + xmlEscape(s.Name) + "</title>\n")
	b.WriteString("  <link>" + xmlEscape(s.BaseURL) + "</link>\n")
	b.WriteString("  <wp:wxr_version>1.2</wp:wxr_version>\n")

	for i, name := range names(s) {
		fields, _ := s.Pages[name].(map[string]any)
		title, _ := fields["title"].(string)
		if title == "" {
			title = name
		}
		body, _ := fields["body"].(string)

		when := now
		if t, ok := s.Changed[name]; ok && !t.IsZero() {
			when = t
		}

		b.WriteString("  <item>\n")
		b.WriteString("    <title>" + xmlEscape(title) + "</title>\n")
		if s.BaseURL != "" {
			b.WriteString("    <link>" + xmlEscape(
				strings.TrimSuffix(s.BaseURL, "/")+"/"+name) + "</link>\n")
		}
		b.WriteString("    <dc:creator>" + xmlEscape(str(fields["byline"])) + "</dc:creator>\n")
		// CDATA rather than escaped text, which is what WordPress writes and
		// what its importer expects. The body is escaped for CDATA below.
		b.WriteString("    <content:encoded><![CDATA[" + cdata(body) + "]]></content:encoded>\n")
		b.WriteString(fmt.Sprintf("    <wp:post_id>%d</wp:post_id>\n", i+1))
		b.WriteString("    <wp:post_date>" +
			when.UTC().Format("2006-01-02 15:04:05") + "</wp:post_date>\n")
		b.WriteString("    <wp:post_name>" + xmlEscape(name) + "</wp:post_name>\n")
		b.WriteString("    <wp:status>publish</wp:status>\n")
		b.WriteString("    <wp:post_type>post</wp:post_type>\n")

		// Everything the WXR shape has no field for goes into postmeta rather
		// than being dropped. A lossy export is the thing this package exists
		// not to be, and postmeta is where WordPress itself puts what it has
		// nowhere else for.
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch k {
			case "title", "body", "byline", "slug":
				continue
			}
			v, err := yamlScalar(fields[k])
			if err != nil {
				continue
			}
			b.WriteString("    <wp:postmeta>\n")
			b.WriteString("      <wp:meta_key>" + xmlEscape(k) + "</wp:meta_key>\n")
			b.WriteString("      <wp:meta_value><![CDATA[" +
				cdata(strings.Trim(v, `"`)) + "]]></wp:meta_value>\n")
			b.WriteString("    </wp:postmeta>\n")
		}
		b.WriteString("  </item>\n")
	}
	b.WriteString("</channel>\n</rss>\n")

	out := []File{{Path: "content/wordpress-export.xml", Body: []byte(b.String())}}
	out = append(out, readme(WXR, s))
	if f, ok := redirectFile(s); ok {
		out = append(out, f)
	}
	return out, nil
}

// cdata neutralises the one sequence that can end a CDATA section early.
//
// A body containing "]]>" would otherwise close the section and let the rest of
// the content be parsed as markup — which in an export is both a corruption and
// an injection into whatever reads it next.
func cdata(s string) string {
	return strings.ReplaceAll(s, "]]>", "]]]]><![CDATA[>")
}

func xmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;",
	).Replace(s)
}

// -- shared ------------------------------------------------------------------

func redirectFile(s Site) (File, bool) {
	if len(s.Redirects) == 0 {
		return File{}, false
	}
	body, err := json.MarshalIndent(
		map[string]any{"redirects": s.Redirects}, "", "  ")
	if err != nil {
		return File{}, false
	}
	return File{Path: "redirects.json", Body: append(body, '\n')}, true
}

// readme explains the export to whoever opens it, including how to load it
// somewhere else.
//
// Written because an export nobody can work out how to use is an export that
// exists to satisfy a checkbox. The instructions name real tools rather than
// gesturing at "your new platform's documentation".
func readme(f Format, s Site) File {
	var b strings.Builder
	b.WriteString("# Export\n\n")
	fmt.Fprintf(&b, "%d page(s) from %s.\n\n", len(s.Pages), orUnnamed(s.Name))

	switch f {
	case Markdown:
		b.WriteString("`content/` holds one Markdown file per page, with flat\n")
		b.WriteString("`key: value` front matter.\n\n")
		b.WriteString("This is the format with the most destinations:\n\n")
		b.WriteString("- **Hugo**: copy `content/` into your site's `content/`.\n")
		b.WriteString("- **Astro**: copy into `src/content/`, then define a collection.\n")
		b.WriteString("- **Eleventy** and **Jekyll**: copy the files in as-is.\n")
		b.WriteString("- **WordPress**: use a Markdown importer plugin, or take\n")
		b.WriteString("  the `wxr` export instead, which WordPress reads natively.\n")
	case JSON:
		b.WriteString("`content/pages.json` maps each page name to its fields.\n\n")
		b.WriteString("This is the lossless format: nothing was flattened or\n")
		b.WriteString("dropped to produce it. `last-changed.json` records\n")
		b.WriteString("when each page's content actually last changed, which is\n")
		b.WriteString("worth carrying across so the new system's sitemap is not\n")
		b.WriteString("wrong from its first day.\n")
	case WXR:
		b.WriteString("`content/wordpress-export.xml` is a WordPress WXR file.\n\n")
		b.WriteString("In WordPress: Tools → Import → WordPress, then upload it.\n\n")
		b.WriteString("Fields with no WXR equivalent are carried as postmeta\n")
		b.WriteString("rather than dropped.\n")
	}

	if len(s.Redirects) > 0 {
		fmt.Fprintf(&b, "\n## Redirects\n\n`redirects.json` holds %d redirect(s) "+
			"from URLs this content\nhad previously. Carry them across, or links "+
			"published before the\nmove will break. Google asks for at least a "+
			"year.\n", len(s.Redirects))
	}

	b.WriteString("\n## Media\n\n")
	b.WriteString("Files referenced by content are not included here; they are\n")
	b.WriteString("exported separately so this file stays small enough to read.\n")

	b.WriteString("\n---\n\nEverything in this export is a plain file. There is no\n")
	b.WriteString("archive to unpack and no manifest to parse: `ls` and `cat` are\n")
	b.WriteString("enough to recover any single page by hand.\n")

	return File{Path: "README.md", Body: []byte(b.String())}
}

func orUnnamed(s string) string {
	if strings.TrimSpace(s) == "" {
		return "an unnamed site"
	}
	return s
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
