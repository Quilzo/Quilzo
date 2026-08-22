package public

import (
	"encoding/json"
	"strings"
)

// Structured data for an ordinary page.
//
// # Why this is built in Go rather than written in the layout
//
// A JSON-LD block is JSON inside a script element, and the template renderer
// escapes for HTML. Those are different escapings: a title containing a quote
// mark comes out as &#34; inside the JSON, which is not valid JSON, and a title
// containing </script> would end the element early. Neither is a bug the
// renderer has — it is escaping correctly for the context it thinks it is in —
// so the only safe place to build this is where the values can be marshalled by
// something that knows they are JSON.
//
// That is the same argument the product block already makes, and this is the
// ordinary-page half of it: a shop had structured data and an article did not.
//
// # Why so little of it
//
// Only fields the page actually carries, and only types the content can support.
// A WebPage with a name and a description is true. An Article with a fabricated
// author or a dateModified taken from when the file was touched is the thing
// search engines eventually stop trusting a whole site over — the same argument
// the sitemap's lastmod already makes in internal/seo, applied here.
//
// # Why a script element is acceptable on a site with script-src 'none'
//
// A JSON-LD block is a data block, not a program: the type is not a scripting
// type, so nothing in it is executed and the policy has nothing to stop. It is
// also not new here — the provenance marking and the product data have both been
// emitted this way. What matters is that no *executable* script is ever emitted,
// and that remains true.
func pageStructuredData(page string, body any, siteName, baseURL string) string {
	m, ok := body.(map[string]any)
	if !ok {
		return ""
	}
	var blocks []any

	if doc := documentLD(m, siteName); doc != nil {
		blocks = append(blocks, doc)
	}
	if crumbs := breadcrumbLD(m, baseURL); crumbs != nil {
		blocks = append(blocks, crumbs)
	}
	if len(blocks) == 0 {
		return ""
	}

	var b strings.Builder
	for _, block := range blocks {
		encoded, err := json.Marshal(block)
		if err != nil {
			continue
		}
		// Marshalled, then checked. encoding/json escapes <, > and & into \u
		// sequences by default, so a value cannot close the element — but this
		// is the one place in the program where a mistake would be script
		// injection, so it is asserted rather than assumed.
		if strings.Contains(strings.ToLower(string(encoded)), "</script") {
			continue
		}
		b.WriteString(`<script type="application/ld+json">`)
		b.Write(encoded)
		b.WriteString("</script>\n")
	}
	return b.String()
}

// documentLD describes the page itself.
//
// An Article when the content says it is one — a byline, a publication date, or
// an og_type saying article — and a WebPage otherwise. The distinction is read
// off the content rather than guessed from the layout, because a layout is a
// design decision and this is a claim about what the page *is*.
func documentLD(m map[string]any, siteName string) map[string]any {
	title := text(m, "title")
	if title == "" {
		return nil
	}
	doc := map[string]any{
		"@context": "https://schema.org",
		"@type":    "WebPage",
		"name":     title,
	}
	if d := text(m, "description"); d != "" {
		doc["description"] = d
	} else if d := text(m, "standfirst"); d != "" {
		doc["description"] = d
	}
	if img := firstText(m, "share_image", "hero"); img != "" {
		doc["image"] = img
	}
	if siteName != "" {
		doc["isPartOf"] = map[string]any{"@type": "WebSite", "name": siteName}
	}
	if l := text(m, "lang"); l != "" {
		doc["inLanguage"] = l
	}

	byline := text(m, "byline")
	published := text(m, "published")
	if byline == "" && published == "" && text(m, "og_type") != "article" {
		return doc
	}

	doc["@type"] = "Article"
	doc["headline"] = title
	if byline != "" {
		doc["author"] = map[string]any{"@type": "Person", "name": byline}
	}
	if published != "" {
		doc["datePublished"] = published
	}
	// Only when the content says so. A dateModified derived from when a file
	// was last written is the claim that stops being believed: it moves when
	// somebody opens a page and saves it without changing a word.
	if updated := text(m, "updated"); updated != "" {
		doc["dateModified"] = updated
	}
	if section := text(m, "section"); section != "" {
		doc["articleSection"] = section
	}
	if tags := textList(m, "tags"); len(tags) > 0 {
		doc["keywords"] = tags
	}
	return doc
}

// breadcrumbLD mirrors the trail the page already renders.
//
// Built from the same field the layout draws, so the two cannot disagree — a
// breadcrumb in the markup and a different one in the structured data is a
// mismatch a crawler notices and a person never does.
func breadcrumbLD(m map[string]any, baseURL string) map[string]any {
	list, ok := m["breadcrumbs"].([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	items := make([]any, 0, len(list))
	position := 0
	for _, entry := range list {
		crumb, isMap := entry.(map[string]any)
		if !isMap {
			continue
		}
		label := text(crumb, "label")
		if label == "" {
			continue
		}
		position++
		item := map[string]any{
			"@type":    "ListItem",
			"position": position,
			"name":     label,
		}
		// An absolute URL or nothing. A relative one in structured data is
		// resolved against whatever the consumer thinks the base is, and a
		// crawler that guesses wrong indexes a URL that does not exist.
		if href := text(crumb, "href"); href != "" && baseURL != "" {
			item["item"] = absolute(baseURL, href)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	return map[string]any{
		"@context":        "https://schema.org",
		"@type":           "BreadcrumbList",
		"itemListElement": items,
	}
}

// absolute joins a base origin and a path without inventing a scheme.
func absolute(base, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(href, "/")
}

func text(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

func firstText(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := text(m, k); v != "" {
			return v
		}
	}
	return ""
}

// textList reads a list of strings, skipping anything else.
func textList(m map[string]any, key string) []string {
	list, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}
