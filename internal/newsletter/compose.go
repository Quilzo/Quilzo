// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package newsletter

import (
	"bytes"
	"html"
	"html/template"
	"regexp"
	"strings"
)

// A page, as mail.
//
// An issue is a published page, so there is one thing to write and the
// web has the same words at an address worth sharing. What a mail reader
// can show is narrower than what a page can: no stylesheet of the site's
// own, no script, and pictures only when the reader asks for them. So the
// page is read for its words in the order a visitor reads them — title,
// lead, picture, text, then each section's heading, paragraphs, items and
// buttons — and written twice: as plain text, which every reader shows,
// and as one plain column of HTML with its styles inline.
//
// What a mail cannot do is left as a link to the page: a booking's free
// times, a question box, comments, a sign-up form, a listing that changes.

// Letter is an issue as mail, before it is addressed: the leave link is
// put in for each address by For.
type Letter struct {
	Subject string
	Text    string
	HTML    string
}

// Source is the page an issue is made from.
type Source struct {
	// Site is the site's name, and Base its https address.
	Site, Base string
	// Path is where the page is served: "/" or "/october".
	Path string
	Page map[string]any
	// Accent colours links and buttons, as #rrggbb; empty is a dark blue.
	Accent string
}

// leaveMark stands in for one address's leave link until For: an address
// nothing escapes, in a domain that cannot exist (RFC 2606).
const leaveMark = "https://leave.quilzo.invalid/address"

type block struct {
	Kind      string // "h2", "p", "lead", "quote", "img", "item", "button"
	Text, By  string
	Href, Alt string
}

// skipKinds are the sections a mail cannot be: each needs the page.
var skipKinds = map[string]bool{
	"ask": true, "comments": true, "booking": true, "newsletter": true,
	"listing": true, "video": true,
}

var (
	reAccent  = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	reHeading = regexp.MustCompile(`^#{1,4}\s+(.+)$`)
)

// Compose makes the letter for a page.
func Compose(src Source, subject string) Letter {
	base := strings.TrimSuffix(src.Base, "/")
	abs := func(ref string) string {
		ref = strings.TrimSpace(ref)
		switch {
		case strings.HasPrefix(ref, "https://"):
			return ref
		case strings.HasPrefix(ref, "/") && !strings.HasPrefix(ref, "//") && base != "":
			return base + ref
		}
		return ""
	}
	web := abs(src.Path)
	title := str(src.Page, "title")
	if title == "" {
		title = subject
	}
	blocks := pageBlocks(src.Page, abs)
	skipped := false
	if sections, ok := src.Page["sections"].([]any); ok {
		for _, s := range sections {
			sec, _ := s.(map[string]any)
			for kind, v := range sec {
				if skipKinds[kind] {
					// A sign-up form is for somebody not yet on the list,
					// and every reader of this is.
					skipped = skipped || kind != "newsletter"
					continue
				}
				if m, ok := v.(map[string]any); ok {
					blocks = append(blocks, sectionBlocks(m, kind, abs)...)
				}
			}
		}
	}
	accent := src.Accent
	if !reAccent.MatchString(accent) {
		accent = "#1d4e89"
	}
	site := src.Site
	if site == "" {
		site = "this site"
	}

	var t strings.Builder
	t.WriteString(title + "\n\n")
	for i, b := range blocks {
		if i > 0 && blocks[i-1].Kind == "item" && b.Kind != "item" {
			t.WriteString("\n")
		}
		switch b.Kind {
		case "h2":
			t.WriteString("\n" + strings.ToUpper(b.Text) + "\n\n")
		case "p", "lead":
			t.WriteString(b.Text + "\n\n")
		case "quote":
			t.WriteString("“" + b.Text + "”\n")
			if b.By != "" {
				t.WriteString("— " + b.By + "\n")
			}
			t.WriteString("\n")
		case "item":
			if b.By != "" {
				t.WriteString("• " + b.By + ": " + b.Text + "\n")
			} else {
				t.WriteString("• " + b.Text + "\n")
			}
		case "button":
			t.WriteString(b.Text + ": " + b.Href + "\n\n")
		}
	}
	if web != "" {
		if skipped {
			t.WriteString("\nThere is more on the page than a mail can carry. ")
		} else {
			t.WriteString("\n")
		}
		t.WriteString("Read it on the web: " + web + "\n")
	}
	t.WriteString("\n-- \nYou are getting this because you asked for " + site + "'s newsletter. " +
		"To stop, open this link, or use your mail app's unsubscribe button: " + leaveMark + "\n")

	var h bytes.Buffer
	_ = letterHTML.Execute(&h, map[string]any{
		"Title": title, "Blocks": blocks, "Web": web, "More": skipped, "Site": site,
		"Accent": template.CSS(accent), "Leave": template.URL(leaveMark), "Subject": subject,
	})
	return Letter{Subject: subject, Text: t.String(), HTML: h.String()}
}

// For addresses a letter to one subscriber, with their own leave link.
func (lt Letter) For(leave string) (text, page string) {
	return strings.ReplaceAll(lt.Text, leaveMark, leave),
		strings.ReplaceAll(lt.HTML, leaveMark, html.EscapeString(leave))
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return oneLine(s)
		}
	}
	return ""
}

// paragraphs splits text on blank lines, keeping a line that starts with
// #s as a heading.
func paragraphs(s string) []block {
	var out []block
	for _, p := range regexp.MustCompile(`\n\s*\n`).Split(s, -1) {
		p = oneLine(strings.ReplaceAll(p, "\n", " "))
		if p == "" {
			continue
		}
		if m := reHeading.FindStringSubmatch(p); m != nil {
			out = append(out, block{Kind: "h2", Text: m[1]})
			continue
		}
		out = append(out, block{Kind: "p", Text: p})
	}
	return out
}

func strings2(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// pageBlocks are a page's own fields, laid out by field rather than by
// section: its lead, its picture, its text and its pulled quote.
func pageBlocks(page map[string]any, abs func(string) string) []block {
	var out []block
	hero, _ := page["hero"].(map[string]any)
	lead := str(page, "standfirst", "lead")
	if lead == "" && hero != nil {
		lead = str(hero, "lead")
	}
	if lead == "" {
		lead = str(page, "description")
	}
	if lead != "" {
		out = append(out, block{Kind: "lead", Text: lead})
	}
	var img, alt string
	if s, ok := page["hero"].(string); ok {
		img, alt = s, str(page, "hero_alt")
	} else if hero != nil {
		img, alt = str(hero, "image"), str(hero, "alt")
	}
	if src := abs(img); src != "" {
		out = append(out, block{Kind: "img", Href: src, Alt: alt})
	}
	if hero != nil {
		if href := abs(str(hero, "cta_href")); href != "" && str(hero, "cta_label") != "" {
			out = append(out, block{Kind: "button", Text: str(hero, "cta_label"), Href: href})
		}
	}
	if body, ok := page["body"].(string); ok {
		out = append(out, paragraphs(body)...)
	}
	for _, p := range strings2(page["paragraphs"]) {
		out = append(out, paragraphs(p)...)
	}
	if q := str(page, "pull_quote"); q != "" {
		out = append(out, block{Kind: "quote", Text: q, By: str(page, "pull_quote_by")})
	}
	return out
}

// sectionBlocks are one section's words: its heading, its text, its
// pictures, its items and its buttons.
func sectionBlocks(sec map[string]any, kind string, abs func(string) string) []block {
	var out []block
	if t := str(sec, "title", "heading"); t != "" {
		out = append(out, block{Kind: "h2", Text: t})
	}
	if q := str(sec, "text"); kind == "quote" && q != "" {
		by := str(sec, "by")
		if r := str(sec, "role"); r != "" && by != "" {
			by += ", " + r
		}
		out = append(out, block{Kind: "quote", Text: q, By: by})
	}
	for _, k := range []string{"intro", "lead", "body"} {
		if s, ok := sec[k].(string); ok {
			out = append(out, paragraphs(s)...)
		}
	}
	for _, p := range strings2(sec["paragraphs"]) {
		out = append(out, paragraphs(p)...)
	}
	if src := abs(str(sec, "image")); src != "" {
		out = append(out, block{Kind: "img", Href: src, Alt: str(sec, "alt")})
	}
	items, _ := sec["items"].([]any)
	for _, it := range items {
		switch v := it.(type) {
		case string:
			if s := oneLine(v); s != "" {
				out = append(out, block{Kind: "item", Text: s})
			}
		case map[string]any:
			if kind == "gallery" || kind == "people" || kind == "carousel" || kind == "tabs" {
				if src := abs(str(v, "image", "src")); src != "" {
					out = append(out, block{Kind: "img", Href: src, Alt: str(v, "alt", "caption", "name")})
				}
			}
			head := str(v, "q", "question", "title", "name", "value")
			text := str(v, "a", "answer", "body", "text", "label", "role")
			if kind == "quotes" && str(v, "text") != "" {
				out = append(out, block{Kind: "quote", Text: str(v, "text"), By: str(v, "by")})
				continue
			}
			switch {
			case head != "" && text != "":
				out = append(out, block{Kind: "item", By: head, Text: text})
			case head != "" || text != "":
				out = append(out, block{Kind: "item", Text: head + text})
			}
		}
	}
	for _, b := range [][2]string{{"cta_label", "cta_href"}, {"secondary_label", "secondary_href"}} {
		if href := abs(str(sec, b[1])); href != "" && str(sec, b[0]) != "" {
			out = append(out, block{Kind: "button", Text: str(sec, b[0]), Href: href})
		}
	}
	return out
}

// letterHTML is one column, every style inline, no image needed to read
// it, and the text the plain part has.
var letterHTML = template.Must(template.New("letter").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:0;background:#f4f4f2;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f4f2;"><tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;background:#ffffff;border-radius:8px;">
<tr><td style="padding:32px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:16px;line-height:1.6;color:#1b1b1b;">
<p style="margin:0 0 8px;font-size:13px;color:#5f5f5f;">{{.Site}}</p>
<h1 style="margin:0 0 16px;font-size:26px;line-height:1.25;color:#1b1b1b;">{{.Title}}</h1>
{{range .Blocks}}{{if eq .Kind "lead"}}<p style="margin:0 0 16px;font-size:18px;color:#3d3d3d;">{{.Text}}</p>
{{else if eq .Kind "p"}}<p style="margin:0 0 16px;">{{.Text}}</p>
{{else if eq .Kind "h2"}}<h2 style="margin:28px 0 12px;font-size:20px;line-height:1.3;color:#1b1b1b;">{{.Text}}</h2>
{{else if eq .Kind "img"}}<p style="margin:0 0 16px;"><img src="{{.Href}}" alt="{{.Alt}}" width="544" style="display:block;width:100%;max-width:544px;height:auto;border:0;border-radius:6px;"></p>
{{else if eq .Kind "quote"}}<blockquote style="margin:0 0 16px;padding:4px 0 4px 16px;border-left:3px solid {{$.Accent}};"><p style="margin:0;font-size:18px;">{{.Text}}</p>{{if .By}}<p style="margin:4px 0 0;font-size:14px;color:#5f5f5f;">{{.By}}</p>{{end}}</blockquote>
{{else if eq .Kind "item"}}<p style="margin:0 0 12px;padding-left:14px;border-left:2px solid #e2e2de;">{{if .By}}<strong>{{.By}}</strong><br>{{end}}{{.Text}}</p>
{{else if eq .Kind "button"}}<p style="margin:8px 0 20px;"><a href="{{.Href}}" style="display:inline-block;padding:10px 20px;border-radius:999px;background:{{$.Accent}};color:#ffffff;text-decoration:none;font-weight:600;">{{.Text}}</a></p>
{{end}}{{end}}
{{if .Web}}<p style="margin:24px 0 0;">{{if .More}}There is more on the page than a mail can carry. {{end}}<a href="{{.Web}}" style="color:{{.Accent}};">Read it on the web</a></p>{{end}}
</td></tr></table>
<p style="max-width:600px;margin:16px auto 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:1.5;color:#5f5f5f;">You are getting this because you asked for {{.Site}}'s newsletter. <a href="{{.Leave}}" style="color:#5f5f5f;">Stop getting it</a>.</p>
</td></tr></table>
</body></html>
`))
