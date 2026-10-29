// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package render

// The site's posts, placed where the page put them.
//
// A posts section names no listing: the site has one blog (site.blog), and
// the section shows its posts newest first, as many as the section asks for,
// at the page of them the address asks for with ?page=. They come from the
// site when the page is asked for, and are decorated here as the page's own
// content is, so a post's picture has its narrower copies too.

// placePosts fills every posts section on a page.
func placePosts(page any, name string, args map[string]string,
	resolve func(page string, rows int, args map[string]string) map[string]any, ask asks) {
	m, ok := page.(map[string]any)
	if !ok {
		return
	}
	sections, _ := m["sections"].([]any)
	for _, s := range sections {
		sec, ok := s.(map[string]any)
		if !ok {
			continue
		}
		p, ok := sec["posts"].(map[string]any)
		if !ok {
			continue
		}
		rows := 0
		if n, ok := p["rows"].(float64); ok {
			rows = int(n)
		}
		var data map[string]any
		if resolve != nil {
			data = resolve(name, rows, args)
		}
		if data == nil {
			data = map[string]any{"closed": true}
		}
		if d, ok := decorate(data, 0, ask).(map[string]any); ok {
			data = d
		}
		for k, v := range data {
			p[k] = v
		}
	}
}
