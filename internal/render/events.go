// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package render

// The site's events, placed where the page put them.
//
// An events section names no listing: the site has one events listing
// (site.events), and the section shows what it keeps now, up to the number
// the section asks for. Which events those are depends on the clock, so they
// come from the site when the page is asked for, like a booking section's
// free times.

// placeEvents fills every events section on a page.
func placeEvents(page any, resolve func(rows int) map[string]any) {
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
		e, ok := sec["events"].(map[string]any)
		if !ok {
			continue
		}
		rows := 0
		if n, ok := e["rows"].(float64); ok {
			rows = int(n)
		}
		var data map[string]any
		if resolve != nil {
			data = resolve(rows)
		}
		if data == nil {
			data = map[string]any{"closed": true}
		}
		for k, v := range data {
			e[k] = v
		}
	}
}
