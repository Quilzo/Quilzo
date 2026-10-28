// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package render

// A sign-up for the site's newsletter, placed where the page put it.
//
// The section's words are content: what the letter is and how often. Whether
// it takes sign-ups now is not, since that depends on mail being set up, so
// it comes from the site when the page is asked for, with what to say after
// somebody signed up, from the page's own query.

// placeNewsletters fills every newsletter section on a page.
func placeNewsletters(page any, name string, args map[string]string,
	resolve func(page string, args map[string]string) map[string]any) {
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
		n, ok := sec["newsletter"].(map[string]any)
		if !ok {
			continue
		}
		var data map[string]any
		if resolve != nil {
			data = resolve(name, args)
		}
		if data == nil {
			data = map[string]any{"closed": true}
		}
		for k, v := range data {
			n[k] = v
		}
		n["page"] = name
	}
}
