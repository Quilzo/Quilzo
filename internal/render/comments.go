// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package render

// What members wrote under a page, placed where the page put it.
//
// A comments section names a board, and the page it is on is that board's
// thread. The posts are not content — they live in internal/board, where an
// author can delete them — so the section arrives at the template with them
// filled in here, the same way a listing section gets its rows.
//
// The same for everybody who looks: what is shown is the visible posts, and
// nothing about who is asking. A member's own post that is waiting for a
// person is shown to them on their account page, not here, so a page with
// comments can still be cached and served alike to all.

// placeComments fills every comments section on a page.
func placeComments(page any, name string, thread func(board, page string) map[string]any) {
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
		c, ok := sec["comments"].(map[string]any)
		if !ok {
			continue
		}
		board, _ := c["board"].(string)
		var data map[string]any
		if thread != nil && board != "" {
			data = thread(board, name)
		}
		posts, _ := data["posts"].([]any)
		if posts == nil {
			posts = []any{}
		}
		c["posts"] = posts
		c["count"] = float64(len(posts))
		c["empty"] = len(posts) == 0
		c["thread"] = name
		// Open only when the site says the board takes posts: a page whose
		// board is missing, closed, or on a site with no accounts shows
		// what is there and no form.
		open, _ := data["open"].(bool)
		c["open"] = open
		c["held"] = data["held"] == true
		if data["live"] == true {
			c["live"] = "/live/board/" + board + "/" + name
		}
		if _, has := c["title"]; !has {
			if t, ok := data["title"].(string); ok {
				c["title"] = t
			}
		}
	}
}
