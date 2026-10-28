// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package render

// Free times for a service, placed where the page put them.
//
// A booking section names one of the site's services. The times are not
// content: they come from the calendar (internal/booking) when the page is
// asked for, the same way a comments section gets its posts. What a visitor
// booked is shown in the same place, from the page's own address, so the
// confirmation is the page they booked on and nothing else.

// placeBookings fills every booking section on a page.
func placeBookings(page any, name string, args map[string]string,
	resolve func(service, page string, args map[string]string) map[string]any) {
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
		b, ok := sec["booking"].(map[string]any)
		if !ok {
			continue
		}
		service, _ := b["service"].(string)
		var data map[string]any
		if resolve != nil && service != "" {
			data = resolve(service, name, args)
		}
		if data == nil {
			// A site taking no bookings, or a service it does not offer:
			// the section says so rather than offering times it cannot keep.
			data = map[string]any{"closed": true}
		}
		for k, v := range data {
			b[k] = v
		}
		b["page"] = name
	}
}
