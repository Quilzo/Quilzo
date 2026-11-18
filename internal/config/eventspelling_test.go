// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// notify.events takes an event by either of its names, as a webhook and a
// trigger do. `quilzo config set notify.events published` said "published"
// is not an event, which is the name every webhook knows it by.
func TestStaffAreToldOfAnEventByEitherSpelling(t *testing.T) {
	for _, v := range []string{"page.published", "published", "booked,form.submitted", "approval.waiting"} {
		if err := New().Set("notify.events", v, "", "test"); err != nil {
			t.Errorf("notify.events %q: %v", v, err)
		}
	}
	for _, v := range []string{"publish", "page.deleted", "PUBLISHED"} {
		if err := New().Set("notify.events", v, "", "test"); err == nil {
			t.Errorf("notify.events %q was accepted", v)
		}
	}
}
