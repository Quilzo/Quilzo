// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"regexp"
	"strings"
)

// The navigation's icons.
//
// Google's Material Symbols, Rounded, as Chrome's own settings and Google's
// apps draw theirs, so a person moving between them and this recognises the
// same pictures for the same things. They are Apache-2.0 and sit, with that
// licence and a note of where they came from, in assets/icons.
//
// Read once, at start, from the embedded files: only each file's single
// path is kept, and it is drawn inline, so an icon costs no request and
// follows the text colour into the dark theme and a forced-colours one.

// iconSymbol is which Material Symbol stands for which screen, for whoever
// adds a screen and needs to fetch its icon.
var iconSymbol = map[string]string{
	"pages": "description", "records": "database", "types": "category",
	"structure": "account_tree", "listings": "view_list", "forms": "assignment",
	"media": "photo_library", "design": "palette", "sections": "dashboard_customize",
	"languages": "translate", "assist": "edit_note", "assistants": "smart_toy",
	"inbox": "inbox", "decisions": "rule", "notes": "sticky_note_2",
	"review": "rate_review", "publishing": "publish", "history": "history",
	"analytics": "analytics", "experiments": "science", "personalise": "tune",
	"transfer": "swap_horiz", "decentralised": "hub", "provenance": "verified",
	"security": "shield", "logs": "receipt_long", "findings": "flag",
	"risk": "warning", "cases": "cases", "events": "list_alt",
	"hunt": "travel_explore", "detections": "radar", "indicators": "fingerprint",
	"vulns": "bug_report", "workforce": "groups", "agents": "robot_2",
	"people": "person", "members": "group", "boards": "forum", "provisioning": "sync", "access": "key", "passkeys": "passkey",
	"integrations": "extension", "models": "memory", "settings": "settings",
	"find": "search", "start": "rocket_launch", "playground": "api",
	"profile": "account_circle",
}

var iconPath = func() map[string]string {
	out := map[string]string{}
	d := regexp.MustCompile(`<path d="([^"]+)"`)
	for key := range iconSymbol {
		b, err := assets.ReadFile("assets/icons/" + key + ".svg")
		if err != nil {
			continue
		}
		if m := d.FindSubmatch(b); m != nil {
			out[key] = strings.TrimSpace(string(m[1]))
		}
	}
	return out
}()

// iconFor is the drawing for a screen, or empty when it has none.
func iconFor(key string) string { return iconPath[key] }
