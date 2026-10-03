// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"html/template"
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
	"vulns": "bug_report", "workforce": "groups", "automations": "bolt", "signins": "login", "feeds": "sensors", "agents": "robot_2",
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

// filledFor is the screen's symbol filled, as Material draws the selected
// destination in a navigation; the outline when there is no filled file.
func filledFor(key string) string {
	if p := readPath("assets/icons/" + key + ".fill.svg"); p != "" {
		return p
	}
	return iconPath[key]
}

// pathData is what a Material Symbol's path may contain: drawing commands
// and numbers. Checked at load, because an icon is written into the page as
// markup, and a file that held anything else would be markup we never
// wrote.
var pathData = regexp.MustCompile(`^[MmLlHhVvCcSsQqTtAaZz0-9.,\- ]+$`)

// readPath is the single path of an embedded icon file, or empty.
func readPath(name string) string {
	b, err := assets.ReadFile(name)
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`<path d="([^"]+)"`).FindSubmatch(b)
	if m == nil {
		return ""
	}
	p := strings.TrimSpace(string(m[1]))
	if !pathData.MatchString(p) {
		panic(fmt.Sprintf("%s: not a drawing: %.40q", name, p))
	}
	return p
}

// uiIcon is a control's icon — the menu, search, the theme, a chevron —
// from the same Material Symbols, Rounded, as the navigation, kept in
// assets/icons as ui-<name>.svg. Every icon the interface draws comes from
// there: none is drawn by hand, so they are one family.
//
// An unknown name is an error rather than nothing, so a template that asks
// for an icon that is not there fails its tests instead of drawing a gap.
func uiIcon(name string) (template.HTML, error) {
	p := readPath("assets/icons/ui-" + name + ".svg")
	if p == "" {
		return "", fmt.Errorf("no icon %q: fetch the Material Symbol into assets/icons/ui-%s.svg", name, name)
	}
	// #nosec G203 -- p is an embedded file's path data, checked above to be
	// drawing commands and numbers only.
	return template.HTML(`<svg class="icon" viewBox="0 -960 960 960" fill="currentColor" aria-hidden="true" focusable="false"><path d="` + p + `"/></svg>`), nil
}

// toneIcon is the symbol beside a severity word, so it is never colour
// alone that says how bad something is.
func toneIcon(tone string) string {
	switch tone {
	case "good":
		return "check_circle"
	case "warning":
		return "error"
	case "serious":
		return "warning"
	case "unknown":
		return "help"
	case "low":
		return "info"
	default:
		return "dangerous"
	}
}

// sectionSymbol is the Material Symbol for each section of the navigation,
// drawn on the rail the menu collapses to. None is a screen's own symbol,
// so a section never looks like one of its screens. The file is
// section-<slug>.svg.
var sectionSymbol = map[string]string{
	"Content": "article", "Release": "send", "Assurance": "verified_user",
	"Security operations": "policy", "Administration": "admin_panel_settings",
	"Reference": "menu_book",
}

var sectionPath = func() map[string]string {
	out := map[string]string{}
	for name := range sectionSymbol {
		if p := readPath("assets/icons/section-" + sectionSlug(name) + ".svg"); p != "" {
			out[name] = p
		}
	}
	return out
}()

// sectionFilled is each section's symbol filled, for the one being worked in.
var sectionFilled = func() map[string]string {
	out := map[string]string{}
	for name := range sectionSymbol {
		if p := readPath("assets/icons/section-" + sectionSlug(name) + ".fill.svg"); p != "" {
			out[name] = p
		} else {
			out[name] = sectionPath[name]
		}
	}
	return out
}()

// sectionSlug is a section's name as a file and element name.
func sectionSlug(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), " ", "-")
}

// sectionShort is a section's name where the rail has room for one word.
// Each is the start of the full name, which a screen reader hears instead,
// so what is seen is always part of what is heard.
//
// Security operations is Operations rather than Security, which is already
// the name of a screen.
var sectionShort = map[string]string{"Security operations": "Operations", "Administration": "Admin"}
