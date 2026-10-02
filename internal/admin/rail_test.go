// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// Collapsed, the menu is a rail of its sections, not nothing: each section
// is a button that opens the one menu, drawn with its own icon, and the
// section being worked in is marked.
func TestTheCollapsedMenuIsARailOfItsSections(t *testing.T) {
	srv, token := setup(t)
	req := httptest.NewRequest("GET", "/security/frameworks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: SidebarCookie, Value: "hidden"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()

	item := regexp.MustCompile(`<button type="button" class="railitem( here)?" popovertarget="sitenav" popovertargetaction="show" data-section="([a-z-]+)">\s*<span class="railpill"><svg class="navicon"[^>]*><path d="[^"]+"/></svg></span>\s*<span class="raillabel" aria-hidden="true">([^<]+)</span><span class="visually-hidden">([^<]+)</span>`)
	found := item.FindAllStringSubmatch(body, -1)
	groups := strings.Count(body, `<details class="navgroup"`)
	if len(found) == 0 || len(found) != groups {
		t.Fatalf("%d rail buttons for %d sections", len(found), groups)
	}
	here := 0
	for _, m := range found {
		if m[1] != "" {
			here++
			if m[4] != "Assurance" {
				t.Errorf("the rail marks %s, not the section this screen is in", m[4])
			}
		}
		// What is seen is part of what is heard (WCAG 2.5.3).
		if !strings.Contains(strings.ToLower(m[4]), strings.ToLower(m[3])) {
			t.Errorf("the rail shows %q for %q; a speech user saying what they see would not reach it", m[3], m[4])
		}
		if !strings.Contains(body, `<details class="navgroup" data-section="`+m[2]+`"`) {
			t.Errorf("rail button %q names no section of the menu", m[2])
		}
	}
	if here != 1 {
		t.Errorf("%d rail buttons are marked as the current section, want 1", here)
	}
}

// Every section has its own icon, and none is a screen's icon, so a section
// never looks like one of its screens.
func TestEverySectionHasItsOwnIcon(t *testing.T) {
	screens := map[string]bool{}
	for _, d := range destinations {
		screens[iconFor(d.Key)] = true
	}
	for _, g := range groups {
		p := sectionPath[g]
		if p == "" {
			t.Errorf("section %q has no icon; add section-%s.svg and sectionSymbol", g, sectionSlug(g))
		}
		if screens[p] {
			t.Errorf("section %q is drawn with a screen's icon", g)
		}
	}
}

// The rail is only ever the wide screen's collapsed menu; a phone has the
// drawer, and the expanded menu has no rail beside it.
func TestTheRailShowsOnlyWhenTheWideMenuIsCollapsed(t *testing.T) {
	css := stylesheet(t)
	if !strings.Contains(css, ".rail { display: none; }") ||
		!regexp.MustCompile(`@media \(min-width: 60rem\) \{\s*body\.nav-hidden:has\(> \.sidenav\) \{ grid-template-columns: 72px 1fr;[^}]*\}\s*body\.nav-hidden > \.rail \{ grid-area: rail; display: flex;`).MatchString(css) {
		t.Error("the rail is not hidden by default and shown only for a collapsed wide menu")
	}
}
