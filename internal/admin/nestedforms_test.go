// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// No screen puts a form inside a form.
//
// Browsers drop an inner <form> tag, so its fields and its button belong to
// the outer form and post there. The Pages screen did this for a year: each
// row's Remove button sat in a form inside the bulk-action form, so pressing
// it posted the bulk form with no action chosen and removed nothing. A
// button that belongs to a different form says so with form="id" instead.
func TestNoScreenNestsAForm(t *testing.T) {
	srv, token := fullyWired(t)
	tag := regexp.MustCompile(`(?i)<(/?)form\b`)
	var routes []string
	for r := range servedRoutes(t) {
		if strings.HasSuffix(r, "/") && r != "/" {
			continue
		}
		if _, excused := notAScreen[r]; excused {
			continue
		}
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, path := range append(routes, "/page/index") {
		w := get(t, srv, path, token)
		if w.Code != http.StatusOK {
			continue
		}
		depth := 0
		for _, m := range tag.FindAllStringSubmatch(w.Body.String(), -1) {
			if m[1] == "/" {
				depth--
				continue
			}
			depth++
			if depth > 1 {
				t.Errorf("%s has a form inside a form; the inner one is dropped "+
					"by the browser and its button posts the outer one", path)
				break
			}
		}
	}
}
