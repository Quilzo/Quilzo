// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"html"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
)

// The new frameworks are on the Frameworks screen, and a framework whose
// list Quilzo carries names each requirement as well as numbering it: NIS2's
// point (j) is a sentence about multi-factor authentication, and "Art.
// 21(2)(j)" alone sends the reader to look it up.
func TestTheFrameworkPagesNameNIS2AndTheAgenticList(t *testing.T) {
	srv, token := setup(t)
	withPosture(srv, brokenPosture())
	list := get(t, srv, "/security/frameworks", token).Body.String()
	whole(t, list)
	for _, want := range []string{"NIS2 Directive", "/security/frameworks/nis2",
		"OWASP Top 10 for Agentic Applications", "/security/frameworks/owasp-asi",
		"OWASP Top 10 for LLM Applications</a><br><span class=\"hint\">2026"} {
		if !strings.Contains(list, want) {
			t.Errorf("the Frameworks screen does not show %q", want)
		}
	}

	page := get(t, srv, "/security/frameworks/nis2", token).Body.String()
	whole(t, page)
	said := html.UnescapeString(page)
	for _, want := range []string{"Art. 21(2)(i)", "human resources security, access control policies and asset management",
		"Art. 21(2)(e)", "security in network and information systems acquisition"} {
		if !strings.Contains(said, want) {
			t.Errorf("the NIS2 page does not say %q", want)
		}
	}
	for _, path := range []string{"/security/frameworks", "/security/frameworks/nis2", "/security/frameworks/owasp-asi"} {
		body := get(t, srv, path, token).Body.String()
		for _, f := range a11y.Check(path, body).Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("%s: %s (%s): %s", path, f.Rule, f.Criterion, f.Detail)
			}
		}
	}
}
