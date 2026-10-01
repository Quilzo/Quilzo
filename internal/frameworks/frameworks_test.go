// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package frameworks_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/frameworks"
	"github.com/quilzo/quilzo/internal/posture"
)

// A control maps to the FedRAMP baselines it is allocated to, and an
// enhancement allocated differently says so.
func TestAControlCarriesItsBaselines(t *testing.T) {
	refs := frameworks.Refs("x", []string{"AC-6"})
	got := map[string]bool{}
	for _, r := range refs {
		got[r.String()] = true
	}
	for _, want := range []string{"nist-800-53 AC-6", "fedramp-moderate AC-6",
		"fedramp-high AC-6", "iso-27001 A.8.2", "soc2 CC6.3"} {
		if !got[want] {
			t.Errorf("AC-6 does not map to %s: %v", want, refs)
		}
	}
	if got["fedramp-low AC-6"] {
		t.Error("AC-6 is mapped to the Low baseline, which does not include it")
	}
	// An enhancement not listed on its own falls back to its control.
	enh := frameworks.Refs("x", []string{"AU-9(2)"})
	var low bool
	for _, r := range enh {
		low = low || r.String() == "fedramp-low AU-9(2)"
	}
	if !low {
		t.Errorf("AU-9(2) did not inherit AU-9's baselines: %v", enh)
	}
}

var shapes = map[string]*regexp.Regexp{
	"nist-800-53":      regexp.MustCompile(`^[A-Z]{2}-\d+(\(\d+\))?$`),
	"fedramp-low":      regexp.MustCompile(`^[A-Z]{2}-\d+(\(\d+\))?$`),
	"fedramp-moderate": regexp.MustCompile(`^[A-Z]{2}-\d+(\(\d+\))?$`),
	"fedramp-high":     regexp.MustCompile(`^[A-Z]{2}-\d+(\(\d+\))?$`),
	"iso-27001":        regexp.MustCompile(`^A\.[5-8]\.\d{1,2}$`),
	"soc2":             regexp.MustCompile(`^(CC\d\.\d|C1\.\d|A1\.\d)$`),
	"nist-csf":         regexp.MustCompile(`^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$`),
	"hipaa":            regexp.MustCompile(`^164\.3\d\d\(`),
	"gdpr":             regexp.MustCompile(`^Art\. \d+`),
	"ccpa":             regexp.MustCompile(`^§ 1798\.\d+`),
	"eu-ai-act":        regexp.MustCompile(`^Art\. \d+`),
	"nist-ai-rmf":      regexp.MustCompile(`^(GOVERN|MAP|MEASURE|MANAGE) \d+\.\d+$`),
	"iso-42001":        regexp.MustCompile(`^A\.\d+\.\d+(\.\d+)?$`),
	"owasp-llm":        regexp.MustCompile(`^LLM(0[1-9]|10)$`),
}

// Every reference names a framework in the catalogue and is shaped like an
// identifier in it, so a typo cannot pass as a citation.
func TestEveryReferenceIsShapedLikeItsFramework(t *testing.T) {
	for _, r := range posture.Rules() {
		for _, ref := range frameworks.Refs(r.ID, r.Controls) {
			if _, ok := frameworks.Get(ref.Framework); !ok {
				t.Errorf("%s cites %q, which is not in the catalogue", r.ID, ref.Framework)
				continue
			}
			if re := shapes[ref.Framework]; re == nil || !re.MatchString(ref.ID) {
				t.Errorf("%s cites %s, which is not shaped like an identifier in it", r.ID, ref)
			}
		}
	}
	if len(shapes) != len(frameworks.Catalogue) {
		t.Errorf("%d frameworks and %d shapes; a new framework needs one",
			len(frameworks.Catalogue), len(shapes))
	}
}

// Each framework is cited by at least one check, or it is in the
// catalogue for show.
func TestEveryFrameworkIsCitedBySomething(t *testing.T) {
	cited := map[string]int{}
	for _, r := range posture.Rules() {
		for _, ref := range frameworks.Refs(r.ID, r.Controls) {
			cited[ref.Framework]++
		}
	}
	for _, f := range frameworks.Catalogue {
		if cited[f.ID] == 0 {
			t.Errorf("%s is listed and no check bears on it", f.Name)
		}
		if f.About == "" || !strings.HasPrefix(f.URL, "https://") {
			t.Errorf("%s does not say what it is or where to read it", f.Name)
		}
	}
}
