// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package a11y

import "testing"

// The report's sentence about the European standard says every evaluated
// criterion is in both versions of it. A check added for a criterion new in
// WCAG 2.2 makes that untrue, and has to change the sentence.
func TestEveryEvaluatedCriterionIsInBothVersionsOfTheStandard(t *testing.T) {
	new22 := map[string]bool{"2.4.11": true, "2.4.12": true, "2.4.13": true,
		"2.5.7": true, "2.5.8": true, "3.2.6": true, "3.3.7": true, "3.3.8": true, "3.3.9": true}
	for _, line := range Covered() {
		for _, n := range criteriaIn(line) {
			if new22[n] {
				t.Errorf("%s is checked and is not in WCAG 2.1, so the report's "+
					"standard sentence (\"in both\") is now false: %s", n, line)
			}
		}
	}
	acr := BuildACR([]*Report{Check("p", `<html lang="en"><title>t</title><img src="a.png"></html>`)})
	if acr.Standard == "" {
		t.Fatal("no standard named")
	}
	for _, c := range acr.Evaluated {
		if c.Clause != "9."+c.Number {
			t.Errorf("%s has clause %q", c.Number, c.Clause)
		}
	}
}
