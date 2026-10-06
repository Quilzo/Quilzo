// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package fedramp

import (
	"regexp"
	"testing"
)

// The embedded list is FedRAMP's: indicators with ids, statements and
// controls in OSCAL's form, from a dated version.
func TestTheIndicatorsAreFedRAMPs(t *testing.T) {
	src, all, err := Indicators()
	if err != nil {
		t.Fatal(err)
	}
	if src.Version == "" || src.LastUpdated == "" || len(all) < 40 {
		t.Fatalf("%+v, %d indicators", src, len(all))
	}
	id := regexp.MustCompile(`^KSI-[A-Z]{3}-[A-Z]{3}$`)
	ctl := regexp.MustCompile(`^[a-z]{2}-\d+(\.\d+)?$`)
	for _, in := range all {
		if !id.MatchString(in.ID) || in.Statement == "" {
			t.Errorf("%q is not an indicator", in.ID)
		}
		for _, c := range in.Controls {
			if !ctl.MatchString(c) {
				t.Errorf("%s relates %q, not an OSCAL control id", in.ID, c)
			}
		}
	}
}

// Quilzo contributes where it implements a related control, fails where a
// check on one is failing, and says so where it has nothing to show.
func TestEachIndicatorSaysWhatQuilzoHasToShow(t *testing.T) {
	_, clean, err := Assess(nil)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Result{}
	for _, r := range clean {
		by[r.ID] = r
	}
	if r := by["KSI-CMT-LMC"]; r.Standing != Contributes || r.Covered == 0 {
		t.Errorf("logging changes: %s, %d", r.Standing, r.Covered)
	}
	if r := by["KSI-CED-RAT"]; r.Standing != Elsewhere || len(r.Evidence) != 0 {
		t.Errorf("training is the provider's: %s", r.Standing)
	}
	_, failing, _ := Assess(map[string][]string{"au-2": {"audit.empty: the log is empty"}})
	for _, r := range failing {
		for _, e := range r.Evidence {
			if e.Control == "AU-2" && r.Standing != Failing {
				t.Errorf("%s relates a failing AU-2 and is %s", r.ID, r.Standing)
			}
		}
	}
}
