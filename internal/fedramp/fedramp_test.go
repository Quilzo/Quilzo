// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

// "Contributes" is documented as Quilzo implementing related controls with
// its checks on them passing, and it was given to every indicator with a
// related control Quilzo implements, whether or not anything checks it: only
// a failing check was looked at, and a control with no check cannot fail.
// A provider reads "contributes" as evidence that runs; for those indicators
// there is only a statement, and the standing says so.
func TestContributingTakesACheckThatIsPassing(t *testing.T) {
	_, res, err := Assess(nil)
	if err != nil {
		t.Fatal(err)
	}
	unchecked := 0
	for _, r := range res {
		checked := false
		for _, e := range r.Evidence {
			checked = checked || len(e.Rules) > 0
		}
		if r.Standing == Contributes && !checked {
			t.Errorf("%s contributes, and none of the %d related controls Quilzo "+
				"implements is checked by anything", r.ID, r.Covered)
		}
		if r.Covered > 0 && !checked {
			unchecked++
			if r.Standing == Elsewhere {
				t.Errorf("%s relates controls Quilzo implements and says it has "+
					"nothing to show", r.ID)
			}
		}
		if r.Covered > 0 && checked && r.Standing != Contributes {
			t.Errorf("%s has a passing check and is %s", r.ID, r.Standing)
		}
	}
	if unchecked == 0 {
		t.Fatal("no indicator relates only controls nothing checks; this test " +
			"needs one to tell a check from a statement")
	}
}
