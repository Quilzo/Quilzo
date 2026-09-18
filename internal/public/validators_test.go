// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http"
	"testing"
)

// A browser that holds two representations of a URL sends both validators, and
// this server used to compare the whole header against one tag and find they
// were not equal — so the cache never hit and nothing anywhere said so. These
// tests drive the three routes that do the comparison.
func TestASecondValidatorStillRevalidates(t *testing.T) {
	st, _ := setup(t)
	st.Stylesheet = ":root { --x: 1 }"

	for _, route := range []string{"/", "/site.css"} {
		first := get(st, route, nil)
		tag := first.Header().Get("ETag")
		if tag == "" {
			t.Fatalf("%s served no ETag", route)
		}

		// The order a browser actually sends: most recent first, and the one
		// this server holds is not it.
		both := `"something-else", ` + tag
		again := get(st, route, map[string]string{"If-None-Match": both})
		if again.Code != http.StatusNotModified {
			t.Errorf("%s: sent the whole body to a client already holding it "+
				"(If-None-Match: %s, got %d)", route, both, again.Code)
		}
	}
}

// A proxy is allowed to weaken a validator in transit. Refusing it means the
// reader pays for the proxy's transformation.
func TestAWeakenedValidatorStillRevalidates(t *testing.T) {
	st, _ := setup(t)
	first := get(st, "/", nil)
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("no ETag")
	}
	again := get(st, "/", map[string]string{"If-None-Match": "W/" + tag})
	if again.Code != http.StatusNotModified {
		t.Errorf("a weakened tag was treated as a different page, got %d", again.Code)
	}
}

// Correct parsing must not become permissive parsing: a client holding some
// other page's copy still gets this page.
func TestAnUnrelatedValidatorStillGetsTheBody(t *testing.T) {
	st, _ := setup(t)
	for _, header := range []string{`"nope"`, `"a", "b"`, `""`} {
		res := get(st, "/", map[string]string{"If-None-Match": header})
		if res.Code != http.StatusOK {
			t.Errorf("If-None-Match: %s answered %d, not the page", header, res.Code)
		}
	}
}
