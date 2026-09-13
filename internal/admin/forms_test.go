// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Declaring a form keeps what was ticked.
//
// The create branch built its first field by hand with three of the seven
// inputs the panel sends, so one screen with one form posting to one route
// disagreed with itself about what a field is. Ticking "Sensitive" while
// creating a form stored Sensitive:false — personal data in the submissions
// listing the operator had just asked to keep it out of — and choosing
// "choice" with the choices typed in stored none of them, after which Validate
// refused the form for having no choices, naming the ones they had typed.
func TestDeclaringAFormKeepsWhatWasTicked(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/forms/save",
		strings.NewReader("form=contact&label=Contact&notice=we+reply&"+
			"field=topic&field_label=Topic&field_kind=choice&"+
			"choices=sales,+support&required=1&sensitive=1&"+
			"field_help=pick+one"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	f := formFieldFromRequest(r)
	if !f.Required {
		t.Error("Required was ticked and the field is not required")
	}
	if !f.Sensitive {
		t.Error("Sensitive was ticked and the field is not sensitive, so " +
			"personal data appears in the listing it was meant to stay out of")
	}
	if len(f.Choices) != 2 || f.Choices[0] != "sales" || f.Choices[1] != "support" {
		t.Errorf("the choices were dropped: %v", f.Choices)
	}
	if f.Help != "pick one" {
		t.Errorf("the help text was dropped: %q", f.Help)
	}
}
