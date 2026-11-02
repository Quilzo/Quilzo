// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/form"
)

// A form with a question asked only on an answer has a stylesheet that
// hides it, the layout is told where it is and in what words, the control
// is not required in the markup, and the server asks it only on the
// answer.
func TestAQuestionAskedOnAnAnswerOnThePublicSite(t *testing.T) {
	st, fs := withForm(t)
	set := &form.Set{Forms: []form.Form{{Name: "contact", Notice: "Kept 90 days.", Fields: []form.Field{
		{Name: "topic", Label: "Topic", Kind: form.Choice, Choices: []string{"Question", "Returns"}, Required: true},
		{Name: "order", Label: "Order number", Kind: form.Line, Required: true, When: &form.When{Field: "topic", Is: "Returns"}},
	}}}}
	st.Forms.Set = func() (*form.Set, error) { return set, nil }

	w := get(st, "/form/contact.css", nil)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") ||
		!strings.Contains(w.Body.String(), "#f-order-field{display:none}") {
		t.Fatalf("%d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if w := get(st, "/form/nothing.css", nil); w.Code != http.StatusNotFound {
		t.Errorf("a stylesheet for no form: %d", w.Code)
	}
	data := st.formData("contact")
	if data["style"] != "/form/contact.css" {
		t.Fatalf("%v", data["style"])
	}
	order := data["fields"].([]any)[1].(map[string]any)
	if order["required"] != false || !strings.Contains(order["when"].(string), "Returns") {
		t.Fatalf("%v", order)
	}

	stamp := fmt.Sprint(time.Now().Add(-5 * time.Second).Unix())
	if w := post(t, st, "/form/contact", url.Values{"topic": {"Returns"}, form.StampField: {stamp}}); w.Code == http.StatusOK || w.Code == http.StatusSeeOther {
		t.Fatalf("asked and not answered: %d", w.Code)
	}
	if w := post(t, st, "/form/contact", url.Values{"topic": {"Question"}, "order": {"not asked"}, form.StampField: {stamp}}); w.Code >= 400 {
		t.Fatalf("refused without the question asked: %d %s", w.Code, w.Body.String())
	}
	subs, err := fs.List("contact")
	if err != nil || len(subs) != 1 {
		t.Fatalf("%d %v", len(subs), err)
	}
	if _, kept := subs[0].Values["order"]; kept {
		t.Fatal("kept an answer to a question not asked")
	}
}
