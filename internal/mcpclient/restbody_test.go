// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"strings"
	"testing"
)

// A body goes out only as the operation describes it: a field it does not
// list, or a value of the wrong type, is refused before anything is sent.
func TestARESTBodyIsCheckedAgainstItsSchema(t *testing.T) {
	in := billing()
	c, calls := restClient(200, "{}")
	for _, bad := range []map[string]any{
		{"amount": 5, "approved_by": "finance"},
		{"amount": "five"},
		{"amount": []any{5}},
	} {
		if _, err := c.Call(context.Background(), in, "createInvoice", map[string]any{"body": bad}); err == nil ||
			!strings.Contains(err.Error(), "createInvoice") {
			t.Errorf("%v was sent: %v", bad, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("%d refused body(ies) reached the API", len(*calls))
	}
	if _, err := c.Call(context.Background(), in, "createInvoice", map[string]any{"body": map[string]any{"amount": 5}}); err != nil {
		t.Fatal(err)
	}
}
