// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"strings"
	"testing"
)

// A record is one passage of its fields, named by its title, without the
// fields that are about a person, and citing nowhere; one with nothing to
// say is not a passage.
func TestARecordIsAPassageWithoutAnybodysDetails(t *testing.T) {
	ps := ChunkRecords("products", []RecordText{
		{ID: "p1", Fields: map[string]any{"name": "Desk blotter", "price": 24.0, "dimensions": "600 × 400mm",
			"in_stock": true, "supplier_email": "jo@supplier.example", "phone": "07700 900123", "tags": []any{"desk", "paper"}}},
		{ID: "p2", Fields: map[string]any{"email": "only@personal.example"}},
	})
	if len(ps) != 1 {
		t.Fatalf("%+v", ps)
	}
	p := ps[0]
	if p.Title != "Desk blotter" || p.Heading != "products" || p.Record != "products/p1" || p.Link() != "" {
		t.Errorf("%+v", p)
	}
	for _, want := range []string{"price: 24", "dimensions: 600 × 400mm", "in stock: yes", "tags: desk, paper"} {
		if !strings.Contains(p.Text, want) {
			t.Errorf("%q does not say %q", p.Text, want)
		}
	}
	for _, leak := range []string{"jo@supplier", "07700"} {
		if strings.Contains(p.Text, leak) {
			t.Errorf("%q kept %q", p.Text, leak)
		}
	}
	bad := Assistant{Name: "h", Title: "H", Collections: []string{"Products!"}}
	if err := bad.Validate(); err == nil {
		t.Error("a collection that is not one")
	}
}
