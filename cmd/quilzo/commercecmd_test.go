// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/commerce"
	"github.com/quilzo/quilzo/internal/out"
)

// The keygen makes a key the loader reads back, and refuses to make a
// second one over the first — which would orphan every outstanding
// checkout at a stroke.
func TestCommerceKeygenMakesOneKeyAndGuardsIt(t *testing.T) {
	w = out.New(false)
	root := t.TempDir()
	if err := cmdCommerce(root, []string{"keygen"}); err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	key, err := commerce.LoadMerchantKey(filepath.Join(root, "commerce", "merchant.json"))
	if err != nil {
		t.Fatalf("the key it made does not load: %v", err)
	}
	if key.KeyID == "" || key.Private == nil {
		t.Fatalf("the key is incomplete: %+v", key)
	}
	info, err := os.Stat(filepath.Join(root, "commerce", "merchant.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the key file is %v, not 0600", info.Mode().Perm())
	}
	if err := cmdCommerce(root, []string{"keygen"}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("a second keygen was allowed: %v", err)
	}
}

// The order book reads back empty and then full, the way an operator reads
// it the morning after an agent has been shopping.
func TestCommerceOrdersReadsTheBook(t *testing.T) {
	w = out.New(false)
	root := t.TempDir()
	if err := cmdCommerce(root, []string{"orders"}); err != nil {
		t.Fatalf("an empty book failed to read: %v", err)
	}
	at := "2026-10-15T10:00:00Z"
	book := `{"orders":[{"id":"od_1","at":"` + at + `","agent":"ExampleAgent",` +
		`"checkout_id":"cs_1","currency":"GBP","total":2400,` +
		`"lines":[{"item_id":"notebook","title":"Linen Notebook","quantity":1,` +
		`"unit_amount":2400,"amount":2400}],"payment_state":"none_presented",` +
		`"status":"placed"}],"used":{}}`
	if err := os.WriteFile(commerce.OrdersPath(root), []byte(book), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdCommerce(root, []string{"orders"}); err != nil {
		t.Fatalf("a filled book failed to read: %v", err)
	}
	// The JSON form rides the global --json, stripped in main before the
	// command sees its arguments.
	if err := cmdCommerce(root, []string{"orders"}); err != nil {
		t.Fatalf("the plain form failed again: %v", err)
	}
}
