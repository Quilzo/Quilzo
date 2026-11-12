// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

// A model may name a page the store can hold, at the top level, and nothing
// the store would refuse.
//
// Its rule allowed 128 characters and the store's segment is 64, so a name
// of a hundred passed here, "kept in step with the store's own rule
// deliberately", and was refused by the store with a message about trees.
func TestAModelNamesPagesByTheStoresRule(t *testing.T) {
	oid := strings.Repeat("0", 64)
	for _, name := range []string{"About_Us", "v1.2", "home", strings.Repeat("a", 64)} {
		if err := store.CheckTreeEntries(map[string]string{name: oid}); err != nil {
			t.Fatalf("the store does not hold %q: %v", name, err)
		}
		if !ValidPageName(name) {
			t.Errorf("%q, a page the store holds, is refused", name)
		}
	}
	for _, name := range []string{strings.Repeat("a", 100), "docs/v1.2", ".hidden", "../x", ""} {
		if ValidPageName(name) {
			t.Errorf("%q is accepted", name)
		}
	}
}
