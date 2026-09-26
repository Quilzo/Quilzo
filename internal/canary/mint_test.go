// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package canary

import "testing"

// TestMintNeverProducesAValueValidateWouldRefuse.
//
// The two used to disagree: the address alphabet contains a, r, t and p, so
// a twenty-character draw spells "trap" about once in fifty thousand. That
// is never in a morning's testing and eventually in CI.
func TestMintNeverProducesAValueValidateWouldRefuse(t *testing.T) {
	for _, k := range Kinds() {
		for range 2000 {
			v, err := Mint(k)
			if err != nil {
				t.Fatalf("%s: %v", k, err)
			}
			if w, bad := Giveaway(v); bad {
				t.Fatalf("%s minted %q, which contains %q — the word list "+
					"and the alphabet disagree", k, v, w)
			}
		}
	}
}

// TestGiveawayIsWhatValidateUses, so the two cannot drift apart.
func TestGiveawayIsWhatValidateUses(t *testing.T) {
	c := Canary{
		ID: Ident("x"), Kind: AsCredential, Value: "AAAATRAPAAAA",
		Where: "s3://acme/x", Why: "nothing reads this",
		Planted: now, State: Armed,
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("a value spelling a giveaway was accepted")
	}
	if w, bad := Giveaway(c.Value); !bad || w != "trap" {
		t.Fatalf("Giveaway says %q, %v", w, bad)
	}
}
