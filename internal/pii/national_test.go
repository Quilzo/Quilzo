// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package pii

import (
	"strings"
	"testing"
)

// Made-up numbers that pass each issuer's check: nobody's.
func TestANationalIdentityNumberIsFound(t *testing.T) {
	for name, text := range map[string]string{
		"ssn":        "My SSN is 536-22-1490, please update it.",
		"nino":       "NI number JM 52 40 18 B on the form.",
		"nino tight": "nino JM524018B",
		"dni":        "DNI 48291037F adjunto.",
		"nie":        "NIE Y5627481Q",
		"aadhaar":    "Aadhaar 7382 1946 5029 for KYC.",
		"cpf":        "CPF 286.153.940-24",
		"sin":        "SIN 193 456 787",
	} {
		hits := Scan(text, nil)
		if len(hits) != 1 || hits[0].Kind != NationalID {
			t.Errorf("%s: %v", name, hits)
			continue
		}
		// Shown only in part.
		if strings.Contains(hits[0].Shown, "536-22") || strings.Contains(hits[0].Shown, "5627481") {
			t.Errorf("%s: shown whole: %s", name, hits[0].Shown)
		}
		var m Masker
		if out := m.Mask(text, false); strings.Contains(out, "<quilzo:national_id:1>") == false {
			t.Errorf("%s: not masked: %s", name, out)
		} else if m.Restore(out) != text {
			t.Errorf("%s: not restored", name)
		}
		// A route that may receive personal data receives it.
		if out := (&Masker{}).Mask(text, true); out != text {
			t.Errorf("%s: masked for a personal route: %s", name, out)
		}
	}
}

// What is shaped like one and is not.
func TestWhatIsShapedLikeANationalNumberIsNotOne(t *testing.T) {
	for name, text := range map[string]string{
		"ssn never issued":     "Ref 666-12-3456 and 000-12-3456 and 912-34-5678 and 123-00-4567",
		"ssn example":          "e.g. 078-05-1120",
		"nino never issued":    "GB 12 34 56 A, ZZ123456C",
		"nino example":         "QQ123456C",
		"dni wrong letter":     "48291037P",
		"aadhaar wrong digit":  "7382 1946 5020",
		"aadhaar run together": "UPC 738219465029",
		"cpf wrong digits":     "286.153.940-25",
		"cpf one digit":        "111.111.111-11",
		"sin fails luhn":       "193 456 788",
		"card":                 "4539 1488 0343 6467",
		"date":                 "2026-10-07",
		"order":                "Order 2026 1007 4411 shipped",
		"price":                "Price 1 299 000",
	} {
		for _, h := range Scan(text, nil) {
			if h.Kind == NationalID {
				t.Errorf("%s: %q found as %s", name, text, h.Shown)
			}
		}
	}
}
