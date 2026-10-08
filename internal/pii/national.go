// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package pii

import (
	"regexp"
	"strconv"
	"strings"
)

// National identity numbers.
//
// Only shapes that carry their own check, or a format nothing else is
// written in, so an order number, a price or a reference is not one: a
// false positive here masks a number a model needed, and a gate that
// fires on every reference is a gate people switch off. Each has the
// numbers its issuer publishes as examples, which are nobody's.
//
//   - United States Social Security number, written with its hyphens, with
//     the area, group and serial numbers that are never issued refused.
//   - United Kingdom National Insurance number, with the prefixes HMRC
//     never issues refused.
//   - Spanish DNI and NIE, whose last letter is a check on the digits.
//   - Indian Aadhaar, in its groups of four, whose last digit is a
//     Verhoeff check.
//   - Brazilian CPF, written with its dots and hyphen, with its two check
//     digits.
//   - Canadian Social Insurance number, written in three groups, passing
//     the Luhn check.
const NationalID Kind = "national_id"

type nationalShape struct {
	name string
	re   *regexp.Regexp
	ok   func(string) bool
}

var nationalShapes = []nationalShape{
	{"a US Social Security number", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), validSSN},
	{"a UK National Insurance number", regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`), validNINO},
	{"a Spanish identity number", regexp.MustCompile(`\b[XYZ]?\d{7,8}-?[A-Z]\b`), validDNI},
	// In its groups of four, as it is printed: twelve digits run together
	// are as often a product's barcode.
	{"an Aadhaar number", regexp.MustCompile(`\b[2-9]\d{3} \d{4} \d{4}\b`), validAadhaar},
	{"a Brazilian CPF", regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`), validCPF},
	{"a Canadian Social Insurance number", regexp.MustCompile(`\b\d{3}[ -]\d{3}[ -]\d{3}\b`), validSIN},
}

// nationalIDs is where national identity numbers are in text, and what
// each is.
func nationalIDs(text string) (locs [][]int, names []string) {
	for _, s := range nationalShapes {
		for _, l := range s.re.FindAllStringIndex(text, -1) {
			if !partOfLonger(text, l) && s.ok(text[l[0]:l[1]]) {
				locs = append(locs, l)
				names = append(names, s.name)
			}
		}
	}
	return locs, names
}

// partOfLonger reports a match that is the start or the middle of a longer
// run of digit groups, such as twelve of a card's sixteen digits.
func partOfLonger(text string, l []int) bool {
	digit := func(i int) bool { return i >= 0 && i < len(text) && text[i] >= '0' && text[i] <= '9' }
	sep := func(i int) bool {
		return i >= 0 && i < len(text) && (text[i] == ' ' || text[i] == '-' || text[i] == '.')
	}
	return (sep(l[1]) && digit(l[1]+1)) || (sep(l[0]-1) && digit(l[0]-2))
}

// The examples the issuers and their guides print.
var exampleNationalIDs = setOf(
	"078051120", "219099999", "123456789", // the Woolworth wallet card, the 1938 advertisement, and the obvious
	"QQ123456C", "AB123456C", // HMRC's
	"12345678Z", "X1234567L", // the Spanish ministry's
	"999941057058", "499118665246", // UIDAI's
	"12345678909", "11144477735", // Receita Federal's and the commonest in documentation
	"046454286", // the Government of Canada's
)

func validSSN(s string) bool {
	d := onlyDigits(s)
	area, _ := strconv.Atoi(d[:3])
	group, serial := d[3:5], d[5:]
	if area == 0 || area == 666 || area >= 900 || group == "00" || serial == "0000" {
		return false
	}
	return !exampleNationalIDs[d]
}

func validNINO(s string) bool {
	c := strings.ReplaceAll(s, " ", "")
	switch c[:2] {
	case "BG", "GB", "NK", "KN", "TN", "NT", "ZZ":
		return false
	}
	return !exampleNationalIDs[c]
}

func validDNI(s string) bool {
	c := strings.ReplaceAll(s, "-", "")
	digits := c[:len(c)-1]
	switch digits[0] {
	case 'X':
		digits = "0" + digits[1:]
	case 'Y':
		digits = "1" + digits[1:]
	case 'Z':
		digits = "2" + digits[1:]
	}
	// A DNI has eight digits; an NIE a letter and seven.
	if len(digits) != 8 || (c[0] >= '0' && c[0] <= '9' && len(c) != 9) {
		return false
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return false
	}
	return "TRWAGMYFPDXBNJZSQVHLCKE"[n%23] == c[len(c)-1] && !exampleNationalIDs[c]
}

// The Verhoeff check, dihedral group D5.
var (
	verhoeffD = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
)

func verhoeff(d string) bool {
	c := 0
	for i := 0; i < len(d); i++ {
		c = verhoeffD[c][verhoeffP[i%8][int(d[len(d)-1-i]-'0')]]
	}
	return c == 0
}

func validAadhaar(s string) bool {
	d := onlyDigits(s)
	return len(d) == 12 && verhoeff(d) && !exampleNationalIDs[d]
}

func validCPF(s string) bool {
	d := onlyDigits(s)
	if strings.Count(d, d[:1]) == len(d) { // 111.111.111-11 passes the check and is nobody's
		return false
	}
	for _, n := range []int{9, 10} {
		sum := 0
		for i := 0; i < n; i++ {
			sum += int(d[i]-'0') * (n + 1 - i)
		}
		check := sum * 10 % 11 % 10
		if check != int(d[n]-'0') {
			return false
		}
	}
	return !exampleNationalIDs[d]
}

func validSIN(s string) bool {
	d := onlyDigits(s)
	return d[0] != '0' && d[0] != '8' && luhn(d) && !exampleNationalIDs[d]
}
