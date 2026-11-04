// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sheet

import (
	"regexp"
	"strings"
)

// One guard for every CSV Quilzo writes.
//
// A cell beginning = + - or @ is a formula to Excel, Numbers and Sheets,
// and =HYPERLINK or =WEBSERVICE sends the rest of the sheet to whoever
// typed it; a tab or a carriage return first is how a formula is smuggled
// past a filter that looks only at the first character. Quoting does not
// help: the escaping is correct CSV and the spreadsheet runs it anyway.
// An apostrophe first is the standard defusal (OWASP's CSV injection): the
// cell shows as typed and is not run.
//
// There were three copies of this, and they disagreed. The form export
// guarded a negative number, the records export let through anything
// strconv.ParseFloat reads (-Inf, -0x1p3), the subscriber export guarded
// the names and not the addresses, and the upload check could not see a
// tab. One rule now, used by every writer and by the upload check.

// formulaStarts are the first characters that make a cell a formula, or
// smuggle one.
const formulaStarts = "=+-@\t\r"

// rePlainDecimal is a number as a person writes one in a sheet: a sign,
// digits, and perhaps a decimal point. A spreadsheet reads it as a number
// and runs nothing.
var rePlainDecimal = regexp.MustCompile(`^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)$`)

// IsFormula reports whether a spreadsheet would run a cell as a formula:
// it begins = + - @ a tab or a carriage return, and is not a plain
// decimal number.
func IsFormula(s string) bool {
	if s == "" || !strings.ContainsRune(formulaStarts, rune(s[0])) {
		return false
	}
	return !rePlainDecimal.MatchString(s)
}

// GuardCell is a cell as it is written to a CSV: after an apostrophe when
// a spreadsheet would run it, and as it is otherwise. It changes the value,
// which is why it happens as a file is written and never to what is kept:
// a submission keeps what the person wrote.
func GuardCell(s string) string {
	if IsFormula(s) {
		return "'" + s
	}
	return s
}

// UnguardCell takes off the apostrophe a writer put before a cell that
// would otherwise be a formula, so what an export guarded comes back in as
// it went out.
func UnguardCell(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune(formulaStarts, rune(s[1])) {
		return s[1:]
	}
	return s
}
