// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sheet

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/schema"
)

// value reads a cell as its field's kind, or says why it cannot.
func value(f schema.Field, cell, order string, decimalComma bool) (any, string) {
	s := strings.TrimSpace(cell)
	switch f.Kind {
	case schema.Number:
		n, ok := number(s, decimalComma)
		if !ok {
			return nil, fmt.Sprintf("%q is not a number", plaintext.Clip(s, maxQuoted, "…"))

		}
		return n, ""
	case schema.Boolean:
		b, ok := yesNo(s)
		if !ok {
			return nil, fmt.Sprintf("%q is not yes or no", plaintext.Clip(s, maxQuoted, "…"))

		}
		return b, ""
	case schema.Date:
		d, ok := date(s, order)
		if !ok {
			return nil, fmt.Sprintf("%q is not a date", plaintext.Clip(s, maxQuoted, "…"))

		}
		return d, ""
	case schema.Time:
		t, ok := clock(s)
		if !ok {
			return nil, fmt.Sprintf("%q is not a time of day", plaintext.Clip(s, maxQuoted, "…"))

		}
		return t, ""
	case schema.List:
		return list(s), ""
	case schema.Choice:
		for _, c := range f.Choices {
			if strings.EqualFold(c, s) || norm(c) == norm(s) {
				return c, ""
			}
		}
		return s, ""
	case schema.Slug:
		if !reSlug(s) {
			return Slug(s), ""
		}
		return s, ""
	case schema.URL:
		if !strings.Contains(s, "://") && !strings.ContainsAny(s, " \t") && strings.Contains(s, ".") &&
			!strings.HasPrefix(s, "/") {
			return "https://" + s, ""
		}
		return s, ""
	case schema.Email:
		return strings.TrimSpace(strings.TrimPrefix(s, "mailto:")), ""
	case schema.LongText:
		return strings.TrimSpace(strings.ReplaceAll(cell, "\r\n", "\n")), ""
	case schema.Text:
		return strings.Join(strings.Fields(cell), " "), ""
	}
	return s, ""
}

// guess reads a cell of a collection with no type: true and false are
// yes and no, a plain number is a number, and the rest is words. A number
// written with a leading nought, such as a postcode or a phone number, is
// words, as it is to the person who wrote it.
func guess(cell string) any {
	s := strings.TrimSpace(cell)
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	if plainNumber(s) {
		if n, err := strconv.ParseFloat(s, 64); err == nil && !math.IsInf(n, 0) {
			return n
		}
	}
	return strings.ReplaceAll(cell, "\r\n", "\n")
}

func plainNumber(s string) bool {
	s = strings.TrimPrefix(s, "-")
	whole, frac, dotted := strings.Cut(s, ".")
	if whole == "" || len(whole) > 15 || (len(whole) > 1 && whole[0] == '0') || (dotted && frac == "") {
		return false
	}
	for _, r := range whole + frac {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// maxQuoted is how much of a cell a problem quotes, in bytes with its mark:
// enough to find the cell by, not the whole of it again.
const maxQuoted = 40

func reSlug(s string) bool {
	if s == "" || s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// Slug is a page link made from words: lower case, hyphens between.
func Slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r < 128 && (r >= 'a' && r <= 'z' || r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		case r == '\'' || r == '’':
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 80 {
		out = strings.TrimRight(out[:80], "-")
	}
	return out
}

// number reads a number as people write one: £1,250.00, 1.250,00 in a
// sheet from a country that writes a decimal comma, 1 250, 12'500.
func number(s string, decimalComma bool) (float64, bool) {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r), r == '\'', r == '_':
			return -1
		case strings.ContainsRune("$£€¥₹₩₽¢₦₱฿₺₴", r):
			return -1
		}
		return r
	}, s)
	if s == "" {
		return 0, false
	}
	dot, comma := strings.LastIndex(s, "."), strings.LastIndex(s, ",")
	switch {
	case dot >= 0 && comma >= 0:
		// Whichever comes last is the decimal point.
		if comma > dot {
			s = strings.ReplaceAll(strings.ReplaceAll(s, ".", ""), ",", ".")
		} else {
			s = strings.ReplaceAll(s, ",", "")
		}
	case comma >= 0:
		if !decimalComma && thousands(s, ',') {
			s = strings.ReplaceAll(s, ",", "")
		} else if strings.Count(s, ",") == 1 {
			s = strings.Replace(s, ",", ".", 1)
		} else {
			return 0, false
		}
	case dot >= 0 && decimalComma && thousands(s, '.'):
		s = strings.ReplaceAll(s, ".", "")
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, false
	}
	return n, true
}

// thousands says whether sep separates groups of three digits: 1,250,000.
func thousands(s string, sep rune) bool {
	parts := strings.Split(strings.TrimPrefix(s, "-"), string(sep))
	if len(parts) < 2 || len(parts[0]) == 0 || len(parts[0]) > 3 {
		return false
	}
	for _, p := range parts[1:] {
		if len(p) != 3 {
			return false
		}
	}
	return true
}

func yesNo(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "y", "1", "on", "x", "✓", "✔", "t":
		return true, true
	case "false", "no", "n", "0", "off", "✗", "✘", "f", "-":
		return false, true
	}
	return false, false
}

// list reads several values in one cell: a JSON list, as a list is
// written when its items hold separators, or items between semicolons,
// bars or commas, the first of those the cell has.
func list(s string) []any {
	if strings.HasPrefix(s, "[") {
		var items []any
		if json.Unmarshal([]byte(s), &items) == nil {
			out := make([]any, 0, len(items))
			for _, it := range items {
				if str, ok := it.(string); ok && strings.TrimSpace(str) != "" {
					out = append(out, strings.TrimSpace(str))
				} else if !ok && it != nil {
					out = append(out, fmt.Sprint(it))
				}
			}
			return out
		}
	}
	sep := ","
	for _, c := range []string{";", "|", "\n"} {
		if strings.Contains(s, c) {
			sep = c
			break
		}
	}
	out := []any{}
	for _, it := range strings.Split(s, sep) {
		if it = strings.TrimSpace(it); it != "" {
			out = append(out, it)
		}
	}
	return out
}

// -- Dates and times ------------------------------------------------------------

var months = map[string]time.Month{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7,
	"aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

// date reads a date as people write one, as YYYY-MM-DD. order says which
// comes first in one written with slashes or hyphens and a year last.
func date(s, order string) (string, bool) {
	s = strings.TrimSpace(s)
	// 2026-11-14, perhaps with a time after it, which is not the date's.
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' && (len(s) == 10 || s[10] == ' ' || s[10] == 'T') {
		return checkDate(s[:10])
	}
	head := s
	if i := strings.IndexAny(s, " T"); i > 0 && strings.ContainsAny(s[:i], "/.-") {
		head = s[:i]
	}
	if a, b, c, sep, ok := numericDate(head); ok {
		switch {
		case len(a) == 4:
			return ymd(a, b, c)
		case sep == '.':
			return ymd(c, b, a)
		case order == MonthFirst:
			return ymd(c, a, b)
		case order == DayFirst:
			return ymd(c, b, a)
		}
		return "", false
	}
	return namedDate(s)
}

// numericDate splits 14/11/2026 into its three numbers.
func numericDate(s string) (a, b, c string, sep byte, ok bool) {
	for _, sp := range []byte{'/', '.', '-'} {
		parts := strings.Split(s, string(sp))
		if len(parts) != 3 {
			continue
		}
		for _, p := range parts {
			if p == "" || len(p) > 4 || strings.TrimFunc(p, unicode.IsDigit) != "" {
				return "", "", "", 0, false
			}
		}
		return parts[0], parts[1], parts[2], sp, true
	}
	return "", "", "", 0, false
}

func ymd(y, m, d string) (string, bool) {
	yi, err1 := strconv.Atoi(y)
	mi, err2 := strconv.Atoi(m)
	di, err3 := strconv.Atoi(d)
	if err1 != nil || err2 != nil || err3 != nil {
		return "", false
	}
	if len(y) <= 2 {
		// Two figures are this century's, until they would be more than a
		// lifetime ahead.
		yi += 2000
		if yi > time.Now().Year()+50 {
			yi -= 100
		}
	}
	return checkDate(fmt.Sprintf("%04d-%02d-%02d", yi, mi, di))
}

// checkDate refuses a date that is not one, such as the 31st of February.
func checkDate(s string) (string, bool) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil || t.Year() < 1000 {
		return "", false
	}
	return s, true
}

// namedDate reads 14 November 2026, Nov 14, 2026 and Saturday 14th Nov
// 2026.
func namedDate(s string) (string, bool) {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == '.' || r == '/' || r == '-'
	})
	var day, year int
	var month time.Month
	for _, w := range words {
		w = strings.TrimRight(w, "stndrh")
		if w == "" {
			continue
		}
		if n, err := strconv.Atoi(w); err == nil {
			switch {
			case n > 31 && year == 0:
				year = n
			case n >= 1 && day == 0:
				day = n
			default:
				return "", false
			}
			continue
		}
		if len(w) >= 3 {
			if m, ok := months[w[:3]]; ok && month == 0 {
				month = m
			}
		}
	}
	if day == 0 || month == 0 || year == 0 {
		return "", false
	}
	return checkDate(fmt.Sprintf("%04d-%02d-%02d", year, int(month), day))
}

// dateOrder works out which comes first in a column's dates written with
// slashes: a first number above 12 is a day, a second above 12 is.
func dateOrder(header string, rows [][]string, col int, asked string) (string, error) {
	if asked == DayFirst || asked == MonthFirst {
		return asked, nil
	}
	dayFirst, monthFirst := false, false
	example := ""
	for _, rec := range rows {
		if col >= len(rec) {
			continue
		}
		s := strings.TrimSpace(unformula(rec[col]))
		if i := strings.IndexAny(s, " T"); i > 0 {
			s = s[:i]
		}
		a, b, _, sep, ok := numericDate(s)
		if !ok || len(a) == 4 || sep == '.' {
			continue
		}
		x, _ := strconv.Atoi(a)
		y, _ := strconv.Atoi(b)
		switch {
		case x > 12:
			dayFirst = true
		case y > 12:
			monthFirst = true
		case example == "":
			example = s
		}
	}
	switch {
	case dayFirst && monthFirst:
		return "", fmt.Errorf("the dates in %q are written both day first and month first", header)
	case dayFirst:
		return DayFirst, nil
	case monthFirst:
		return MonthFirst, nil
	case example != "":
		return "", &AmbiguousDates{Column: header, Example: example}
	}
	return "", nil
}

// clock reads a time of day as HH:MM: 19:30, 7:30 pm, 7pm, 19h30, noon.
func clock(s string) (string, bool) {
	s = strings.TrimSpace(s)
	// A date and time, such as a sheet's 2026-11-14 19:30:00 or 11/14/2026
	// 7:30 PM: the time.
	if len(s) > 11 && s[4] == '-' && s[7] == '-' && (s[10] == ' ' || s[10] == 'T') {
		s = s[11:]
	} else if i := strings.IndexByte(s, ' '); i > 0 && strings.Contains(s[:i], "/") {
		s = s[i+1:]
	}
	s = strings.ToLower(strings.Join(strings.Fields(s), ""))
	s = strings.NewReplacer("a.m.", "am", "p.m.", "pm", "a.m", "am", "p.m", "pm").Replace(s)
	s = strings.ReplaceAll(s, ".", ":")
	switch s {
	case "noon", "midday":
		return "12:00", true
	case "midnight":
		return "00:00", true
	}
	half := ""
	for _, suf := range []string{"am", "pm", "a", "p"} {
		if strings.HasSuffix(s, suf) {
			half, s = suf[:1], strings.TrimSuffix(s, suf)
			break
		}
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "z"), "h")
	hh, mm, found := strings.Cut(strings.Replace(s, "h", ":", 1), ":")
	if !found {
		mm = "00"
	}
	if i := strings.IndexByte(mm, ':'); i >= 0 {
		mm = mm[:i] // the seconds
	}
	h, err1 := strconv.Atoi(hh)
	m, err2 := strconv.Atoi(mm)
	if err1 != nil || err2 != nil || len(mm) != 2 || len(hh) > 2 || m > 59 || h < 0 || m < 0 {
		return "", false
	}
	switch half {
	case "a":
		if h < 1 || h > 12 {
			return "", false
		}
		if h == 12 {
			h = 0
		}
	case "p":
		if h < 1 || h > 12 {
			return "", false
		}
		if h != 12 {
			h += 12
		}
	default:
		if h > 23 {
			return "", false
		}
	}
	return fmt.Sprintf("%02d:%02d", h, m), true
}
