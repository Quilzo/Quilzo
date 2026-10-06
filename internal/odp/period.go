// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package odp

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A time period, as a governance tool or a person writes one.
//
// OSCAL leaves a parameter's value as text, so what arrives is "15
// minutes", "one year", "P90D" or "8h" depending on who wrote it. Each of
// those is accepted; a description ("at the end of the working day") is
// not, because a period this program cannot measure is one it cannot
// enforce, and accepting it would be the quiet translation this package
// exists to remove. A month is thirty days and a year 365, which an
// assessor reading "1 year" means.

const (
	day   = 24 * time.Hour
	week  = 7 * day
	month = 30 * day
	year  = 365 * day
)

var units = map[string]time.Duration{
	"second": time.Second, "seconds": time.Second, "sec": time.Second, "secs": time.Second, "s": time.Second,
	"minute": time.Minute, "minutes": time.Minute, "min": time.Minute, "mins": time.Minute,
	"hour": time.Hour, "hours": time.Hour, "hr": time.Hour, "hrs": time.Hour,
	"day": day, "days": day, "week": week, "weeks": week,
	"month": month, "months": month, "year": year, "years": year,
}

var numberWords = map[string]int{
	"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
	"seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
	"fifteen": 15, "twenty": 20, "thirty": 30, "sixty": 60, "ninety": 90,
}

// ParsePeriod reads a time period.
func ParsePeriod(s string) (time.Duration, error) {
	raw := s
	s = strings.ToLower(strings.TrimSpace(s))
	for _, tail := range []string{" of inactivity", " inactivity", " of inactive time"} {
		s = strings.TrimSuffix(s, tail)
	}
	if s == "" {
		return 0, fmt.Errorf("no period given")
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return d, nil
	}
	if strings.HasPrefix(s, "p") {
		if d, ok := iso8601(s); ok {
			return d, nil
		}
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' })
	var total time.Duration
	for i := 0; i < len(fields); i++ {
		if fields[i] == "and" {
			continue
		}
		n, err := strconv.Atoi(fields[i])
		if err != nil {
			w, ok := numberWords[fields[i]]
			if !ok {
				return 0, fmt.Errorf("%q is not a time period this can measure; write it like 15 minutes, 8 hours, 90 days, 1 year, PT15M or P90D", raw)
			}
			n = w
		}
		if i+1 >= len(fields) {
			return 0, fmt.Errorf("%q gives a number without a unit", raw)
		}
		u, ok := units[fields[i+1]]
		if !ok {
			return 0, fmt.Errorf("%q: %q is not a unit (seconds, minutes, hours, days, weeks, months, years)", raw, fields[i+1])
		}
		if n < 0 || time.Duration(n) > (1<<62)/u {
			return 0, fmt.Errorf("%q is too long", raw)
		}
		total += time.Duration(n) * u
		i++
	}
	if total == 0 && !strings.HasPrefix(fields[0], "0") {
		return 0, fmt.Errorf("%q is not a time period this can measure", raw)
	}
	return total, nil
}

// iso8601 reads PnYnMnWnDTnHnMnS, the form OSCAL tools emit.
func iso8601(s string) (time.Duration, bool) {
	s = strings.ToUpper(s)
	if !strings.HasPrefix(s, "P") || len(s) < 3 {
		return 0, false
	}
	var total time.Duration
	inTime, num := false, ""
	for _, r := range s[1:] {
		switch {
		case r >= '0' && r <= '9':
			num += string(r)
		case r == 'T':
			if num != "" || inTime {
				return 0, false
			}
			inTime = true
		default:
			if num == "" {
				return 0, false
			}
			n, err := strconv.Atoi(num)
			if err != nil || n > 1<<20 {
				return 0, false
			}
			var u time.Duration
			switch {
			case r == 'Y' && !inTime:
				u = year
			case r == 'M' && !inTime:
				u = month
			case r == 'W' && !inTime:
				u = week
			case r == 'D' && !inTime:
				u = day
			case r == 'H' && inTime:
				u = time.Hour
			case r == 'M' && inTime:
				u = time.Minute
			case r == 'S' && inTime:
				u = time.Second
			default:
				return 0, false
			}
			total += time.Duration(n) * u
			num = ""
		}
	}
	return total, num == ""
}

// Words is a period as a person says it: "15 minutes", "1 year".
func Words(d time.Duration) string {
	unit := func(n int64, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	switch {
	case d <= 0:
		return "0 seconds"
	case d%year == 0:
		return unit(int64(d/year), "year")
	case d%day == 0:
		return unit(int64(d/day), "day")
	case d%time.Hour == 0:
		return unit(int64(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return unit(int64(d/time.Minute), "minute")
	}
	return d.String()
}

// goDuration is a period as a setting holds it: "15m", "8h", "720h".
func goDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}
