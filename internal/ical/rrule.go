// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ical

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A repeating event, each time it happens.
//
// The rules people's calendars actually hold: every day, every week on
// these days, every month on a date or on the second Tuesday or the last
// Friday, every year; each every so many, a number of times or until a
// day, with the times left out (EXDATE), added (RDATE) or changed one at a
// time (RECURRENCE-ID). The parts of RFC 5545's rule language nobody's
// club night uses (BYSETPOS, BYWEEKNO, BYYEARDAY, BYHOUR, and repeating
// by the hour or minute) are not read: an event repeating by one of them
// is brought as its first time, and said so, rather than as times guessed.
//
// Each time is worked out on the wall clock of the event's own zone, so a
// class at 19:00 is at 19:00 on both sides of a change to summer time.

// Occurrence is one time an event happens.
type Occurrence struct {
	VEvent
	// Repeats says whether this is one time of a repeating event.
	Repeats bool
	// Key names this time within its series: the time it was planned for,
	// which a change to it keeps. Empty for an event that does not repeat.
	Key string
}

// maxPeriods bounds how far one rule is walked, whatever it says, and
// maxWalk all of a file's rules together: a file of ten thousand daily
// rules is not ten thousand times the work of one.
const (
	maxPeriods = 50000
	maxWalk    = 1000000
)

// Occurrences is every event in the file, one that repeats as each time it
// happens from from to to, at most max times for each. Times changed one
// at a time replace the time they change; one whose series is not in the
// file is an event of its own.
func (c *Read) Occurrences(from, to time.Time, max int) ([]Occurrence, []string) {
	var notes []string
	overrides := map[string]map[string]VEvent{}
	hasMaster := map[string]bool{}
	for _, ev := range c.Events {
		if ev.RecurrenceID.IsZero() {
			hasMaster[ev.UID] = true
			continue
		}
		if overrides[ev.UID] == nil {
			overrides[ev.UID] = map[string]VEvent{}
		}
		overrides[ev.UID][keyOf(ev.RecurrenceID, ev.AllDay)] = ev
	}
	var out []Occurrence
	unread, capped, budget := 0, 0, maxWalk
	for _, ev := range c.Events {
		if !ev.RecurrenceID.IsZero() {
			if ev.UID == "" || !hasMaster[ev.UID] {
				out = append(out, Occurrence{VEvent: ev})
			}
			continue
		}
		if ev.RRule == "" && len(ev.RDates) == 0 {
			out = append(out, Occurrence{VEvent: ev})
			continue
		}
		starts, ok, full := expand(ev, from, to, max, &budget)
		if !ok {
			unread++
		}
		if full {
			capped++
		}
		length := ev.End.Sub(ev.Start)
		for _, s := range starts {
			o := Occurrence{VEvent: ev, Repeats: true, Key: keyOf(s, ev.AllDay)}
			if ov, changed := overrides[ev.UID][o.Key]; changed {
				o.VEvent = ov
			} else {
				o.Start = s
				if ev.HasEnd {
					o.End = s.Add(length)
					if ev.AllDay {
						// A day is not always 24 hours of a zone's clock, but
						// an all-day event's dates are UTC, where it is.
						o.End = s.AddDate(0, 0, int(length.Hours()/24))
					}
				}
			}
			o.RRule, o.RDates, o.ExDates = "", nil, nil
			out = append(out, o)
		}
	}
	if unread > 0 {
		notes = append(notes, fmt.Sprintf("%d event(s) repeat by a rule this does not read, so only their "+
			"first time was brought", unread))
	}
	if capped > 0 {
		notes = append(notes, fmt.Sprintf("%d repeating event(s) were brought only %d times each", capped, max))
	}
	if budget <= 0 {
		notes = append(notes, "the file repeats more than can be worked out at once, so some repeating events "+
			"were brought only in part")
	}
	return out, notes
}

// keyOf is how a time in a series is named, the same whether it is an
// expanded time or a RECURRENCE-ID.
func keyOf(t time.Time, allDay bool) string {
	if allDay {
		return t.Format("20060102")
	}
	return t.UTC().Format("20060102T150405Z")
}

// rule is an RRULE, read.
type rule struct {
	freq       string
	interval   int
	count      int
	until      time.Time
	byDay      []weekday
	byMonthDay []int
	byMonth    []int
	wkst       time.Weekday
}

// weekday is MO, or 2TU, or -1FR: a day, and which of them in the month.
type weekday struct {
	day time.Weekday
	nth int
}

var days = map[string]time.Weekday{"SU": time.Sunday, "MO": time.Monday, "TU": time.Tuesday,
	"WE": time.Wednesday, "TH": time.Thursday, "FR": time.Friday, "SA": time.Saturday}

// parseRule reads a rule, refusing one with a part it does not read.
func parseRule(s string, start time.Time, allDay bool) (*rule, error) {
	r := &rule{interval: 1, wkst: time.Monday}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k, v = strings.ToUpper(strings.TrimSpace(k)), strings.ToUpper(strings.TrimSpace(v))
		switch k {
		case "FREQ":
			r.freq = v
		case "INTERVAL":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 1000 {
				return nil, fmt.Errorf("INTERVAL %q", v)
			}
			r.interval = n
		case "COUNT":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("COUNT %q", v)
			}
			r.count = n
		case "UNTIL":
			t, err := until(v, start, allDay)
			if err != nil {
				return nil, err
			}
			r.until = t
		case "BYDAY":
			for _, d := range strings.Split(v, ",") {
				d = strings.TrimSpace(d)
				if len(d) < 2 {
					return nil, fmt.Errorf("BYDAY %q", v)
				}
				wd, ok := days[d[len(d)-2:]]
				if !ok {
					return nil, fmt.Errorf("BYDAY %q", v)
				}
				nth := 0
				if n := d[:len(d)-2]; n != "" {
					x, err := strconv.Atoi(n)
					if err != nil || x == 0 || x < -5 || x > 5 {
						return nil, fmt.Errorf("BYDAY %q", v)
					}
					nth = x
				}
				r.byDay = append(r.byDay, weekday{wd, nth})
			}
		case "BYMONTHDAY":
			for _, d := range strings.Split(v, ",") {
				x, err := strconv.Atoi(strings.TrimSpace(d))
				if err != nil || x == 0 || x < -31 || x > 31 {
					return nil, fmt.Errorf("BYMONTHDAY %q", v)
				}
				r.byMonthDay = append(r.byMonthDay, x)
			}
		case "BYMONTH":
			for _, m := range strings.Split(v, ",") {
				x, err := strconv.Atoi(strings.TrimSpace(m))
				if err != nil || x < 1 || x > 12 {
					return nil, fmt.Errorf("BYMONTH %q", v)
				}
				r.byMonth = append(r.byMonth, x)
			}
		case "WKST":
			wd, ok := days[v]
			if !ok {
				return nil, fmt.Errorf("WKST %q", v)
			}
			r.wkst = wd
		default:
			return nil, fmt.Errorf("%s is not read", k)
		}
	}
	switch r.freq {
	case "DAILY", "WEEKLY", "MONTHLY":
	case "YEARLY":
		// A day of the week in a year, with no month to count it in, is
		// BYWEEKNO's territory: not read.
		if len(r.byDay) > 0 && len(r.byMonth) == 0 {
			return nil, fmt.Errorf("BYDAY in a year without BYMONTH is not read")
		}
	default:
		return nil, fmt.Errorf("FREQ %q is not read", r.freq)
	}
	return r, nil
}

// until reads a rule's last day: a date is the whole of that day.
func until(v string, start time.Time, allDay bool) (time.Time, error) {
	if len(v) == 8 {
		d, err := time.Parse("20060102", v)
		if err != nil {
			return time.Time{}, err
		}
		if allDay {
			return d, nil
		}
		return time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, start.Location()), nil
	}
	if strings.HasSuffix(v, "Z") {
		t, err := time.Parse("20060102T150405", v[:len(v)-1])
		return t.UTC(), err
	}
	return time.ParseInLocation("20060102T150405", v, start.Location())
}

// expand is when an event happens between from and to: its start, the
// times its rule makes and its RDATEs, less its EXDATEs, at most max. ok
// is false when its rule cannot be read, and full when max was reached.
func expand(ev VEvent, from, to time.Time, max int, budget *int) (starts []time.Time, ok, full bool) {
	ex := map[string]bool{}
	for _, t := range ev.ExDates {
		ex[keyOf(t, ev.AllDay)] = true
	}
	seen := map[string]bool{}
	var all []time.Time
	add := func(t time.Time) {
		k := keyOf(t, ev.AllDay)
		if seen[k] {
			return
		}
		seen[k] = true
		if !ex[k] {
			all = append(all, t)
		}
	}
	ok = true
	if ev.RRule == "" {
		add(ev.Start)
	} else if r, err := parseRule(ev.RRule, ev.Start, ev.AllDay); err != nil {
		ok = false
		add(ev.Start)
	} else {
		r.walk(ev.Start, from.Add(-ev.End.Sub(ev.Start)), to, budget, add)
	}
	for _, t := range ev.RDates {
		if ev.AllDay {
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		}
		add(t)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Before(all[j]) })
	for _, t := range all {
		// An event still going on at from is kept: it is not over.
		end := t
		if ev.HasEnd {
			end = t.Add(ev.End.Sub(ev.Start))
		}
		if end.Before(from) || t.After(to) {
			continue
		}
		if len(starts) == max {
			return starts, ok, true
		}
		starts = append(starts, t)
	}
	return starts, ok, false
}

// walk calls add for each time the rule makes, from start, which is
// always the first, until the rule ends or to has passed. A rule that is
// not counted starts walking near from, which is all that is wanted of
// it: a daily rule from 1990 is not walked through 1991.
func (r *rule) walk(start, from, to time.Time, budget *int, add func(time.Time)) {
	n := 0
	emit := func(t time.Time) bool {
		if t.Before(start) {
			return true
		}
		if !r.until.IsZero() && t.After(r.until) {
			return false
		}
		if t.After(to) {
			return false
		}
		if !t.Equal(start) {
			n++
			if r.count > 0 && n >= r.count {
				return false
			}
			add(t)
		}
		return true
	}
	add(start)
	if r.count == 1 {
		return
	}
	at := func(y int, m time.Month, d int) (time.Time, bool) {
		t := time.Date(y, m, d, start.Hour(), start.Minute(), start.Second(), 0, start.Location())
		// A 31st in a month of thirty days is not a day the event happens.
		return t, t.Day() == d && t.Month() == m
	}
	p0 := 0
	if r.count == 0 && from.After(start) {
		p0 = r.periodsBetween(start, from) - 2
		if p0 < 0 {
			p0 = 0
		}
	}
	for p := p0; p < p0+maxPeriods; p++ {
		if *budget <= 0 {
			return
		}
		*budget--
		var cands []time.Time
		switch r.freq {
		case "DAILY":
			d := start.AddDate(0, 0, p*r.interval)
			if t, ok := at(d.Year(), d.Month(), d.Day()); ok && r.dayMatches(t) {
				cands = append(cands, t)
			}
		case "WEEKLY":
			back := (int(start.Weekday()) - int(r.wkst) + 7) % 7
			week := start.AddDate(0, 0, -back+7*p*r.interval)
			wds := r.byDay
			if len(wds) == 0 {
				wds = []weekday{{day: start.Weekday()}}
			}
			for _, wd := range wds {
				d := week.AddDate(0, 0, (int(wd.day)-int(r.wkst)+7)%7)
				if t, ok := at(d.Year(), d.Month(), d.Day()); ok && r.monthMatches(t) {
					cands = append(cands, t)
				}
			}
		case "MONTHLY":
			first := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, p*r.interval, 0)
			if r.monthMatches(first) {
				cands = r.inMonth(first.Year(), first.Month(), start, at)
			}
		case "YEARLY":
			y := start.Year() + p*r.interval
			months := r.byMonth
			if len(months) == 0 {
				months = []int{int(start.Month())}
			}
			for _, m := range months {
				cands = append(cands, r.inMonth(y, time.Month(m), start, at)...)
			}
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i].Before(cands[j]) })
		for _, t := range cands {
			if !emit(t) {
				return
			}
		}
		// Past to with nothing left to make: a rule's later periods are
		// all later still.
		if len(cands) > 0 && cands[0].After(to) {
			return
		}
		if r.periodStart(start, p).After(to) {
			return
		}
	}
}

// periodsBetween is about how many of the rule's periods lie between two
// times, never more.
func (r *rule) periodsBetween(a, b time.Time) int {
	days := int(b.Sub(a).Hours() / 24)
	switch r.freq {
	case "DAILY":
		return days / r.interval
	case "WEEKLY":
		return days / (7 * r.interval)
	case "MONTHLY":
		return (days / 31) / r.interval
	default:
		return (days / 366) / r.interval
	}
}

// periodStart is roughly where period p begins, for stopping.
func (r *rule) periodStart(start time.Time, p int) time.Time {
	switch r.freq {
	case "DAILY":
		return start.AddDate(0, 0, p*r.interval)
	case "WEEKLY":
		return start.AddDate(0, 0, 7*p*r.interval-7)
	case "MONTHLY":
		return start.AddDate(0, p*r.interval-1, 0)
	default:
		return start.AddDate(p*r.interval-1, 0, 0)
	}
}

// inMonth is the days a monthly or yearly rule makes in one month.
func (r *rule) inMonth(y int, m time.Month, start time.Time,
	at func(int, time.Month, int) (time.Time, bool)) []time.Time {

	last := time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
	var days []int
	switch {
	case len(r.byMonthDay) > 0:
		for _, d := range r.byMonthDay {
			if d < 0 {
				d = last + d + 1
			}
			if d >= 1 && d <= last {
				days = append(days, d)
			}
		}
	case len(r.byDay) > 0:
		for _, wd := range r.byDay {
			var matching []int
			for d := 1; d <= last; d++ {
				if time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Weekday() == wd.day {
					matching = append(matching, d)
				}
			}
			switch {
			case wd.nth > 0 && wd.nth <= len(matching):
				days = append(days, matching[wd.nth-1])
			case wd.nth < 0 && -wd.nth <= len(matching):
				days = append(days, matching[len(matching)+wd.nth])
			case wd.nth == 0:
				days = append(days, matching...)
			}
		}
	default:
		days = []int{start.Day()}
	}
	var out []time.Time
	for _, d := range days {
		t, ok := at(y, m, d)
		if !ok {
			continue
		}
		// BYDAY with BYMONTHDAY keeps the days both name.
		if len(r.byMonthDay) > 0 && len(r.byDay) > 0 && !r.dayMatches(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// dayMatches is BYDAY, BYMONTHDAY and BYMONTH as filters on one day.
func (r *rule) dayMatches(t time.Time) bool {
	if len(r.byDay) > 0 {
		found := false
		for _, wd := range r.byDay {
			if wd.day == t.Weekday() {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if len(r.byMonthDay) > 0 && r.freq == "DAILY" {
		last := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
		found := false
		for _, d := range r.byMonthDay {
			if d == t.Day() || d < 0 && last+d+1 == t.Day() {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return r.monthMatches(t)
}

func (r *rule) monthMatches(t time.Time) bool {
	if len(r.byMonth) == 0 {
		return true
	}
	for _, m := range r.byMonth {
		if time.Month(m) == t.Month() {
			return true
		}
	}
	return false
}
