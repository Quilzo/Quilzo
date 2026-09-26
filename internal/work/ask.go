// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package work

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Blocking is everything one person or team is holding up.
//
// The question a status field cannot answer. In a tracker where "in review"
// is a word, finding out what alan is holding up means reading the board
// and guessing; here the wait names a subject, so it is a lookup. It is
// also the most useful question on any board and the one nobody can ask,
// which is why the answer usually arrives in a meeting as "I think you have
// a couple of things of mine?"
func (b *Board) Blocking(who string) []*Item {
	who = strings.ToLower(strings.TrimSpace(who))
	var out []*Item
	for _, it := range b.Items {
		if it.Waiting == nil || !it.State.Open() {
			continue
		}
		if strings.ToLower(it.Waiting.On) == who {
			out = append(out, it)
		}
	}
	byAge(out)
	return out
}

// Mine is everything somebody owns that is still open.
func (b *Board) Mine(who string) []*Item {
	who = strings.ToLower(strings.TrimSpace(who))
	var out []*Item
	for _, it := range b.Items {
		if it.State.Open() && strings.ToLower(it.Owner) == who {
			out = append(out, it)
		}
	}
	byAge(out)
	return out
}

// In is everything in a state.
func (b *Board) In(s State) []*Item {
	var out []*Item
	for _, it := range b.Items {
		if it.State == s {
			out = append(out, it)
		}
	}
	byAge(out)
	return out
}

func byAge(in []*Item) {
	sort.SliceStable(in, func(i, j int) bool {
		return in[i].Moved.Before(in[j].Moved)
	})
}

// Stall is work that has stopped moving.
type Stall struct {
	Item *Item         `json:"item"`
	For  time.Duration `json:"for"`
	Why  string        `json:"why"`
}

// Stuck is everything that has not moved in a while, worst first.
//
// Two different kinds of stuck, and they are reported apart because they
// need different responses. Work that is waiting on somebody has a person
// to ask. Work that is Doing and waiting on nothing has been picked up and
// put down, and the honest question is whether anybody is actually on it.
func (b *Board) Stuck(after time.Duration, at time.Time) []Stall {
	var out []Stall
	for _, it := range b.Items {
		if !it.State.Open() {
			continue
		}
		var held time.Duration
		var why string
		if it.Waiting != nil {
			held = it.Waiting.Held(at)
			if it.Waiting.Kind == OnTime && at.Before(it.Waiting.Until) {
				continue // Waiting for a date that has not arrived is fine.
			}
			why = fmt.Sprintf("waiting on %s for %s", it.Waiting.On,
				it.Waiting.For)
			if !it.Waiting.Chaseable() {
				why = fmt.Sprintf("waiting for %s, which has passed",
					it.Waiting.For)
			}
		} else {
			held = at.Sub(it.Moved)
			why = fmt.Sprintf("%s and waiting on nothing, so either "+
				"somebody is on it or nobody is", it.State)
		}
		if held >= after {
			out = append(out, Stall{Item: it, For: held, Why: why})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].For > out[j].For })
	return out
}

// Load is how much is waiting on each person, worst first.
//
// The thing a standup is for and never achieves, because the information is
// spread across a board as words.
type Load struct {
	On    string        `json:"on"`
	Kind  WaitKind      `json:"kind"`
	Items int           `json:"items"`
	Worst time.Duration `json:"worst"`
}

// Queue is who the board is waiting on, and for how long.
func (b *Board) Queue(at time.Time) []Load {
	by := map[string]*Load{}
	for _, it := range b.Items {
		if it.Waiting == nil || !it.State.Open() ||
			it.Waiting.Kind == OnTime {
			continue
		}
		k := strings.ToLower(it.Waiting.On)
		l, ok := by[k]
		if !ok {
			l = &Load{On: it.Waiting.On, Kind: it.Waiting.Kind}
			by[k] = l
		}
		l.Items++
		if held := it.Waiting.Held(at); held > l.Worst {
			l.Worst = held
		}
	}
	out := make([]Load, 0, len(by))
	for _, l := range by {
		out = append(out, *l)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Items != out[j].Items {
			return out[i].Items > out[j].Items
		}
		return out[i].Worst > out[j].Worst
	})
	return out
}

// Twice is work that looks like it exists more than once.
//
// The same thing tracked in two places is the most common corruption of a
// board, and it happens because somebody typed a title rather than finding
// the item. Reported rather than merged: two items with similar titles are
// sometimes genuinely two pieces of work, and a tracker that silently
// merged them would be doing something worse than the duplication.
func (b *Board) Twice() [][]*Item {
	by := map[string][]*Item{}
	for _, it := range b.Items {
		if !it.State.Open() {
			continue
		}
		by[fold(it.Title)] = append(by[fold(it.Title)], it)
	}
	var out [][]*Item
	for _, group := range by {
		if len(group) > 1 {
			byAge(group)
			out = append(out, group)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i][0].Title < out[j][0].Title
	})
	return out
}

// fold reduces a title to the words that carry it, so that "Write the
// migration" and "write migration" land together.
func fold(s string) string {
	var keep []string
	for _, f := range strings.Fields(strings.ToLower(s)) {
		f = strings.Trim(f, ".,:;!?\"'()[]")
		switch f {
		case "", "a", "an", "the", "to", "for", "of", "and", "in", "on":
			continue
		}
		keep = append(keep, f)
	}
	sort.Strings(keep)
	return strings.Join(keep, " ")
}

// Shape is what a board looks like, for somebody deciding whether it is
// being used or merely populated.
type Shape struct {
	Items    int `json:"items"`
	Open     int `json:"open"`
	Waiting  int `json:"waiting"`
	Unowned  int `json:"unowned"`
	Stuck    int `json:"stuck"`
	Twice    int `json:"twice"`
	Excused  int `json:"excused"`
	Reopened int `json:"reopened"`
}

// Look measures a board.
func (b *Board) Look(stale time.Duration, at time.Time) Shape {
	s := Shape{Items: len(b.Items)}
	for _, it := range b.Items {
		if it.State.Open() {
			s.Open++
			if it.Waiting != nil {
				s.Waiting++
			}
			if strings.TrimSpace(it.Owner) == "" {
				s.Unowned++
			}
		}
		s.Excused += len(it.Excused)
		for _, m := range it.Log {
			if m.From.Backward(m.To) {
				s.Reopened++
			}
		}
	}
	s.Stuck = len(b.Stuck(stale, at))
	s.Twice = len(b.Twice())
	return s
}

// Why describes a board's health in a sentence, or returns empty when
// there is nothing worth saying.
func (s Shape) Why() string {
	var says []string
	if s.Unowned > 0 {
		says = append(says, fmt.Sprintf("%d open item(s) have no owner",
			s.Unowned))
	}
	if s.Stuck > 0 {
		says = append(says, fmt.Sprintf("%d have stopped moving", s.Stuck))
	}
	if s.Twice > 0 {
		says = append(says, fmt.Sprintf("%d title(s) appear more than once",
			s.Twice))
	}
	if s.Excused > 0 {
		says = append(says, fmt.Sprintf("%d requirement(s) were excused "+
			"rather than met", s.Excused))
	}
	if len(says) == 0 {
		return ""
	}
	return strings.Join(says, ", ")
}
