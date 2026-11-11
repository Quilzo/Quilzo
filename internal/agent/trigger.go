// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata" // a trigger's zone resolves the same on every host
	"unicode"

	"github.com/quilzo/quilzo/internal/event"
)

// A Trigger starts an agent without a person asking: at a time, or when
// something happens on the site.
//
// # Whose authority
//
// A triggered run acts for the agent's sponsor, the person who answers for
// it, checked when it fires: an agent whose sponsor has left, or whose
// identity has run out, does not start. It runs capped at the author role
// whatever its sponsor holds, so nothing that starts unattended can do more
// than draft and propose: publishing, and anything else that goes out, is
// still a person's decision. See cmd/quilzo/agenttriggers.go.
//
// # It does not run away
//
// Each trigger starts at most PerDay runs a day, never a second while its
// first is still going, and never from something the agent itself caused.
// An event that agents' runs led to carries their names, and once
// event.MaxChain of them have, it starts nothing more.
type Trigger struct {
	// On is what starts it: an event (internal/event), or "schedule".
	On string `json:"on"`
	// Where narrows an event to what it is about: a page path ("/blog"
	// and everything under it), a collection, a form, a chatbot or a
	// service. Empty is anything.
	Where string `json:"where,omitempty"`
	// Every and At are a schedule's: how often, and the time of day
	// ("07:30") in Zone (an IANA name, UTC when empty). With At, Every is
	// whole days.
	Every Duration `json:"every,omitempty"`
	At    string   `json:"at,omitempty"`
	Zone  string   `json:"zone,omitempty"`
	// Goal is what each run is asked to do. What started it is given to
	// the run after this, as data.
	Goal string `json:"goal"`
	// PerDay is the most runs it starts in a day: DefaultPerDay when zero.
	PerDay int `json:"per_day,omitempty"`
}

// OnSchedule is a Trigger's On for one that fires at times.
const OnSchedule = "schedule"

// Limits on triggers.
const (
	MaxTriggers   = 8
	DefaultPerDay = 24
	MaxPerDay     = 500
	MaxGoal       = 1000
	// MinEvery is the shortest a schedule repeats: a quarter of an hour.
	// Anything that has to happen more often than that is a reaction to
	// something, and is an event's trigger.
	MinEvery = 15 * time.Minute
	MaxEvery = 31 * 24 * time.Hour
)

var (
	reAt    = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	reWhere = regexp.MustCompile(`^[\p{L}\p{N}/_.:@ -]{0,200}$`)
)

// Validate says what is wrong with a trigger, or nil.
func (t Trigger) Validate() error {
	goal := strings.TrimSpace(t.Goal)
	switch {
	case goal == "":
		return fmt.Errorf("a trigger says what each run is to do (its goal)")
	case len(goal) > MaxGoal:
		return fmt.Errorf("a trigger's goal is at most %d characters", MaxGoal)
	case strings.IndexFunc(goal, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) >= 0:
		return fmt.Errorf("a trigger's goal is text, without control characters")
	case t.PerDay < 0 || t.PerDay > MaxPerDay:
		return fmt.Errorf("a trigger starts between 1 and %d runs a day", MaxPerDay)
	}
	if t.On == OnSchedule {
		every := time.Duration(t.Every)
		switch {
		case every < MinEvery:
			return fmt.Errorf("a schedule repeats every %s at the most often; something that has to "+
				"happen sooner is a reaction to an event", MinEvery)
		case every > MaxEvery:
			return fmt.Errorf("a schedule repeats at least every %d days", int(MaxEvery.Hours()/24))
		case t.Where != "":
			return fmt.Errorf("a schedule is about no one thing, so it has no where")
		}
		if t.At != "" {
			if !reAt.MatchString(t.At) {
				return fmt.Errorf("%q is not a time of day (07:30)", t.At)
			}
			if every%(24*time.Hour) != 0 {
				return fmt.Errorf("a schedule at a time of day repeats in whole days, not every %s", every)
			}
		}
		if _, err := t.location(); err != nil {
			return err
		}
		return nil
	}
	on, ok := event.Parse(t.On)
	if !ok {
		return fmt.Errorf("%q is neither an event nor %q", t.On, OnSchedule)
	}
	if on == event.PublishScheduled {
		return fmt.Errorf("no agent starts from %s: one that wants a launch starts from %s, when it goes out",
			t.On, event.PagePublished)
	}
	if !event.Triggerable(on) {
		return fmt.Errorf("no agent starts from %s: an agent started by another's waiting is how a queue feeds itself", t.On)
	}
	if t.Every != 0 || t.At != "" || t.Zone != "" {
		return fmt.Errorf("a trigger on %s happens when it does, with no every, at or zone", t.On)
	}
	if !reWhere.MatchString(t.Where) {
		return fmt.Errorf("%q is not a page, collection, form, chatbot or service", t.Where)
	}
	return nil
}

func (t Trigger) location() (*time.Location, error) {
	if t.Zone == "" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(t.Zone)
	if err != nil {
		return nil, fmt.Errorf("%q is not a time zone (Europe/London, America/New_York)", t.Zone)
	}
	return loc, nil
}

// PerDayOrDefault is how many runs it may start in a day.
func (t Trigger) PerDayOrDefault() int {
	if t.PerDay == 0 {
		return DefaultPerDay
	}
	return t.PerDay
}

// Key names a trigger for what is kept about it, so changing a trigger is
// starting a new one: its count for the day and when it next fires begin
// again.
//
// The event is hashed by its own name, whichever name it was declared by.
// A manifest refuses a trigger whose Key is an earlier one's, and with the
// name hashed as typed, page.published and published were two triggers on
// one event: the agent started twice for every publish. A trigger declared
// by its event's own name, as every one was before the webhook names were
// taken, keeps the key it had.
func (t Trigger) Key() string {
	on := t.On
	if e, ok := event.Parse(t.On); ok {
		on = string(e)
	}
	h := sha256.Sum256([]byte(strings.Join([]string{on, t.Where, time.Duration(t.Every).String(),
		t.At, t.Zone, t.Goal}, "\x00")))
	return hex.EncodeToString(h[:6])
}

// Matches reports whether an event starts this trigger. The event is named
// either way, as a trigger is kept as it was declared: "published" is
// page.published, as a webhook knows it.
func (t Trigger) Matches(e event.Event) bool {
	on, ok := event.Parse(t.On)
	return t.On != OnSchedule && ok && on == e.Type && e.Within(t.Where)
}

// Next is when a schedule fires next, strictly after after.
//
// A time of day is kept in its zone across a change of the clocks: "07:30
// in London" is 07:30 in summer and in winter, which adding hours to a
// time does not give.
func (t Trigger) Next(after time.Time) time.Time {
	every := time.Duration(t.Every)
	if t.At == "" {
		return after.Add(every)
	}
	loc, err := t.location()
	if err != nil {
		loc = time.UTC
	}
	var hh, mm int
	fmt.Sscanf(t.At, "%d:%d", &hh, &mm)
	local := after.In(loc)
	next := time.Date(local.Year(), local.Month(), local.Day(), hh, mm, 0, 0, loc)
	days := int(every / (24 * time.Hour))
	for !next.After(after) {
		next = time.Date(next.Year(), next.Month(), next.Day()+days, hh, mm, 0, 0, loc)
	}
	return next
}

// Describe is a trigger in a person's words.
func (t Trigger) Describe() string {
	if t.On == OnSchedule {
		every := time.Duration(t.Every)
		s := "every " + plainEvery(every)
		if t.At != "" {
			zone := t.Zone
			if zone == "" {
				zone = "UTC"
			}
			s += " at " + t.At + " " + zone
		}
		return s
	}
	on, ok := event.Parse(t.On)
	if !ok {
		on = event.Type(t.On)
	}
	s := "when " + event.Describe(on)
	if t.Where != "" {
		s += " (" + t.Where + ")"
	}
	return s
}

func plainEvery(d time.Duration) string {
	switch {
	case d%(7*24*time.Hour) == 0 && d >= 7*24*time.Hour:
		if d == 7*24*time.Hour {
			return "week"
		}
		return fmt.Sprintf("%d weeks", d/(7*24*time.Hour))
	case d%(24*time.Hour) == 0:
		if d == 24*time.Hour {
			return "day"
		}
		return fmt.Sprintf("%d days", d/(24*time.Hour))
	case d%time.Hour == 0:
		if d == time.Hour {
			return "hour"
		}
		return fmt.Sprintf("%d hours", d/time.Hour)
	}
	return fmt.Sprintf("%d minutes", d/time.Minute)
}

// validateTriggers checks a manifest's triggers as a set.
func validateTriggers(ts []Trigger) error {
	if len(ts) > MaxTriggers {
		return fmt.Errorf("an agent has at most %d triggers", MaxTriggers)
	}
	seen := map[string]bool{}
	for i, t := range ts {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("trigger %d: %w", i+1, err)
		}
		if seen[t.Key()] {
			return fmt.Errorf("trigger %d is the same as an earlier one", i+1)
		}
		seen[t.Key()] = true
	}
	return nil
}
