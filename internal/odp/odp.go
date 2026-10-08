// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package odp is the organisation's security policy, written the way its
// auditors already write it: as values for NIST SP 800-53's
// organisation-defined parameters.
//
// Every control in 800-53 leaves numbers to the organisation — "a limit of
// [number] consecutive invalid logon attempts during a [time period]",
// "terminate a user session after [conditions]". An enterprise decides those
// once, in its governance tool, and an assessor checks that every system
// enforces them. Each system then has its own settings with its own names,
// and somebody translates by hand, and the translation is where the gap
// opens. Here the organisation declares the parameters themselves, by their
// OSCAL ids, and the program does the translation it owns.
//
// What it promises, in four words from the plan:
//
//   - Closed: only parameters this program can enforce or state are
//     accepted. A declaration it could not keep is refused when it is made,
//     not discovered at the audit.
//   - Enforced: a declared value becomes a floor under the setting it maps
//     to (config.Floor). One administrator may make the setting stricter;
//     nobody may make it weaker without changing the policy.
//   - Checked: a setting found below its floor — the file edited by hand —
//     is a posture finding, and upkeep puts it back.
//   - Mapped: the policy exports as OSCAL set-parameters, and imports from
//     a profile, a system security plan or a component definition.
//
// And changing the policy takes two administrators: one proposes, another
// approves. A deployment with one administrator may apply its own proposal,
// and the record says it was approved alone.
package odp

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/config"
)

// Kind is what a parameter's value is.
type Kind string

const (
	// Number is a count.
	Number Kind = "number"
	// Period is a length of time.
	Period Kind = "time period"
	// Choice is one or more of the catalogue's alternatives.
	Choice Kind = "selection"
)

// How is how this program answers for a parameter.
type How string

const (
	// Set: a setting holds the value, and a declaration becomes its floor.
	Set How = "set"
	// Fixed: the program's behaviour is the value; a declaration is
	// accepted when the behaviour meets it and refused when it does not.
	Fixed How = "fixed"
	// Described: the value is the program's own description of what it
	// does, derived from settings. It is exported and cannot be declared.
	Described How = "described"
)

// Param is one parameter this program answers for.
type Param struct {
	// ID is the OSCAL parameter id in the SP 800-53 Rev 5 catalogue.
	ID string
	// Control is the control it belongs to, as the catalogue writes it.
	Control string
	// Label is the catalogue's label for it.
	Label string
	Kind  Kind
	How   How
	// Setting is the key that holds the value, for How == Set.
	Setting string
	// Stricter says which way is stricter for a Number or a Period:
	// "lower" or "higher". A Period of zero in a "lower" parameter means
	// never, the weakest.
	Stricter string
	// Choices are the alternatives this program can provide, for a Choice,
	// each as the catalogue words it.
	Choices []string
	// Means explains, for a person, how the declared value is enforced.
	Means string
}

// Params is the closed list.
//
// Ids, labels and choice wording are the catalogue's (SP 800-53 Rev 5.2.0,
// OSCAL, 11 May 2026). A test reads the shipped catalogue-derived facts back
// so a mistyped id fails rather than exporting a parameter that does not
// exist.
var Params = []Param{
	{ID: "ac-07_odp.01", Control: "AC-7", Label: "number", Kind: Number, How: Set,
		Setting: "auth.throttle.after", Stricter: "lower",
		Means: "consecutive failed sign-ins allowed in an hour before the next is delayed; throttling must be on"},
	{ID: "ac-07_odp.02", Control: "AC-7", Label: "time period", Kind: Period, How: Fixed,
		Stricter: "higher",
		Means:    "failed sign-ins are counted over an hour; a declared period of an hour or less is met"},
	{ID: "ac-07_odp.03", Control: "AC-7", Label: "action", Kind: Choice, How: Set,
		Choices: []string{
			"delay next logon prompt per {{ insert: param, ac-07_odp.05 }}",
			"lock the account or node for {{ insert: param, ac-07_odp.04 }}",
			"notify system administrator",
		},
		Means: "what happens past the limit: delaying needs throttling on, locking needs auth.lockout.hard, " +
			"notifying needs an alert threshold; locking until an administrator releases it is not something this program does"},
	{ID: "ac-07_odp.04", Control: "AC-7", Label: "time period", Kind: Period, How: Fixed,
		Stricter: "higher",
		Means:    "a hard lockout lasts until an hour passes with no further attempt; a declared period of an hour or less is met"},
	{ID: "ac-07_odp.05", Control: "AC-7", Label: "delay algorithm", How: Described,
		Means: "the delay doubles from auth.throttle.base to auth.throttle.max, and nothing is accepted past auth.throttle.ceiling failures in an hour"},
	{ID: "ac-02.05_odp", Control: "AC-2(5)", Label: "time period of expected inactivity or description of when to log out",
		Kind: Period, How: Set, Setting: "session.idle", Stricter: "lower",
		Means: "the admin signs a person out after this long with nobody using the page"},
	{ID: "ac-12_odp", Control: "AC-12", Label: "conditions or trigger events", Kind: Period, How: Set,
		Setting: "session.max", Stricter: "lower",
		Means: "a sign-in to the admin ends after this long, and sooner on signing out or when its credential is revoked"},
	{ID: "ia-05_odp.01", Control: "IA-5", Label: "time period by authenticator type", Kind: Period, How: Set,
		Setting: "token.ttl.max", Stricter: "lower",
		Means: "the longest life of any token; sign-in sessions end by ac-12_odp; passkeys are replaced when lost, not on a clock"},
	{ID: "au-11_odp", Control: "AU-11", Label: "time period", Kind: Period, How: Fixed, Stricter: "higher",
		Means: "the audit log is append-only and never pruned, so any retention period is met"},
}

// Lookup finds a parameter by id.
func Lookup(id string) (Param, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range Params {
		if p.ID == id {
			return p, true
		}
	}
	return Param{}, false
}

// IDs lists what may be declared, for a refusal that says what would work.
func IDs() []string {
	var out []string
	for _, p := range Params {
		if p.How != Described {
			out = append(out, p.ID)
		}
	}
	return out
}

// fixed is the value a Fixed parameter has, as a period.
var fixed = map[string]time.Duration{
	"ac-07_odp.02": time.Hour,
	"ac-07_odp.04": time.Hour,
	// au-11: never pruned; longer than any declaration.
	"au-11_odp": 1<<63 - 1,
}

// Check parses a declared value for a parameter and reports whether this
// program can keep it. A Fixed parameter whose behaviour falls short, a
// choice this program cannot provide, a value that does not parse: each
// is refused here, with the reason.
func (p Param) Check(declared string) error {
	declared = strings.TrimSpace(declared)
	if declared == "" {
		return fmt.Errorf("%s needs a value", p.ID)
	}
	switch p.How {
	case Described:
		return fmt.Errorf("%s is this program's description of what it does (%s); "+
			"it is exported, and the settings it describes are what to declare", p.ID, p.Means)
	case Fixed:
		d, err := ParsePeriod(declared)
		if err != nil {
			return fmt.Errorf("%s: %w", p.ID, err)
		}
		if !meets(p.Stricter, fixed[p.ID], d) {
			return fmt.Errorf("%s: this program cannot meet %q — %s", p.ID, declared, p.Means)
		}
		return nil
	}
	switch p.Kind {
	case Number:
		if _, err := parseNumber(declared); err != nil {
			return fmt.Errorf("%s: %w", p.ID, err)
		}
	case Period:
		d, err := ParsePeriod(declared)
		if err != nil {
			return fmt.Errorf("%s: %w", p.ID, err)
		}
		if d == 0 {
			return fmt.Errorf("%s: a period of zero declares nothing", p.ID)
		}
		if p.Setting != "" {
			s, _ := config.Lookup(p.Setting)
			if err := s.Validate(goDuration(d)); err != nil {
				return fmt.Errorf("%s cannot be %q here: %w", p.ID, declared, err)
			}
		}
	case Choice:
		if _, err := p.choices(declared); err != nil {
			return err
		}
	}
	return nil
}

// choices splits a declared selection and matches each against what this
// program provides. The catalogue's insert markers are compared loosely, as
// a governance tool may write them resolved or not.
func (p Param) choices(declared string) ([]int, error) {
	var out []int
	for _, part := range splitChoices(declared) {
		found := -1
		for i, c := range p.Choices {
			if loose(c) == loose(part) {
				found = i
			}
		}
		if found < 0 {
			return nil, fmt.Errorf("%s: %q is not something this program does; it can %s",
				p.ID, part, strings.Join(plainChoices(p.Choices), "; "))
		}
		out = append(out, found)
	}
	return out, nil
}

// splitChoices takes a selection as OSCAL values (one per line, as Import
// joins them) or as a semicolon-separated list typed by a person.
func splitChoices(s string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ';' }) {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// loose reduces a choice to its words: lower case, insert markers and
// whatever a tool substituted for them dropped after the first word.
func loose(s string) string {
	s = strings.ToLower(s)
	if i := strings.Index(s, "{{"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, " per "); i >= 0 {
		s = s[:i+4]
	}
	if i := strings.Index(s, " for "); i >= 0 && strings.HasPrefix(s, "lock") {
		s = s[:i+4]
	}
	return strings.Join(strings.Fields(s), " ")
}

func plainChoices(cs []string) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = strings.TrimSpace(strings.Split(c, "{{")[0])
		out[i] = strings.TrimSuffix(strings.TrimSuffix(out[i], " per"), " for")
	}
	return out
}

func meets(stricter string, have, declared time.Duration) bool {
	if stricter == "higher" {
		return have >= declared
	}
	return have != 0 && have <= declared
}

func parseNumber(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a whole number", s)
	}
	return n, nil
}

// Allows reports whether a setting's value meets a declared one: the floor
// config.Set enforces.
func (p Param) Allows(declared string) func(value string) bool {
	switch p.Kind {
	case Number:
		want, err := parseNumber(declared)
		if err != nil {
			return func(string) bool { return false }
		}
		return func(v string) bool {
			n, err := parseNumber(v)
			if err != nil {
				return false
			}
			if p.Stricter == "higher" {
				return n >= want
			}
			return n <= want
		}
	case Period:
		want, err := ParsePeriod(declared)
		if err != nil {
			return func(string) bool { return false }
		}
		return func(v string) bool {
			d, err := time.ParseDuration(v)
			return err == nil && meets(p.Stricter, d, want)
		}
	}
	return func(string) bool { return true }
}

// Floors turns a policy into the floors config.Config enforces, by setting.
// Choices become floors on the switches they need.
func Floors(pol *Policy) map[string][]config.Floor {
	out := map[string][]config.Floor{}
	if pol == nil {
		return out
	}
	for _, d := range pol.Declared {
		p, ok := Lookup(d.Param)
		if !ok || p.How != Set {
			continue
		}
		if p.Kind == Choice {
			idx, err := p.choices(d.Value)
			if err != nil {
				continue
			}
			for _, i := range idx {
				key, allows := choiceNeeds(i)
				out[key] = append(out[key], config.Floor{Param: p.ID, Declared: d.Value, Allows: allows})
			}
			continue
		}
		f := config.Floor{Param: p.ID, Declared: d.Value, Allows: p.Allows(d.Value)}
		out[p.Setting] = append(out[p.Setting], f)
		// A limit on failed attempts is a limit only while attempts are
		// counted at all.
		if p.ID == "ac-07_odp.01" {
			out["auth.throttle"] = append(out["auth.throttle"], config.Floor{Param: p.ID, Declared: d.Value,
				Allows: func(v string) bool { return v == "true" }})
		}
	}
	return out
}

// choiceNeeds is the setting an AC-7 action needs, and the values that
// provide it, by the index into the parameter's Choices.
func choiceNeeds(i int) (string, func(string) bool) {
	switch i {
	case 0:
		return "auth.throttle", func(v string) bool { return v == "true" }
	case 1:
		return "auth.lockout.hard", func(v string) bool { return v == "true" }
	default:
		return "auth.lockout.alert", func(v string) bool { n, err := parseNumber(v); return err == nil && n > 0 }
	}
}

// Enforce is the change to a setting that makes it meet a declaration it
// does not: the declared value itself for a Number or a Period, the switch
// for a choice. Empty when it is met already.
func Enforce(cfg *config.Config, d Declared) map[string]string {
	p, ok := Lookup(d.Param)
	if !ok || p.How != Set {
		return nil
	}
	out := map[string]string{}
	for key, floors := range Floors(&Policy{Declared: []Declared{d}}) {
		for _, f := range floors {
			if f.Allows(cfg.Raw(key)) {
				continue
			}
			switch {
			case key == p.Setting && p.Kind == Number:
				n, _ := parseNumber(d.Value)
				out[key] = strconv.Itoa(n)
			case key == p.Setting && p.Kind == Period:
				dur, _ := ParsePeriod(d.Value)
				out[key] = goDuration(dur)
			case key == "auth.lockout.alert":
				out[key] = "5"
			default:
				out[key] = "true"
			}
		}
	}
	return out
}

// Effective is a parameter's value as this deployment has it now, in the
// words an OSCAL document carries.
func Effective(p Param, cfg *config.Config) string {
	switch p.ID {
	case "ac-07_odp.01":
		if !cfg.Bool("auth.throttle") {
			return "no limit: throttling is off"
		}
		return strconv.Itoa(cfg.Int("auth.throttle.after"))
	case "ac-07_odp.02", "ac-07_odp.04":
		return "1 hour"
	case "ac-07_odp.03":
		var out []string
		if cfg.Bool("auth.throttle") {
			out = append(out, p.Choices[0])
		}
		if cfg.Bool("auth.lockout.hard") {
			out = append(out, p.Choices[1])
		}
		if cfg.Int("auth.lockout.alert") > 0 {
			out = append(out, p.Choices[2])
		}
		return strings.Join(out, "\n")
	case "ac-07_odp.05":
		return fmt.Sprintf("the delay before the next attempt starts at %s and doubles with each failure up to %s; "+
			"after %d failures in an hour nothing is accepted until the hour passes",
			cfg.Dur("auth.throttle.base"), cfg.Dur("auth.throttle.max"), cfg.Int("auth.throttle.ceiling"))
	case "ac-02.05_odp":
		if d := cfg.Dur("session.idle"); d > 0 {
			return Words(d) + " of inactivity"
		}
		return "never: no inactivity sign-out is set"
	case "ac-12_odp":
		s := Words(cfg.Dur("session.max")) + " after signing in; on signing out; when the credential that started it is revoked"
		if d := cfg.Dur("session.idle"); d > 0 {
			s += "; after " + Words(d) + " of inactivity"
		}
		return s
	case "ia-05_odp.01":
		return "API tokens: at most " + Words(cfg.Dur("token.ttl.max")) + "; sign-in sessions: at most " +
			Words(cfg.Dur("session.max")) + "; passkeys: replaced when lost or compromised"
	case "au-11_odp":
		return "indefinitely: the audit log is append-only and never pruned"
	}
	return ""
}

// Met reports whether this deployment meets a declared value now.
func Met(d Declared, cfg *config.Config) bool {
	p, ok := Lookup(d.Param)
	if !ok {
		return false
	}
	if p.How == Fixed {
		return p.Check(d.Value) == nil
	}
	for key, floors := range Floors(&Policy{Declared: []Declared{d}}) {
		for _, f := range floors {
			if !f.Allows(cfg.Raw(key)) {
				return false
			}
		}
	}
	return true
}
