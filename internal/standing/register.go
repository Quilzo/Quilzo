// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package standing

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
)

// Register is every situational role in this program.
//
// One list rather than a declaration per package, for the same reason the
// privilege table in the command layer is one list: the question worth
// answering is "what can anybody do here", and an answer assembled from
// nine files is one nobody assembles.
func Register() []Situational {
	return []Situational{
		{
			Package: "huddle", Name: "host",
			What: "runs a call",
			Held: "whoever opened it, or whoever they passed the chair to",
			Ends: "when the call does",
			Powers: []Power{
				{Name: "admit", Why: "somebody is in a call that will be " +
					"over within the hour, and admitting them is what a " +
					"meeting is"},
				{Name: "eject", Why: "removing somebody from a call ends " +
					"when the call ends. It is cryptographic and it is " +
					"still contained: they can be invited to the next one"},
				{Name: "mute", Why: "the same, and weaker — everybody " +
					"drops their media until the call is over"},
				{Name: "lock", Why: "closes one call to new arrivals"},
			},
		},
		{
			Package: "huddle", Name: "cohost",
			What: "shares the moderation of a call",
			Held: "granted by the host, for that call",
			Ends: "when the call does",
			Powers: []Power{
				{Name: "admit", Why: "as the host's, and a cohost cannot " +
					"make another cohost, so the power does not spread"},
				{Name: "eject", Why: "as the host's, and not of the host"},
				{Name: "mute", Why: "as the host's"},
			},
		},
		{
			Package: "incident", Name: "commander",
			What: "decides what happens during an incident",
			Held: "whoever takes the role when one is declared",
			Ends: "when the incident closes",
			Powers: []Power{
				{Name: "direct", Why: "telling responders what to do next " +
					"is the job, and it ends with the incident"},
				{Name: "decide-trigger", Outside: true,
					Needs: auth.ActPublish,
					Why: "recording awareness or materiality starts a " +
						"regulatory clock that outlives the incident and " +
						"binds the organisation. internal/auth makes " +
						"publishing the sharp rung because it is the only " +
						"action with an outside observer, and a " +
						"supervisory authority is the outside observer " +
						"this one has"},
				{Name: "waive", Outside: true, Needs: auth.ActPublish,
					Why: "deciding an obligation does not apply is a " +
						"statement a regulator may later ask about, and it " +
						"survives the incident by years"},
			},
		},
		{
			Package: "errand", Name: "owner",
			What: "the person who agreed to do something in a call",
			Held: "by having said so; internal/errand carries the sentence",
			Ends: "when the errand is carried out or declined",
			Powers: []Power{
				{Name: "accept", Why: "confirming your own commitment is " +
					"the narrowest possible authority: it is about one " +
					"task that one person said they would do"},
				{Name: "decline", Why: "the same, and refusing work you " +
					"were never granted is not an escalation"},
			},
		},
		{
			Package: "proving", Name: "promoter",
			What: "moves a detection between rings",
			Held: "by being somebody other than whoever proposed it",
			Ends: "at the promotion; it is not a standing position",
			Powers: []Power{
				{Name: "promote", Outside: true, Needs: auth.ActPublish,
					Why: "a rule reaching live alerts everybody and " +
						"changes what the estate sees for as long as it " +
						"runs. Nothing about the candidate's own history " +
						"bounds that"},
				{Name: "retire", Outside: true, Needs: auth.ActPublish,
					Why: "withdrawing a detection removes coverage " +
						"everybody else is relying on, and the absence is " +
						"the hardest kind of change to notice"},
			},
		},
		{
			Package: "room", Name: "moderator",
			What: "removes messages from a room",
			Held: "granted for that room",
			Ends: "with the grant",
			Powers: []Power{
				{Name: "remove", Why: "taking a message down leaves a " +
					"tombstone and the audit chain, so the effect is " +
					"visible and bounded by the room it happened in"},
			},
		},
		{
			Package: "scribe", Name: "participant",
			What: "anybody in a call, over the note-taker",
			Held: "by being in the call",
			Ends: "when they leave",
			Powers: []Power{
				{Name: "withdraw-consent", Why: "withdrawing consent to " +
					"be recorded is nobody's to refuse, and it is the one " +
					"power here that deliberately has no floor at all"},
				{Name: "eject-scribe", Why: "removing the note-taker ends " +
					"the recording of one call. That anybody present can " +
					"do it is the design rather than an oversight"},
			},
		},
		{
			Package: "work", Name: "assignee",
			What: "the person an item is owned by",
			Held: "by assignment on the board",
			Ends: "when the item is finished or reassigned",
			Powers: []Power{
				{Name: "move", Why: "moving your own work between four " +
					"states affects one item on one board"},
				{Name: "excuse", Outside: true, Needs: auth.ActPublish,
					Why: "waiving a requirement in a definition of done is " +
						"the record an auditor reads a year later, and it " +
						"outlives both the item and the person"},
			},
		},
	}
}

// Find looks a situational role up.
func Find(pkg, name string) (Situational, bool) {
	for _, s := range Register() {
		if strings.EqualFold(s.Package, pkg) &&
			strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return Situational{}, false
}

// Packages is every package that confers situational authority.
func Packages() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range Register() {
		if !seen[s.Package] {
			seen[s.Package] = true
			out = append(out, s.Package)
		}
	}
	sort.Strings(out)
	return out
}

// Escalations is every power that reaches outside its situation.
//
// The list worth reviewing. Each of these is a standing act somebody can
// reach by being in the right place at the right time, and each one either
// has a floor under it or is a way to acquire authority nobody granted.
func Escalations() []Situational {
	var out []Situational
	for _, s := range Register() {
		if !s.Contained() {
			out = append(out, s)
		}
	}
	return out
}

// Shape is what the register looks like, for somebody deciding whether
// this program's authority is reviewable.
type Shape struct {
	Roles     int `json:"roles"`
	Packages  int `json:"packages"`
	Powers    int `json:"powers"`
	Contained int `json:"contained"`
	Reaching  int `json:"reaching"`
}

// Look measures the register.
func Look() Shape {
	s := Shape{Packages: len(Packages())}
	for _, r := range Register() {
		s.Roles++
		s.Powers += len(r.Powers)
		if r.Contained() {
			s.Contained++
		} else {
			s.Reaching++
		}
	}
	return s
}

// Why describes the register in a sentence.
func (s Shape) Why() string {
	return fmt.Sprintf(
		"%d situational role(s) across %d package(s), conferring %d "+
			"power(s). %d are contained and %d confer something that "+
			"survives the situation and therefore rests on a standing "+
			"grant", s.Roles, s.Packages, s.Powers, s.Contained,
		s.Reaching)
}

// Check validates the whole register.
//
// Run as a test. The failure this exists to prevent is a ninth model
// appearing quietly in the tenth package, so the register being complete
// matters more than any single entry in it being right.
func Check() error {
	seen := map[string]bool{}
	for _, s := range Register() {
		if err := s.Validate(); err != nil {
			return err
		}
		key := s.Package + "/" + s.Name
		if seen[key] {
			return fmt.Errorf("%s is registered twice", key)
		}
		seen[key] = true
	}
	return nil
}
