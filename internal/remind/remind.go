// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package remind tells people what their tools say they still have to do,
// once, in one message, and then leaves them alone for a while.
//
// # What it is careful about
//
// A reminder is a security email arriving from something that is not the
// tool it is about, and people are trained — by the very tools it is about —
// to distrust exactly that. So it carries no tracking, links only to the
// tools' own addresses and only when somebody configured them, says where
// it comes from, and never asks anybody to sign in to anything here.
//
// It is also a message to an employee about their own shortfalls, sometimes
// copied to their manager. Three rules follow. Everything outstanding goes
// in one message, not one per tool, because four messages from four places
// in one morning is how people learn to filter a sender. Nobody hears from
// it more often than it is configured to allow. And a phishing result never
// goes to a manager: it is between the person and the security team, and a
// programme that reports clicks up the line teaches people not to report
// the real ones.
//
// # What it stores
//
// A ledger of what was sent: when, to whom by key, on which channel, about
// which items, and whether the relay or Slack accepted it. Not the address
// and not the text — the ledger exists to space reminders out and to show
// who was told what, and an address is not needed for either.
package remind

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/estate"
)

// Channel is how a reminder is sent.
type Channel string

const (
	Email Channel = "email"
	Slack Channel = "slack"
)

// Campaign is one kind of thing people are reminded about.
type Campaign string

const (
	Training Campaign = "training"
	Policies Campaign = "policies"
	Devices  Campaign = "devices"
	// Phishing is the follow-up after a failed simulation. Off unless
	// turned on: some programmes let the training platform do this itself.
	Phishing Campaign = "phishing"
)

// Campaigns lists them in the order a message presents them.
func Campaigns() []Campaign { return []Campaign{Training, Policies, Devices, Phishing} }

// Config is how reminders are sent.
type Config struct {
	// Enabled is whether anything is sent at all. Off until an
	// administrator turns it on, after seeing a preview.
	Enabled   bool              `json:"enabled"`
	Campaigns map[Campaign]bool `json:"campaigns"`
	Channels  []Channel         `json:"channels"`
	// EveryDays is the least time between two reminders to one person.
	EveryDays int `json:"every_days"`
	// EscalateAfter is how many reminders about the same thing, over at
	// least EscalateDays, before their manager is told. Zero never does.
	EscalateAfter int `json:"escalate_after"`
	EscalateDays  int `json:"escalate_days"`
	// Zone, FromHour, ToHour and Weekdays bound when anything is sent.
	Zone     string `json:"zone"`
	FromHour int    `json:"from_hour"`
	ToHour   int    `json:"to_hour"`
	Weekdays bool   `json:"weekdays"`
	// Links is where each tool is opened, by tool name. Only https, and
	// only these: a reminder never links anywhere else.
	Links map[string]string `json:"links,omitempty"`
	// Signature is who the message says it is from, in words: "The
	// security team at Acme".
	Signature string `json:"signature"`
}

// Default is a configuration that sends nothing until somebody enables it,
// and then reminds weekly about training, policies and devices, in office
// hours on weekdays, escalating after three reminders over two weeks.
func Default() Config {
	return Config{
		Campaigns: map[Campaign]bool{Training: true, Policies: true,
			Devices: true},
		Channels:  []Channel{Email},
		EveryDays: 7, EscalateAfter: 3, EscalateDays: 14,
		Zone: "UTC", FromHour: 9, ToHour: 17, Weekdays: true,
		Signature: "Your security team",
	}
}

// Validate refuses a configuration that could send more, or elsewhere,
// than it says.
func (c Config) Validate() error {
	if c.EveryDays < 1 {
		return fmt.Errorf("reminders at most once a day: every_days is %d",
			c.EveryDays)
	}
	if c.EscalateAfter < 0 || (c.EscalateAfter > 0 && c.EscalateDays < 7) {
		return fmt.Errorf("an escalation needs at least a week of reminders " +
			"first; telling somebody's manager after two days is not a " +
			"reminder programme")
	}
	if _, err := time.LoadLocation(c.Zone); err != nil {
		return fmt.Errorf("%q is not a time zone", c.Zone)
	}
	if c.FromHour < 0 || c.ToHour > 24 || c.FromHour >= c.ToHour {
		return fmt.Errorf("the sending window %d–%d is not a window",
			c.FromHour, c.ToHour)
	}
	if len(c.Channels) == 0 {
		return fmt.Errorf("no channel to send on")
	}
	for _, ch := range c.Channels {
		if ch != Email && ch != Slack {
			return fmt.Errorf("%q is not a channel", ch)
		}
	}
	for tool, link := range c.Links {
		if err := checkLink(link); err != nil {
			return fmt.Errorf("the link for %s: %w", tool, err)
		}
	}
	if strings.TrimSpace(c.Signature) == "" || len(c.Signature) > 120 ||
		strings.ContainsAny(c.Signature, "\r\n<>") {
		return fmt.Errorf("a signature is one short line saying who sends this")
	}
	for camp := range c.Campaigns {
		known := false
		for _, k := range Campaigns() {
			known = known || k == camp
		}
		if !known {
			return fmt.Errorf("%q is not something to remind people about",
				camp)
		}
	}
	return nil
}

func checkLink(link string) error {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		strings.ContainsAny(link, " \r\n<>\"'") {
		return fmt.Errorf("%q is not an https address with nothing odd in it",
			link)
	}
	return nil
}

// Item is one thing somebody still has to do.
type Item struct {
	// Key identifies it across days, so a reminder about the same thing
	// counts toward escalating it.
	Key      string   `json:"key"`
	Campaign Campaign `json:"campaign"`
	Text     string   `json:"text"`
	Tool     string   `json:"tool"`
	Link     string   `json:"link,omitempty"`
}

// Person is somebody with something to do.
type Person struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	ManagerEmail string `json:"manager_email,omitempty"`
	Items        []Item `json:"items"`
}

// Due lists who has something to do, according to the enabled campaigns.
// Somebody the tools say has left is not reminded of anything; somebody
// with no address is listed with nothing to send to, so the gap shows.
func Due(e *estate.Estate, now time.Time, c Config) []Person {
	var out []Person
	for _, ind := range e.People {
		known, current, _, _ := ind.Current()
		if known && !current {
			continue
		}
		p := Person{Key: ind.Key, Name: ind.Name()}
		if len(ind.Emails) > 0 {
			p.Email = ind.Emails[0]
		}
		for _, r := range ind.Records {
			if p.ManagerEmail == "" && r.ManagerEmail != "" {
				p.ManagerEmail = r.ManagerEmail
			}
		}
		add := func(camp Campaign, key, tool, text string) {
			if !c.Campaigns[camp] {
				return
			}
			p.Items = append(p.Items, Item{Key: key, Campaign: camp,
				Text: text, Tool: tool, Link: c.Links[tool]})
		}

		// Training: overdue in the tool that tracks it, or past due in
		// the one that runs it.
		status, from := ind.Task("training")
		pastDue := ""
		for _, t := range ind.Training {
			if !t.Policy && !t.Done &&
				strings.Contains(strings.ToLower(t.Status), "past due") {
				pastDue = t.ID.Issuer
			}
		}
		switch {
		case pastDue != "":
			add(Training, "training", pastDue,
				"Finish your security awareness training")
		case status == "OVERDUE":
			add(Training, "training", from,
				"Finish your security awareness training")
		}

		if status, from := ind.Task("policies"); status == "OVERDUE" {
			add(Policies, "policies", from,
				"Read and accept the policies waiting for you")
		}
		for _, t := range ind.Training {
			if t.Policy && t.Done && t.Acknowledged != nil && !*t.Acknowledged {
				add(Policies, "policy:"+t.ID.Value, t.ID.Issuer,
					"Acknowledge "+orThe(t.Module, "the policy you read"))
			}
		}

		for _, m := range ind.Devices {
			seen := m.Seen()
			if seen.IsZero() || now.Sub(seen) > estate.Live {
				continue
			}
			name := m.Name()
			for _, check := range []struct {
				key, text string
				get       func(estate.Device) *bool
				bad       bool
			}{
				{"encryption", "Turn on disk encryption on %s",
					func(d estate.Device) *bool { return d.Encrypted }, false},
				{"screenlock", "Set a screen lock on %s",
					func(d estate.Device) *bool { return d.ScreenLock }, false},
				{"antivirus", "Turn on antivirus on %s",
					func(d estate.Device) *bool { return d.Antivirus }, false},
				{"passcode", "Set a passcode on %s",
					func(d estate.Device) *bool { return d.Passcode }, false},
				{"rooted", "Ask IT about %s, which reports as rooted or " +
					"jailbroken", func(d estate.Device) *bool { return d.Rooted },
					true},
			} {
				for _, r := range m.Records {
					v := check.get(r)
					if v == nil || *v != check.bad {
						continue
					}
					add(Devices, "device:"+check.key+":"+m.Key, r.ID.Issuer,
						fmt.Sprintf(check.text, name))
					break
				}
			}
		}

		for _, ph := range ind.Phishing {
			t, failed := ph.Failed()
			if !failed || now.Sub(t) > estate.Recent {
				continue
			}
			trained := false
			for _, tr := range ind.Training {
				if !tr.Policy && tr.Done && tr.Completed.After(t) {
					trained = true
				}
			}
			if !trained {
				add(Phishing, "phishing:"+ph.ID.Value, ph.ID.Issuer,
					"Take the short refresher course on spotting phishing")
			}
			break
		}

		if len(p.Items) > 0 {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func orThe(s, instead string) string {
	if strings.TrimSpace(s) == "" {
		return instead
	}
	return s
}

// Sent is one line of the ledger.
type Sent struct {
	At      time.Time `json:"at"`
	Person  string    `json:"person"`
	Channel Channel   `json:"channel"`
	Items   []string  `json:"items"`
	// Manager is set on an escalation, which went to the person's manager
	// about these items; the manager's address is not kept either.
	Manager bool   `json:"manager,omitempty"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// Message is one reminder ready to send.
type Message struct {
	Person  string   `json:"person"`
	Name    string   `json:"name"`
	Channel Channel  `json:"channel"`
	To      string   `json:"to"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	Items   []string `json:"items"`
	Manager bool     `json:"manager,omitempty"`
	// Why is why it is being sent now, or not.
	Why string `json:"why,omitempty"`
}

// Held is somebody not being reminded this time, and why.
type Held struct {
	Name string `json:"name"`
	Why  string `json:"why"`
}

// InHours reports whether now is inside the sending window.
func (c Config) InHours(now time.Time) bool {
	loc, err := time.LoadLocation(c.Zone)
	if err != nil {
		return false
	}
	local := now.In(loc)
	if c.Weekdays && (local.Weekday() == time.Saturday ||
		local.Weekday() == time.Sunday) {
		return false
	}
	return local.Hour() >= c.FromHour && local.Hour() < c.ToHour
}

// Plan decides what to send now, from who has something to do and what
// has already been sent. It sends nothing itself.
func Plan(people []Person, ledger []Sent, c Config, now time.Time) (
	[]Message, []Held) {

	var out []Message
	var held []Held
	last := map[string]time.Time{}
	// How many distinct days somebody was reminded about each item, and
	// since when: two channels on one morning are one reminder.
	type count struct {
		days  map[string]bool
		first time.Time
	}
	about := map[string]*count{}
	lastEscalated := map[string]time.Time{}
	for _, s := range ledger {
		if !s.OK {
			continue
		}
		if s.Manager {
			if s.At.After(lastEscalated[s.Person]) {
				lastEscalated[s.Person] = s.At
			}
			continue
		}
		if s.At.After(last[s.Person]) {
			last[s.Person] = s.At
		}
		for _, it := range s.Items {
			k := s.Person + "|" + it
			cn := about[k]
			if cn == nil {
				cn = &count{days: map[string]bool{}, first: s.At}
				about[k] = cn
			}
			if s.At.Before(cn.first) {
				cn.first = s.At
			}
			cn.days[s.At.UTC().Format("2006-01-02")] = true
		}
	}
	every := time.Duration(c.EveryDays) * 24 * time.Hour
	for _, p := range people {
		if t, ok := last[p.Key]; ok && now.Sub(t) < every {
			held = append(held, Held{Name: p.Name, Why: fmt.Sprintf(
				"reminded %d day(s) ago; next after %d", int(now.Sub(t).Hours()/24),
				c.EveryDays)})
			continue
		}
		var keys []string
		for _, it := range p.Items {
			keys = append(keys, it.Key)
		}
		for _, ch := range c.Channels {
			to := p.Email
			if to == "" {
				held = append(held, Held{Name: p.Name, Why: "no address in " +
					"any tool"})
				break
			}
			subject, body := Render(p, c, ch)
			out = append(out, Message{Person: p.Key, Name: p.Name,
				Channel: ch, To: to, Subject: subject, Body: body, Items: keys})
		}

		// Escalation: some item reminded about EscalateAfter times over at
		// least EscalateDays, still open, and the manager not told in the
		// last EscalateDays. Phishing never goes to a manager.
		if c.EscalateAfter == 0 || p.ManagerEmail == "" {
			continue
		}
		if t, ok := lastEscalated[p.Key]; ok &&
			now.Sub(t) < time.Duration(c.EscalateDays)*24*time.Hour {
			continue
		}
		var stuck []Item
		for _, it := range p.Items {
			if it.Campaign == Phishing {
				continue
			}
			cn := about[p.Key+"|"+it.Key]
			if cn != nil && len(cn.days) >= c.EscalateAfter &&
				now.Sub(cn.first) >= time.Duration(c.EscalateDays)*24*time.Hour {
				stuck = append(stuck, it)
			}
		}
		if len(stuck) == 0 {
			continue
		}
		subject, body := RenderManager(p, stuck, c)
		var keys2 []string
		for _, it := range stuck {
			keys2 = append(keys2, it.Key)
		}
		out = append(out, Message{Person: p.Key, Name: p.Name, Channel: Email,
			To: p.ManagerEmail, Subject: subject, Body: body, Items: keys2,
			Manager: true})
	}
	return out, held
}
