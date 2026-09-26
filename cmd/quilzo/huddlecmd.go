// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/groupkey"
	"github.com/quilzo/quilzo/internal/huddle"
	"github.com/quilzo/quilzo/internal/sframe"
)

// The controls in a call, and which of them are real.
//
// Every product has this row of buttons and presents them as equally solid.
// They are not. "Remove from meeting" is arithmetic and "mute participant"
// is the other person's software choosing to cooperate, and nothing in any
// interface says which is which — so in the meeting where it matters,
// nobody knows what they are relying on.
//
// `huddle controls` prints the table. `huddle demo` runs a call end to end
// against real keys, so the difference is demonstrated rather than claimed:
// muting somebody leaves them holding the key, and ejecting them does not.

func cmdHuddle(args []string) error {
	if len(args) == 0 {
		args = []string{"demo"}
	}
	switch args[0] {
	case "demo":
		return huddleDemo(args[1:])
	case "controls":
		return huddleControls()
	default:
		return fmt.Errorf("unknown huddle command %q; try demo or controls",
			args[0])
	}
}

func huddleControls() error {
	rows := huddle.Controls()
	if w.JSON(map[string]any{"controls": rows}) {
		return nil
	}
	w.Human("%swhat actually stands behind each control%s\n\n", bold, reset)
	last := huddle.Enforcement("")
	for _, c := range rows {
		if c.Enforcement != last {
			if last != "" {
				w.Human("\n")
			}
			colour := yellow
			if c.Enforcement.Holds() {
				colour = green
			}
			w.Human("  %s%s%s\n", colour, c.Enforcement, reset)
			w.Human("    %s%s%s\n\n", dim, wrapAt(c.Enforcement.Why(), 66,
				"    "), reset)
			last = c.Enforcement
		}
		w.Human("    %-30s %s%s%s\n", c.Name, dim, c.How, reset)
	}
	w.Human("\n  %sthis is not a smaller claim than the competition makes. "+
		"It is the\n  same claim, made accurately: no product can hard-mute "+
		"a modified\n  client, and the others simply do not say so%s\n",
		dim, reset)
	return nil
}

// wrapAt breaks a sentence to a width, indenting continuations.
func wrapAt(s string, width int, indent string) string {
	out, line := "", ""
	for _, word := range splitWords(s) {
		if len(line)+len(word)+1 > width && line != "" {
			out += line + "\n" + indent
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return out + line
}

func splitWords(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		if r == ' ' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func huddleDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	suiteID := fs.Int("suite", int(sframe.AES128GCMSHA256128),
		"which SFrame cipher suite the media goes out under")
	if err := fs.Parse(args); err != nil {
		return err
	}
	suite := sframe.Suite(*suiteID)
	if !suite.Known() {
		return fmt.Errorf("%d is not a registered cipher suite", *suiteID)
	}
	at := time.Now().UTC()

	hostID, err := groupkey.NewIdentity("ada")
	if err != nil {
		return err
	}
	g, err := groupkey.Create("standup", hostID)
	if err != nil {
		return err
	}
	c, err := huddle.Open("standup", "the standup", "ada", at)
	if err != nil {
		return err
	}

	secret, inv, err := c.Invite(0, 2*time.Hour, at,
		huddle.Reusable(3), huddle.Because("posted in #eng"))
	if err != nil {
		return err
	}
	w.Human("%sa link, posted in a channel%s\n", bold, reset)
	w.Human("  %s%s%s\n", dim, secret, reset)
	w.Human("  %s%d bits, good for %d use(s), expires %s. Zoom's meeting\n"+
		"  identifiers are nine to eleven digits — about thirty-six bits —\n"+
		"  and researchers predicted four percent of them%s\n\n",
		dim, huddle.SecretBits, inv.Uses,
		inv.Expires.Format("15:04"), reset)

	// Two people arrive.
	people := map[string]*groupkey.Identity{}
	for _, name := range []string{"grace", "alan"} {
		id, err := groupkey.NewIdentity(name)
		if err != nil {
			return err
		}
		people[name] = id
		straight, err := c.Present(secret, name, id.Member(0), at)
		if err != nil {
			return err
		}
		w.Human("  %s%s knocks%s", dim, name, reset)
		if straight {
			w.Human(" %s(no decision needed)%s", dim, reset)
		}
		w.Human("\n")
	}
	w.Human("  %sthey hold no group secret, so there is nothing for them to\n"+
		"  hear yet — whatever the server does%s\n\n", dim, reset)

	// The host admits both in one commit.
	var changes []groupkey.Change
	for _, name := range []string{"grace", "alan"} {
		ch, err := c.Admit(name, 0, huddle.Speaker, at)
		if err != nil {
			return err
		}
		changes = append(changes, ch)
	}
	interim := g.Interim()
	commit, welcomes, err := g.Commit(hostID, changes)
	if err != nil {
		return err
	}
	if err := g.Apply(commit, hostID); err != nil {
		return err
	}
	views := map[string]*groupkey.Group{"ada": g}
	for _, wl := range welcomes {
		for name, id := range people {
			jg, err := groupkey.Join(wl, interim, id)
			if err != nil {
				continue
			}
			views[name] = jg
			if err := c.Seated(name, jg.Me(), huddle.Speaker, at); err != nil {
				return err
			}
		}
	}
	w.Human("%sadmitted%s %sone commit, %d in the call, epoch %d · %s%s\n\n",
		bold, reset, dim, c.Size(), g.Epoch, g.Authenticator(), reset)

	// Three streams at once, from two people.
	w.Human("%sthree screens at once%s\n", bold, reset)
	type stream struct {
		who   string
		share huddle.Share
	}
	var streams []stream
	for _, s := range []struct {
		who   string
		what  huddle.What
		title string
	}{
		{"ada", huddle.Screen, "the design"},
		{"grace", huddle.Window, "the code"},
		{"grace", huddle.Window, "the tests"},
	} {
		seat, ok := c.Named(s.who)
		if !ok {
			return fmt.Errorf("%s has no seat", s.who)
		}
		sh, err := c.StartShare(seat.Index, s.what, s.title, at)
		if err != nil {
			return err
		}
		streams = append(streams, stream{s.who, sh})
	}
	for _, s := range streams {
		k, err := views[s.who].SenderKey(suite, s.share.Context)
		if err != nil {
			return err
		}
		w.Human("  %-7s %-10s %scontext %d · KID %#x · salt %x…%s\n",
			s.who, s.share.Title, dim, s.share.Context, k.KID, k.Salt[:4],
			reset)
	}
	w.Human("  %sgrace is sharing two windows at once. RFC 9605 gives the key\n"+
		"  identifier a context field for exactly this — so a second stream\n"+
		"  is a number, not a second key exchange, and no two streams "+
		"share\n  a salt%s\n\n", dim, reset)

	// Hands.
	for i, name := range []string{"alan", "grace"} {
		seat, _ := c.Named(name)
		if err := c.Signal(seat.Index, huddle.Hand, "",
			at.Add(time.Duration(1-i)*time.Second)); err != nil {
			return err
		}
	}
	w.Human("%shands up%s\n", bold, reset)
	for i, h := range c.Queue(at.Add(time.Minute)) {
		seat, _ := c.Seat(h.Seat)
		w.Human("  %d. %s\n", i+1, seat.Name)
	}
	w.Human("  %salan raised first and their clock says otherwise. The "+
		"queue\n"+
		"  follows the call's own order, because two hands inside the same\n"+
		"  second should not be decided by whose laptop was fast%s\n\n",
		dim, reset)

	// Mute, then eject, and show what each did to the keys.
	graceSeat, _ := c.Named("grace")
	before, err := views["grace"].BaseKey(suite)
	if err != nil {
		return err
	}
	if err := c.Mute(graceSeat.Index, 0, at); err != nil {
		return err
	}
	_, why := c.MaySpeak(graceSeat.Index)
	after, err := views["grace"].BaseKey(suite)
	if err != nil {
		return err
	}
	w.Human("%sada mutes grace%s\n", bold, reset)
	w.Human("  %smay speak: no — %s%s\n", dim, why, reset)
	w.Human("  %skey unchanged: %v%s\n", dim,
		string(before) == string(after), reset)
	w.Human("  %sagreed, not cryptographic. Every honest client drops "+
		"their\n  media and they still hold the key. Software that "+
		"ignored the\n"+
		"  mute could still send, and no product's mute is different%s\n\n",
		dim, reset)

	drop, err := c.Eject(graceSeat.Index, 0, at)
	if err != nil {
		return err
	}
	commit2, _, err := g.Commit(hostID, []groupkey.Change{drop})
	if err != nil {
		return err
	}
	if err := g.Apply(commit2, hostID); err != nil {
		return err
	}
	w.Human("%sada ejects grace%s\n", bold, reset)
	if err := views["grace"].Apply(commit2, people["grace"]); err != nil {
		w.Human("  %stheir client cannot follow:%s %s\n", green, reset,
			firstLine(err))
	} else {
		return fmt.Errorf("the ejected member followed the call")
	}
	now, err := g.BaseKey(suite)
	if err != nil {
		return err
	}
	w.Human("  %skey changed: %v · epoch %d · %s%s\n", dim,
		string(now) != string(before), g.Epoch, g.Authenticator(), reset)
	w.Human("  %scryptographic. The epoch secret was never encapsulated to\n"+
		"  them, so this holds against software nobody here wrote and "+
		"against\n  a server that is not on your side%s\n\n", dim, reset)

	w.Human("%swhat happened, in the call's order%s\n", bold, reset)
	for _, e := range c.Log() {
		w.Human("  %s%-3d%s %s\n", dim, e.Order(), reset, e.Note)
	}
	return nil
}
