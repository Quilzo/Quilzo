// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/remind"
)

// Reminding people what their tools say they still have to do.
//
// remind/config.json says how, and starts disabled. `remind preview` shows
// exactly who would be sent what, and `remind enable` is the separate,
// audited act of allowing it. `remind send` sends what is due, inside the
// configured hours — run it on a schedule and it is a reminder programme.
//
// The Slack app's token is a credential like a connector's and is held in
// the same sealed store, under slack-bot-token:
//
//	QUILZO_CONNECT_SECRET=xoxb-… quilzo connect secret slack-bot-token

func remindDir(root string) string { return filepath.Join(root, "remind") }

func remindConfigPath(root string) string {
	return filepath.Join(remindDir(root), "config.json")
}

func remindLedgerPath(root string) string {
	return filepath.Join(remindDir(root), "sent.jsonl")
}

// slackSecret is the name the Slack app's token is stored under.
const slackSecret = "slack-bot-token"

// slackTarget is how Slack is reached: egress to slack.com, and a local
// server in a test. A variable and not a flag, for the reason connectDoer is.
var slackTarget = func() (remind.Doer, string) {
	return egress.Client("slack", 20*time.Second), ""
}

func loadRemindConfig(root string) (remind.Config, error) {
	c := remind.Default()
	b, err := os.ReadFile(remindConfigPath(root))
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("remind/config.json: %w", err)
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("remind/config.json: %w", err)
	}
	return c, nil
}

func saveRemindConfig(root string, c remind.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(remindDir(root), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(remindConfigPath(root), append(b, '\n'), 0o600)
}

func loadLedger(root string) ([]remind.Sent, error) {
	b, err := os.ReadFile(remindLedgerPath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []remind.Sent
	for n, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var s remind.Sent
		if uerr := json.Unmarshal([]byte(line), &s); uerr != nil {
			return nil, fmt.Errorf("remind/sent.jsonl line %d: %w", n+1, uerr)
		}
		out = append(out, s)
	}
	return out, nil
}

func appendLedger(root string, sent []remind.Sent) error {
	if len(sent) == 0 {
		return nil
	}
	if err := os.MkdirAll(remindDir(root), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(remindLedgerPath(root),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, s := range sent {
		if err := enc.Encode(s); err != nil {
			return err
		}
	}
	return f.Sync()
}

// remindPlan is who would be sent what now, and who is held back.
func remindPlan(root string, now time.Time) (remind.Config, []remind.Message,
	[]remind.Held, error) {

	c, err := loadRemindConfig(root)
	if err != nil {
		return c, nil, nil, err
	}
	e, _, err := buildEstate(root, now)
	if err != nil {
		return c, nil, nil, err
	}
	ledger, err := loadLedger(root)
	if err != nil {
		return c, nil, nil, err
	}
	msgs, held := remind.Plan(remind.Due(e, now, c), ledger, c, now)
	return c, msgs, held, nil
}

// remindSenders builds the senders the configuration asks for, and says
// which channel cannot be used and why.
func remindSenders(root string, c remind.Config) (map[remind.Channel]remind.Sender,
	map[remind.Channel]string) {

	senders := map[remind.Channel]remind.Sender{}
	missing := map[remind.Channel]string{}
	for _, ch := range c.Channels {
		switch ch {
		case remind.Email:
			m, err := loadMailConfig(root)
			switch {
			case err != nil:
				missing[ch] = err.Error()
			case m == nil:
				missing[ch] = "no mail relay is configured (notify/mail.json)"
			default:
				senders[ch] = remind.EmailSender{Mail: m.SendPlain}
			}
		case remind.Slack:
			held, err := loadSecrets(root)
			token := held[slackSecret]
			switch {
			case err != nil:
				missing[ch] = err.Error()
			case strings.TrimSpace(token) == "":
				missing[ch] = "no Slack token is stored; quilzo connect " +
					"secret " + slackSecret
			default:
				client, base := slackTarget()
				senders[ch] = remind.SlackSender{Token: token, Client: client,
					Base: base, Sleep: func(d time.Duration) { time.Sleep(d) }}
			}
		}
	}
	return senders, missing
}

// remindSendNow sends what is due. Refused while disabled or outside the
// hours, and every message's outcome is written to the ledger before the
// next one is tried, so a run that dies half way does not send twice.
func remindSendNow(root string, now time.Time, by string,
	kind audit.Kind) (sent, failed int, err error) {

	c, msgs, _, err := remindPlan(root, now)
	if err != nil {
		return 0, 0, err
	}
	if !c.Enabled {
		return 0, 0, fmt.Errorf("reminders are not enabled. Look at quilzo " +
			"remind preview, then quilzo remind enable")
	}
	if !c.InHours(now) {
		return 0, 0, fmt.Errorf("outside the sending hours (%02d:00–%02d:00 "+
			"%s%s); nothing was sent", c.FromHour, c.ToHour, c.Zone,
			map[bool]string{true: ", weekdays"}[c.Weekdays])
	}
	senders, missing := remindSenders(root, c)
	ctx := context.Background()
	for _, m := range msgs {
		entry := remind.Sent{At: now, Person: m.Person, Channel: m.Channel,
			Items: m.Items, Manager: m.Manager}
		s, ok := senders[m.Channel]
		if !ok {
			entry.Error = missing[m.Channel]
		} else if serr := s.Send(ctx, m); serr != nil {
			entry.Error = serr.Error()
		} else {
			entry.OK = true
		}
		if entry.OK {
			sent++
		} else {
			failed++
		}
		if lerr := appendLedger(root, []remind.Sent{entry}); lerr != nil {
			return sent, failed, lerr
		}
	}
	record(root, audit.Record{
		Action: "remind.send", Resource: "/workforce/reminders",
		Outcome: audit.Success, Principal: by, Kind: kind,
		Verified: kind != audit.KindUnknown,
		Detail: map[string]string{"by": by, "sent": fmt.Sprint(sent),
			"failed": fmt.Sprint(failed)},
	})
	return sent, failed, nil
}

func setRemindEnabled(root string, on bool, by string,
	kind audit.Kind) error {
	c, err := loadRemindConfig(root)
	if err != nil {
		return err
	}
	c.Enabled = on
	if err := saveRemindConfig(root, c); err != nil {
		return err
	}
	action := "remind.disable"
	if on {
		action = "remind.enable"
	}
	record(root, audit.Record{Action: action, Resource: "/workforce/reminders",
		Outcome: audit.Success, Principal: by, Kind: kind,
		Verified: kind != audit.KindUnknown,
		Detail:   map[string]string{"by": by}})
	return nil
}

func cmdRemind(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"preview"}
	}
	caller := resolveCaller(root, flagToken)
	// Every part of this is an administrator's: a preview lists named
	// people and what they have not done.
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	switch args[0] {
	case "preview":
		return remindPreview(root)
	case "send":
		fs := flag.NewFlagSet("send", flag.ContinueOnError)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		sent, failed, err := remindSendNow(root, time.Now().UTC(),
			caller.Name, caller.Kind)
		if err != nil {
			return err
		}
		if w.JSON(map[string]int{"sent": sent, "failed": failed}) {
			return nil
		}
		w.Human("%d sent, %d not sent", sent, failed)
		if failed > 0 {
			w.Human(" %s(the ledger says why: remind/sent.jsonl)%s", dim, reset)
		}
		w.Human("\n")
		return nil
	case "enable", "disable":
		if err := setRemindEnabled(root, args[0] == "enable", caller.Name,
			caller.Kind); err != nil {
			return err
		}
		w.Human("reminders %sd\n", args[0])
		return nil
	default:
		return fmt.Errorf("unknown remind command %q; try preview, send, "+
			"enable or disable", args[0])
	}
}

func remindPreview(root string) error {
	c, msgs, held, err := remindPlan(root, time.Now().UTC())
	if err != nil {
		return err
	}
	_, missing := remindSenders(root, c)
	if w.JSON(map[string]any{"enabled": c.Enabled, "messages": msgs,
		"held": held, "unavailable": missing}) {
		return nil
	}
	state := yellow + "disabled" + reset
	if c.Enabled {
		state = green + "enabled" + reset
	}
	w.Human("reminders are %s; %d message(s) due now\n\n", state, len(msgs))
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].Name < msgs[j].Name })
	for _, m := range msgs {
		who := m.Name
		if m.Manager {
			who = "the manager of " + m.Name
		}
		w.Human("%s%s%s by %s: %s\n", bold, who, reset, m.Channel, m.Subject)
		for _, l := range strings.Split(strings.TrimSpace(m.Body), "\n") {
			if strings.HasPrefix(l, "- ") {
				w.Human("  %s\n", l)
			}
		}
	}
	for ch, why := range missing {
		w.Human("\n%s%s cannot be used: %s%s\n", yellow, ch, why, reset)
	}
	if len(held) > 0 {
		w.Human("\n%s%d held back%s\n", dim, len(held), reset)
	}
	return nil
}
