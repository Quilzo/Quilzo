// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/posture"
)

// mailbox is what would have been sent to the security contact.
type mailbox struct {
	mu   sync.Mutex
	sent []mail.Message
	fail error
}

// read waits for what the command started in the background, and is what
// reached the relay.
func (m *mailbox) read() []mail.Message {
	finishBackground(10 * time.Second)
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mail.Message(nil), m.sent...)
}

// securityMailbox gives a store a security contact to mail and a relay to
// mail it through, and catches what would have been sent, or refuses it
// as a relay that is down does when fail is set.
func securityMailbox(t *testing.T, root string) *mailbox {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("security.contact", "mailto:security@crumb.example", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mailConfigPath(root), []byte(`{"host":"relay.example:587","from":"quilzo@crumb.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	box := &mailbox{}
	old := deliverMail
	deliverMail = func(_ *mail.Mailer, m mail.Message) error {
		box.mu.Lock()
		defer box.mu.Unlock()
		if box.fail != nil {
			return box.fail
		}
		if _, err := m.Bytes(); err != nil {
			return err
		}
		box.sent = append(box.sent, m)
		return nil
	}
	t.Cleanup(func() { finishBackground(10 * time.Second); deliverMail = old })
	return box
}

// auditFor is every record in the store's log with this action.
func auditFor(t *testing.T, root, action string) []audit.Event {
	t.Helper()
	finishBackground(10 * time.Second)
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range evs {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// Holding every playbook stops the shield acting on its own, which is the
// first thing an intruder with an administrator's session would want; and
// it used to tell nobody, setting it or lifting it. The security contact
// hears of both, and the log says whether the message went.
func TestHoldingThePlaybooksAndLettingThemActAgainAreBothTold(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	box := securityMailbox(t, root)
	if err := shieldHold(root, []string{"--why", "a block looked wrong"}); err != nil {
		t.Fatal(err)
	}
	got := box.read()
	if len(got) != 1 || got[0].To != "security@crumb.example" ||
		!strings.Contains(got[0].Body, "held to watching") || !strings.Contains(got[0].Body, "a block looked wrong") {
		t.Fatalf("setting a hold told: %+v", got)
	}
	// The only administrator lets them act again alone, and says so.
	if err := shieldRelease(root, []string{"--why", "the block was right"}); err != nil {
		t.Fatal(err)
	}
	got = box.read()
	if len(got) != 2 || !strings.Contains(got[1].Body, "act again") {
		t.Fatalf("lifting a hold told: %+v", got)
	}
	told := auditFor(t, root, "shield.told")
	if len(told) != 2 || told[0].Detail["about"] != "held" || told[1].Detail["about"] != "released" ||
		told[0].Outcome != audit.Success {
		t.Fatalf("the log does not say the security contact was told: %+v", told)
	}
}

// unrouted is what the posture says about where alerts go, for this store.
func unrouted(t *testing.T, root string) []posture.Finding {
	t.Helper()
	var out []posture.Finding
	for _, f := range posture.Scan(Observe(root, t.TempDir(), posture.ServerFacts{}), nil).Findings {
		if f.Rule == "alerts.unrouted" {
			out = append(out, f)
		}
	}
	return out
}

// Nothing checked that an alert could reach anybody: with no mailto: in
// security.contact, or no mail.json, every one was dropped and nothing
// said so. Now the posture does, as a high finding, which posture drift
// writes to the log for the SIEM.
func TestAlertsThatCannotBeDeliveredAreAFinding(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	securityMailbox(t, root)
	if got := unrouted(t, root); len(got) != 0 {
		t.Fatalf("a mailto: address and a relay: %+v", got)
	}
	for _, contact := range []string{"https://crumb.example/security", "tel:+44-20-7946-0000"} {
		cfg, _ := loadConfig(root)
		if err := cfg.Set("security.contact", contact, "", "test"); err != nil {
			t.Fatal(err)
		}
		if err := saveConfig(root, cfg); err != nil {
			t.Fatal(err)
		}
		if got := unrouted(t, root); len(got) != 1 || got[0].Resource != "security.contact" || got[0].Severity != posture.High {
			t.Errorf("a contact of %s: %+v", contact, got)
		}
	}
	cfg, _ := loadConfig(root)
	cfg.Set("security.contact", "https://crumb.example/security, mailto:security@crumb.example", "", "test")
	saveConfig(root, cfg)
	if err := os.Remove(mailConfigPath(root)); err != nil {
		t.Fatal(err)
	}
	if got := unrouted(t, root); len(got) != 1 || got[0].Resource != "mail.json" {
		t.Errorf("no mail.json: %+v", got)
	}
}

// A newly failing check that is high is mailed, and a call held for a
// person is mailed; both threw away whether the mail went. A relay that
// refuses is now a failure in the log, where whoever watches it sees that
// the security contact was not told.
func TestAnAlertThatCouldNotBeSentIsAFailureInTheLog(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	box := securityMailbox(t, root)
	box.fail = errors.New("the relay refused the connection")

	now := time.Now()
	state := posture.State{Now: now, Stream: posture.StreamFacts{Set: true, Sent: 40, Failures: 9,
		Since: now.Add(-30 * time.Hour), Error: "the receiver answered 503"}}
	if opened, _, err := postureDrift(root, state, now); err != nil || opened != 1 {
		t.Fatalf("opened %d: %v", opened, err)
	}
	told := auditFor(t, root, "posture.told")
	if len(told) != 1 || told[0].Outcome != audit.Failure || told[0].Detail["rule"] != "siem.stream-failing" ||
		!strings.Contains(told[0].Detail["error"], "refused") {
		t.Fatalf("a drift mail that failed: %+v", told)
	}

	tellHeld(root, "crm", "delete_contact", "gq_0123456789ab", auth.Token{Principal: "dana", Client: "Desk"})
	told = auditFor(t, root, "mcp.gateway.told")
	if len(told) != 1 || told[0].Outcome != audit.Failure || told[0].Detail["held"] != "gq_0123456789ab" ||
		!strings.Contains(told[0].Detail["error"], "refused") {
		t.Fatalf("a held call's mail that failed: %+v", told)
	}

	// And when it goes, the log says so.
	box.fail = nil
	tellHeld(root, "crm", "delete_contact", "gq_ba9876543210", auth.Token{Principal: "dana"})
	told = auditFor(t, root, "mcp.gateway.told")
	if len(told) != 2 || told[1].Outcome != audit.Success || told[1].Detail["did"] != "told security@crumb.example" {
		t.Fatalf("a held call's mail that went: %+v", told)
	}
	if got := box.read(); len(got) != 1 || !strings.Contains(got[0].Body, "gq_ba9876543210") {
		t.Fatalf("%+v", got)
	}
}
