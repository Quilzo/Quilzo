// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/mail"
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
