// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/mail"
)

// Telling somebody, by mail.
//
// The shield telling the security contact what it did, a sign-in that had
// to be confirmed, a held call waiting for a person, an agent's sponsor told
// it is about to stop running: one plain message to one address, through
// the relay in mail.json (internal/mail). Nothing else is sent: notices to
// customers and reminders to a workforce are a security team's tools, and
// left Quilzo with them for Vaigil.
//
// A file rather than flags. The credentials for a mail relay on a command
// line end up in a shell history and in the process table.

// mailConfig is mail.json.
type mailConfig struct {
	Host     string `json:"host"`
	From     string `json:"from"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

func mailConfigPath(root string) string { return filepath.Join(root, "mail.json") }

// legacyMailConfigPath is where a store made before notices left kept it,
// read when mail.json is not there so its relay goes on working.
func legacyMailConfigPath(root string) string { return filepath.Join(root, "notify", "mail.json") }

// loadMailer is the relay, or nil when none is set up.
func loadMailer(root string) (*mail.Mailer, error) {
	path := mailConfigPath(root)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		path = legacyMailConfigPath(root)
		b, err = os.ReadFile(path)
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	name, _ := filepath.Rel(root, path)
	var c mailConfig
	if uerr := json.Unmarshal(b, &c); uerr != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", name, uerr)
	}
	if strings.TrimSpace(c.Host) == "" || strings.TrimSpace(c.From) == "" {
		return nil, fmt.Errorf("%s needs a host and a from address, or mail is "+
			"configured in a way that fails at the moment it is used", name)
	}
	return &mail.Mailer{
		Host: c.Host, From: c.From, Username: c.Username, Password: c.Password,
		// Through egress, so mail obeys offline mode and is in the report
		// of what this program talks to.
		Dial: func(network, address string) (net.Conn, error) {
			return egress.Dial(context.Background(), "mail", network, address)
		},
	}, nil
}

// securityAddress is the first mail address in security.contact.
func securityAddress(root string) string {
	cfg, err := loadConfig(root)
	if err != nil || cfg == nil {
		return ""
	}
	for _, c := range splitList(cfg.Raw("security.contact")) {
		if addr, ok := strings.CutPrefix(strings.TrimSpace(c), "mailto:"); ok {
			return addr
		}
	}
	return ""
}

// tellSecurity mails the security contact, and says whom it told.
func tellSecurity(root, summary string) (string, error) {
	return tell(root, securityAddress(root), summary)
}

// tellPerson mails one person, and says whom it told.
func tellPerson(root, to, summary string) (string, error) { return tell(root, to, summary) }

func tell(root, to, summary string) (string, error) {
	if to == "" {
		return "", errors.New("there is no address to send it to (security.contact takes a mailto: address)")
	}
	m, err := loadMailer(root)
	if err != nil {
		return "", err
	}
	if m == nil {
		return "", errors.New("no mail is set up (mail.json), so nobody was told; it is in the audit log")
	}
	// One line: a name with a line break in it must not cost the message
	// (mail refuses broken headers). Through deliverMail, which is what
	// Send does, so a test catches what the security contact would have
	// been sent.
	if err := deliverMail(m, mail.Message{To: to, Subject: "Quilzo: " + onOneLine(summary),
		Body: summary + "\n\nThis was sent by Quilzo."}); err != nil {
		return "", err
	}
	return "told " + to, nil
}

// tellOfHold mails the security contact that every playbook was held to
// watching (held), or let act again, in the background, and records
// whether it reached them. Holding the playbooks takes one administrator
// and used to tell nobody: an intruder's first step could go unheard, and
// so could the hold that kept the shield from answering it.
func tellOfHold(root string, held bool, by, why string) {
	summary := fmt.Sprintf("Shield: every playbook was held to watching by %s, because %q. Until a second "+
		"administrator lets them act again, the shield blocks and turns off nothing by itself; it still tells you "+
		"what it sees.", by, why)
	about := "held"
	if !held {
		summary = fmt.Sprintf("Shield: every playbook may act again, approved by %s: %q.", by, why)
		about = "released"
	}
	inBackground(func() {
		did, err := tellSecurity(root, summary)
		detail := map[string]string{"about": about, "did": did}
		outcome := audit.Success
		if err != nil {
			detail["error"], outcome = err.Error(), audit.Failure
		}
		record(root, audit.Record{Action: "shield.told", Resource: "/security/shield", Outcome: outcome,
			Principal: "shield", Kind: audit.KindService, Verified: true, Detail: detail})
	})
}
