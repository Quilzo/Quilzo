// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
)

// What an agent did, in a form somebody else can check.
//
// Every action of a run is one record in the audit log (agent.action), and
// the log is a hash chain whose heads are signed with Ed25519 and ML-DSA. A
// receipt is a run's records, each with its proof of inclusion, and a
// signed head they are proved against: an auditor, a customer, or a second
// system can confirm from the file alone that these are exactly the
// records the log holds, unaltered, without seeing anything else in the
// log, and against keys they were given rather than keys the file brings.

// receiptFormat names the file's shape, so a later one can be told apart;
// appReceiptFormat is the same proofs for what an app connected to the
// agent interface did for one person.
const (
	receiptFormat    = "quilzo-agent-receipt/1"
	appReceiptFormat = "quilzo-app-receipt/1"
)

type agentReceiptFile struct {
	Format string `json:"format"`
	Run    string `json:"run,omitempty"`
	Agent  string `json:"agent,omitempty"`
	// Connection and App, for an app's receipt: the connection's id and
	// the app it is.
	Connection string `json:"connection,omitempty"`
	App        string `json:"app,omitempty"`
	// Subject, for a memory receipt: the person it is about, by the handle
	// the log knows them by; Person is their name, for them.
	Subject string           `json:"subject,omitempty"`
	Person  string           `json:"person,omitempty"`
	Made    time.Time        `json:"made"`
	Entries []receiptEntry   `json:"entries"`
	Head    audit.SignedHead `json:"head"`
	// Keys are the signing keys' public halves, as this store publishes
	// them. Checking against these proves only that the file agrees with
	// itself; checking against keys from somewhere else proves more.
	Keys publishedKeys `json:"keys"`
}

type receiptEntry struct {
	Entry audit.Event `json:"entry"`
	Index int         `json:"index"`
	Proof []string    `json:"proof"`
}

// agentReceipt is `quilzo agent receipt RUN [-o FILE]`.
func agentReceipt(root string, args []string) error {
	return receiptCmd(root, "agent receipt", "RUN", args, buildReceipt)
}

// appReceipt is `quilzo apps receipt CONNECTION [-o FILE]`: every call an
// app made through one connection, for the person it acted for.
func appReceipt(root string, args []string) error {
	return receiptCmd(root, "apps receipt", "CONNECTION", args, buildAppReceipt)
}

func receiptCmd(root, name, what string, args []string,
	build func(root, id string, now time.Time) (*agentReceiptFile, error)) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	outPath := fs.String("o", "", "write the receipt here instead of printing it")
	if len(args) < 1 {
		return fmt.Errorf("quilzo %s %s [-o FILE]", name, what)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	rf, err := build(root, args[0], time.Now())
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(rf, "", " ")
	if err != nil {
		return err
	}
	if *outPath == "" {
		_, err = os.Stdout.Write(append(body, '\n'))
		return err
	}
	if err := os.WriteFile(*outPath, body, 0o644); err != nil {
		return err
	}
	of := "run " + rf.Run
	if rf.Connection != "" {
		of = "connection " + rf.Connection
	}
	fmt.Printf("%d records of %s, each with its proof, against a head of %d signed by %s\n",
		len(rf.Entries), of, rf.Head.Size, rf.Head.KeyID)
	fmt.Printf("  %scheck it anywhere: quilzo agent verify-receipt %s --keys head.pub.json%s\n", dim, *outPath, reset)
	return nil
}

func buildReceipt(root, run string, now time.Time) (*agentReceiptFile, error) {
	if !agent.ValidRecordID(run) {
		return nil, fmt.Errorf("%q is not a run id", run)
	}
	rf := &agentReceiptFile{Format: receiptFormat, Run: run, Made: now.UTC()}
	err := proveRecords(root, rf, now, func(e audit.Event) bool {
		// Each step, the run's outcome, and for a program's run how its box
		// went and every connection it asked for.
		switch e.Action {
		case "agent.action", "agent.run", "agent.program", "agent.egress":
			return e.Detail["run"] == run
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	if len(rf.Entries) == 0 {
		return nil, fmt.Errorf("the log holds no record of run %s", run)
	}
	rf.Agent = rf.Entries[0].Entry.Detail["agent"]
	return rf, nil
}

// buildAppReceipt is every call an app made through one connection.
func buildAppReceipt(root, connection string, now time.Time) (*agentReceiptFile, error) {
	if !reConnection.MatchString(connection) {
		return nil, fmt.Errorf("%q is not an app connection's id (gr_…)", connection)
	}
	rf := &agentReceiptFile{Format: appReceiptFormat, Connection: connection, Made: now.UTC()}
	err := proveRecords(root, rf, now, func(e audit.Event) bool {
		return e.Action == "mcp.call" && e.Detail["grant"] == connection
	})
	if err != nil {
		return nil, err
	}
	if len(rf.Entries) == 0 {
		return nil, fmt.Errorf("the log holds no call made through %s", connection)
	}
	rf.App = rf.Entries[0].Entry.Model
	return rf, nil
}

var reConnection = regexp.MustCompile(`^gr_[0-9a-f]{16}$`)

// proveRecords puts the log's records that belong in a receipt into it,
// each with its proof, and signs a head they are proved against.
func proveRecords(root string, rf *agentReceiptFile, now time.Time, belongs func(audit.Event) bool) error {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	head, err := audit.TreeHead(events, now)
	if err != nil {
		return err
	}
	for i, e := range events {
		if !belongs(e) {
			continue
		}
		proof, _, err := audit.Inclusion(events, e.Seq)
		if err != nil {
			return err
		}
		rf.Entries = append(rf.Entries, receiptEntry{Entry: e, Index: i, Proof: proof})
	}
	if len(rf.Entries) == 0 {
		return nil
	}
	signer, err := headSigner(root)
	if err != nil {
		return err
	}
	if rf.Head, err = signer.Sign(head); err != nil {
		return err
	}
	ed, ml := signer.Verifier().PublicKeys()
	rf.Keys = publishedKeys{KeyID: signer.Verifier().KeyID(),
		Ed25519: base64.StdEncoding.EncodeToString(ed), MLDSA: base64.StdEncoding.EncodeToString(ml)}
	return nil
}

// receiptCheck is what checking a receipt found.
type receiptCheck struct {
	Run        string   `json:"run,omitempty"`
	Agent      string   `json:"agent,omitempty"`
	Connection string   `json:"connection,omitempty"`
	App        string   `json:"app,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Records    int      `json:"records"`
	Steps      []int    `json:"steps"`
	Missing    []int    `json:"missing,omitempty"`
	KeyID      string   `json:"key_id"`
	OwnKeys    bool     `json:"checked_against_its_own_keys"`
	Problems   []string `json:"problems,omitempty"`
}

// checkReceipt verifies every record's inclusion and the head's signature.
// keys nil means the receipt's own.
func checkReceipt(rf *agentReceiptFile, keys *publishedKeys) receiptCheck {
	c := receiptCheck{Run: rf.Run, Agent: rf.Agent, Connection: rf.Connection, App: rf.App, Subject: nonEmpty(rf.Person, rf.Subject),
		Records: len(rf.Entries), KeyID: rf.Head.KeyID}
	if rf.Format != receiptFormat && rf.Format != appReceiptFormat && rf.Format != memoryReceiptFormat {
		c.Problems = append(c.Problems, fmt.Sprintf("this is a %q file, not a %s, a %s or a %s", rf.Format,
			receiptFormat, appReceiptFormat, memoryReceiptFormat))
		return c
	}
	if keys == nil {
		keys, c.OwnKeys = &rf.Keys, true
	}
	ed, err1 := base64.StdEncoding.DecodeString(keys.Ed25519)
	ml, err2 := base64.StdEncoding.DecodeString(keys.MLDSA)
	if err1 != nil || err2 != nil {
		c.Problems = append(c.Problems, "the public keys are not base64")
		return c
	}
	v, err := audit.NewHeadVerifier(ed, ml)
	if err != nil {
		c.Problems = append(c.Problems, err.Error())
		return c
	}
	if err := v.Verify(rf.Head); err != nil {
		c.Problems = append(c.Problems, "the head's signature does not verify: "+err.Error())
	}
	seen := map[int]bool{}
	max := 0
	for _, e := range rf.Entries {
		switch {
		case rf.Format == appReceiptFormat && (e.Entry.Action != "mcp.call" || e.Entry.Detail["grant"] != rf.Connection):
			c.Problems = append(c.Problems, fmt.Sprintf("record %d is not a call through %s", e.Entry.Seq, rf.Connection))
		case rf.Format == receiptFormat && e.Entry.Detail["run"] != rf.Run:
			c.Problems = append(c.Problems, fmt.Sprintf("record %d belongs to another run", e.Entry.Seq))
		case rf.Format == memoryReceiptFormat && (!memoryReceiptAction[e.Entry.Action] || e.Entry.Detail["subject"] != rf.Subject):
			c.Problems = append(c.Problems, fmt.Sprintf("record %d is not about %s's memory", e.Entry.Seq, rf.Subject))
		}
		if err := audit.VerifyInclusion(e.Entry, e.Index, e.Proof, rf.Head.Head); err != nil {
			c.Problems = append(c.Problems, fmt.Sprintf("record %d is not proved to be in the log: %v", e.Entry.Seq, err))
		}
		if n, err := strconv.Atoi(e.Entry.Detail["step"]); err == nil && e.Entry.Action == "agent.action" {
			seen[n] = true
			if n > max {
				max = n
			}
		}
	}
	for n := 1; n <= max; n++ {
		if seen[n] {
			c.Steps = append(c.Steps, n)
		} else {
			c.Missing = append(c.Missing, n)
		}
	}
	sort.Ints(c.Steps)
	return c
}

// agentVerifyReceipt is `quilzo agent verify-receipt FILE [--keys FILE]`.
func agentVerifyReceipt(root string, args []string) error {
	fs := flag.NewFlagSet("agent verify-receipt", flag.ContinueOnError)
	keysPath := fs.String("keys", "", "the public keys you were given (head.pub.json); without it, the receipt's own")
	if len(args) < 1 {
		return errors.New("quilzo agent verify-receipt FILE [--keys head.pub.json]")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	body, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var rf agentReceiptFile
	if err := json.Unmarshal(body, &rf); err != nil {
		return fmt.Errorf("%s is not a receipt: %w", args[0], err)
	}
	var keys *publishedKeys
	if *keysPath != "" {
		kb, err := os.ReadFile(*keysPath)
		if err != nil {
			return err
		}
		keys = &publishedKeys{}
		if err := json.Unmarshal(kb, keys); err != nil {
			return fmt.Errorf("%s is not a published key file: %w", *keysPath, err)
		}
	}
	c := checkReceipt(&rf, keys)
	if w.JSON(c) {
		if len(c.Problems) > 0 {
			return errors.New("the receipt does not verify")
		}
		return nil
	}
	if len(c.Problems) > 0 {
		for _, p := range c.Problems {
			w.Human("  %s%s%s\n", red, p, reset)
		}
		return errors.New("the receipt does not verify")
	}
	if c.Connection != "" {
		w.Human("%sverified%s  %s by %s through connection %s\n", bold, reset, count(c.Records, "call"), c.App, c.Connection)
	} else if c.Subject != "" {
		w.Human("%sverified%s  %s of memory about %s forgotten, deleted or rewritten\n", bold, reset, count(c.Records, "record"), c.Subject)
	} else {
		w.Human("%sverified%s  %d records of run %s by %s, steps %v\n", bold, reset, c.Records, c.Run, c.Agent, c.Steps)
	}
	w.Human("  %seach is in the log under a head signed by %s%s\n", dim, c.KeyID, reset)
	if len(c.Missing) > 0 {
		w.Human("  %ssteps %v are not in this receipt%s\n", yellow, c.Missing, reset)
	}
	if c.OwnKeys {
		w.Human("\n  %schecked against the keys the receipt brought, which proves it agrees\n"+
			"  with itself. Check it against keys you were given: --keys head.pub.json%s\n", yellow, reset)
	}
	return nil
}
