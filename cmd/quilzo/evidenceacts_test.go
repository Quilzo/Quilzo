// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/anchor"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/timestamp"
)

// `auditlog anchor` needs the grant permission, because it sends a digest to
// outside services and writes what they return. `anchor` and `timestamp`
// needed only view for the same acts, so a reader or an auditor could submit
// a publication to the calendars, upgrade the proofs and ask an authority to
// stamp. Those take what `auditlog anchor` takes; reading and exporting what
// is kept, and the bare commands, which only read, stay a reader's.
func TestSendingEvidenceOutTakesWhatAuditlogAnchorTakes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "rae", "reader"}); err != nil {
		t.Fatal(err)
	}
	isolateToken(t)
	issueFor := func(who string, role auth.Role) string {
		ts, _ := loadTokens(root)
		secret, _, err := ts.Issue("t-"+who, who, role, "/", time.Hour, role)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveJSON(tokensPath(root), ts); err != nil {
			t.Fatal(err)
		}
		return secret
	}
	reader, admin := issueFor("rae", auth.RoleReader), issueFor("boss", auth.RoleAdmin)

	acts := [][]string{{"anchor", "submit"}, {"anchor", "upgrade"},
		{"timestamp", "stamp"}, {"stamp", "stamp"}}
	reads := [][]string{{"anchor"}, {"anchor", "status"}, {"anchor", "export"},
		{"timestamp"}, {"timestamp", "list"}, {"timestamp", "export"},
		{"stamp"}, {"stamp", "list"}, {"stamp", "export"}}

	t.Setenv("QUILZO_TOKEN", reader)
	for _, c := range acts {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("a reader may run %v, which sends a digest out and writes what comes back", c)
		}
	}
	for _, c := range reads {
		if err := authoriseCommand(root, c[0], c[1:]); err != nil {
			t.Errorf("a reader cannot run %v, which only reads: %v", c, err)
		}
	}
	if n, _ := lookupNeed("auditlog", []string{"anchor"}); n.action != auth.ActGrant {
		t.Fatalf("auditlog anchor needs %q; this test compares against grant", n.action)
	}
	t.Setenv("QUILZO_TOKEN", admin)
	for _, c := range acts {
		if err := authoriseCommand(root, c[0], c[1:]); err != nil {
			t.Errorf("an administrator cannot run %v: %v", c, err)
		}
	}
}

// auditedActions reads the actions in the store's audit log.
func auditedActions(t *testing.T, root string) map[string]audit.Event {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]audit.Event{}
	for _, e := range events {
		out[e.Action] = e
	}
	return out
}

// `timestamp stamp` sends a digest to an outside authority and wrote no
// audit record of it, where `anchor submit` writes one. `auditlog anchor`
// and `anchor upgrade` wrote none either. Each is on the record now, and the
// authority is named without what its address carries besides the host.
func TestSendingEvidenceOutIsAudited(t *testing.T) {
	root, live := publishedStore(t)
	savedCal, savedTSA := anchorCalendars, stampRequest
	anchorCalendars = func() anchor.Submitter { return upgradingCalendars{} }
	stampRequest = func(_ *http.Client, tsa, subject string) (timestamp.Stamp, error) {
		return timestamp.Stamp{Root: subject, Authority: tsa, Token: []byte{0x30, 0x00},
			RequestedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	}
	t.Cleanup(func() { anchorCalendars, stampRequest = savedCal, savedTSA })

	if err := stampNow(root, []string{"--tsa", "https://who:pass@tsa.example/stamp?key=k"}); err != nil {
		t.Fatal(err)
	}
	if err := anchorSubmit(root, nil); err != nil {
		t.Fatal(err)
	}
	if err := anchorUpgrade(root); err != nil {
		t.Fatal(err)
	}
	if err := auditAnchor(root); err != nil {
		t.Fatal(err)
	}

	got := auditedActions(t, root)
	for _, action := range []string{"timestamp.stamp", "anchor.submit", "anchor.upgrade", "auditlog.anchor"} {
		if _, ok := got[action]; !ok {
			t.Errorf("%s left no audit record", action)
		}
	}
	if e, ok := got["timestamp.stamp"]; ok && !strings.Contains(e.Detail["root"], live) {
		t.Errorf("the stamp's record does not say what was stamped: %v", e.Detail)
	}
	if e := got["timestamp.stamp"]; e.Detail["authority"] != "tsa.example" {
		t.Errorf("the stamp's record names the authority as %q, not its host",
			e.Detail["authority"])
	}
}

// upgradingCalendars answers a submission with a pending proof and an
// upgrade with the rest of it, ending in a block.
type upgradingCalendars struct{ fakeCalendars }

func (upgradingCalendars) Get(context.Context, string) ([]byte, error) {
	b := []byte{0x08, 0x00} // SHA-256, then an attestation
	b = append(b, 0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01)
	return append(b, 0x03, 0xf0, 0x8c, 0x35), nil // height 870000
}
