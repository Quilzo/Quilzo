// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/remind"
)

func TestRemindersGoOnceToWhoeverHasSomethingToDo(t *testing.T) {
	root := connectStore(t)
	// An estate: Sam is overdue on training, Ann has nothing to do.
	now := time.Now().UTC()
	snap := map[string]any{"source": "vanta", "at": now,
		"endpoints": map[string]any{"people": map[string]any{
			"produces": "identity", "complete": true}}}
	lines := `{"_source":"vanta","_endpoint":"people","_produces":"identity","id":"v1","email":"sam@acme.com","name":"Sam Okafor","employment":"CURRENT","training":"OVERDUE"}
{"_source":"vanta","_endpoint":"people","_produces":"identity","id":"v2","email":"ann@acme.com","name":"Ann Lee","employment":"CURRENT","training":"COMPLETE"}
`
	os.MkdirAll(toolsDir(root), 0o700)
	b, _ := json.Marshal(snap)
	records, meta := snapshotPaths(root, "vanta")
	os.WriteFile(meta, b, 0o600)
	os.WriteFile(records, []byte(lines), 0o600)

	var posted []string
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,
		r *http.Request) {
		switch r.URL.Path {
		case "/api/users.lookupByEmail":
			io.WriteString(w, `{"ok":true,"user":{"id":"U024BE7LH"}}`)
		case "/api/chat.postMessage":
			body, _ := io.ReadAll(r.Body)
			posted = append(posted, string(body))
			io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer slack.Close()
	old := slackTarget
	slackTarget = func() (remind.Doer, string) { return slack.Client(), slack.URL }
	defer func() { slackTarget = old }()

	t.Setenv("QUILZO_CONNECT_SECRET", "xoxb-test-token")
	if err := cmdConnect(root, []string{"secret", slackSecret}); err != nil {
		t.Fatal(err)
	}
	c := remind.Default()
	c.Channels = []remind.Channel{remind.Slack}
	c.FromHour, c.ToHour, c.Weekdays = 0, 24, false
	if err := saveRemindConfig(root, c); err != nil {
		t.Fatal(err)
	}

	if err := cmdRemind(root, []string{"send"}); err == nil ||
		!strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("sent while disabled: %v", err)
	}
	if err := cmdRemind(root, []string{"enable"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdRemind(root, []string{"send"}); err != nil {
		t.Fatal(err)
	}
	if len(posted) != 1 || !strings.Contains(posted[0], "Finish your security") {
		t.Fatalf("posted %v", posted)
	}
	ledger, _ := os.ReadFile(remindLedgerPath(root))
	if strings.Contains(string(ledger), "@") {
		t.Errorf("the ledger kept an address: %s", ledger)
	}
	// The same day again: nobody hears twice.
	if err := cmdRemind(root, []string{"send"}); err != nil {
		t.Fatal(err)
	}
	if len(posted) != 1 {
		t.Errorf("a second run the same day sent %d more", len(posted)-1)
	}

	// Outside the hours, nothing, and it says so.
	c, _ = loadRemindConfig(root)
	h := now.Hour()
	c.FromHour, c.ToHour = (h+2)%24, (h+3)%24
	if c.FromHour >= c.ToHour {
		c.FromHour, c.ToHour = 0, 1
		if h == 0 {
			c.FromHour, c.ToHour = 2, 3
		}
	}
	saveRemindConfig(root, c)
	if err := cmdRemind(root, []string{"send"}); err == nil ||
		!strings.Contains(err.Error(), "outside the sending hours") {
		t.Errorf("outside the hours: %v", err)
	}
}
