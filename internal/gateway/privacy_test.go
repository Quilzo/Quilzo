// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hearing is a model that answers with what it was sent.
type hearing struct{ heard string }

func (h *hearing) Name() string { return "hearing" }
func (h *hearing) Complete(_ context.Context, system, user string) (string, error) {
	h.heard = system + "\n" + user
	return "Reply sent to " + firstPlaceholder(user) + ".", nil
}

func firstPlaceholder(s string) string {
	i := strings.Index(s, "<quilzo:")
	if i < 0 {
		return "nobody"
	}
	j := strings.IndexByte(s[i:], '>')
	return s[i : i+j+1]
}

func TestAPromptLeavesWithoutPersonalDataAndTheAnswerComesBackWhole(t *testing.T) {
	h := &hearing{}
	cfg := Config{Routes: []Route{{Name: "hosted", URL: "https://api.provider.test/v1", Model: "m", KeyEnv: "K"}}}
	l, err := OpenLedger(filepath.Join(t.TempDir(), "usage.jsonl"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	g := New(cfg, func(Route) (Model, error) { return h, nil }, l)
	g.OwnDomains = []string{"paper.shop"}
	var masked map[string]int
	var route string
	g.OnMasked = func(consumer, r string, counts map[string]int) { route, masked = r, counts }

	prompt := "Customer mira.k@mailhost.net (+44 20 7946 0958) asks about card 5425233430109903; " +
		"our address is help@paper.shop. Deploy key AKIAIOSFODNN7EXAMPLE."
	out, err := g.For("agent:support").Complete(context.Background(), "be helpful; escalate to boss.lane@mailhost.net", prompt)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"mira.k@mailhost.net", "boss.lane", "7946", "5425233430109903", "AKIAIOSFODNN7EXAMPLE"} {
		if strings.Contains(h.heard, gone) {
			t.Errorf("%q reached the provider: %s", gone, h.heard)
		}
	}
	if !strings.Contains(h.heard, "help@paper.shop") {
		t.Error("the site's own address was masked")
	}
	if out != "Reply sent to mira.k@mailhost.net." {
		t.Errorf("the answer came back as %q", out)
	}
	if route != "hosted" || masked["email"] != 2 || masked["phone"] != 1 || masked["card"] != 1 || masked["secret"] != 1 {
		t.Errorf("told %s %v", route, masked)
	}
	// The ledger counts what was masked, and names none of it.
	b, _ := os.ReadFile(l.path)
	if !strings.Contains(string(b), `"masked":{`) || strings.Contains(string(b), "mailhost") {
		t.Errorf("ledger: %s", b)
	}
}

func TestARouteForPersonalDataStillGetsNoCardOrKey(t *testing.T) {
	h := &hearing{}
	cfg := Config{Routes: []Route{{Name: "local", URL: "http://127.0.0.1:11434/v1", Model: "m", Personal: true}}}
	l, _ := OpenLedger(filepath.Join(t.TempDir(), "usage.jsonl"), time.Now())
	g := New(cfg, func(Route) (Model, error) { return h, nil }, l)
	if _, err := g.For("agent:support").Complete(context.Background(), "",
		"mira.k@mailhost.net paid with 5425233430109903"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.heard, "mira.k@mailhost.net") || strings.Contains(h.heard, "5425233430109903") {
		t.Fatalf("heard %s", h.heard)
	}
}

func TestAModelOutsideTheGatewayIsGuardedAlike(t *testing.T) {
	h := &hearing{}
	var told map[string]int
	g := Guarded{Model: h, OnMasked: func(c map[string]int) { told = c }}
	out, err := g.Complete(context.Background(), "", "write to mira.k@mailhost.net")
	if err != nil || strings.Contains(h.heard, "mailhost") || out != "Reply sent to mira.k@mailhost.net." || told["email"] != 1 {
		t.Fatalf("heard %q, answered %q, told %v, %v", h.heard, out, told, err)
	}
}
