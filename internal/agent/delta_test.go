// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
	"time"
)

func base() Manifest {
	return Manifest{Name: "buyer", Kind: KindTask, Purpose: "buy",
		Capabilities: []string{"read_page", "browser_open"}, Autonomy: AutonomyPropose,
		Budget: Budget{Steps: 10, Tools: 2, Duration: Duration(time.Minute)}}
}

// Every widening is named, in words a reader reads, and nothing that
// narrows or stays is.
func TestEveryWideningIsNamed(t *testing.T) {
	old := base()
	old.Browser = &Browser{Read: []string{"docs.example.com"}}
	old.Shell = &Shell{Programs: []string{"ls"}, Hosts: nil, Ask: []string{"network", "write"}}

	nw := base()
	nw.Capabilities = []string{"read_page", "browser_open", "write_page"}
	nw.Autonomy = AutonomyPublish
	nw.Browser = &Browser{Read: []string{"docs.example.com", "shop.example.com"},
		Write: []string{"payments.example.com"}, Pictures: true}
	nw.Shell = &Shell{Programs: []string{"ls", "git"}, Hosts: []string{"github.com"}, Ask: []string{"network"}}
	nw.Delegates = []string{"researcher"}
	nw.Budget = Budget{Steps: 40, Tools: 9, Duration: Duration(time.Hour)}

	d := DeltaOf(old, nw)
	if !d.Widens {
		t.Fatal("a widening on every axis was not one")
	}
	got := d.Lines()
	for _, want := range []string{
		"may now write_page",
		"may now read shop.example.com",
		"may now act on payments.example.com",
		"may now be shown pictures",
		"may now run git",
		"may now reach github.com",
		"stopped asking a person before a command that writes",
		"may now hand work to researcher",
		"autonomy raised from propose to publish",
		"step budget raised from 10 to 40",
		"time budget raised",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the diff does not say %q:\n%s", want, got)
		}
	}
}

// Narrowing and standing still are not widenings, and no line is invented
// for them.
func TestNarrowingIsNotAWidening(t *testing.T) {
	old := base()
	old.Browser = &Browser{Read: []string{"docs.example.com", "shop.example.com"}}
	nw := base()
	nw.Browser = &Browser{Read: []string{"docs.example.com"}}
	nw.Budget = Budget{Steps: 5, Tools: 1, Duration: Duration(30 * time.Second)}
	if d := DeltaOf(old, nw); d.Widens || len(d.Added) != 0 {
		t.Fatalf("narrowing widened: %+v", d)
	}
	if d := DeltaOf(old, old); d.Widens {
		t.Fatal("an unchanged declaration widened")
	}
}

// What a declaration holds beyond capabilities and hosts widens too: a
// capability that stops asking, approval switched off, a cap dropped, a
// tool, a sign-in, pictures of a desktop, a wider read, memory switched
// on, a different program, a different workspace, another kind.
func TestTheQuietWideningsAreNamed(t *testing.T) {
	old := base()
	old.AskFirst = []string{"browser_open"}
	old.HumanApproval = true
	old.Budget.Tokens, old.Budget.Money = 1000, "0.50"
	old.Tools = []Tool{{Name: "crm", Host: "crm.example.com", Purpose: "look up"}}
	old.Browser = &Browser{Read: []string{"docs.example.com"}}
	old.Cell = &Cell{}
	old.Retrieval = Retrieval{Types: []string{"page"}, Path: "help"}
	old.Program = &Program{Command: []string{"/opt/agent/run"}}
	old.Shell = &Shell{Workspace: "reports"}

	nw := base()
	nw.Capabilities = append(nw.Capabilities, CellCapabilities[:]...)
	nw.Budget.Money = ""
	nw.Budget.Tokens = 5000
	nw.Tools = []Tool{{Name: "crm", Host: "crm.example.com", Purpose: "look up", Writes: true},
		{Name: "pay", Host: "pay.example.com", Purpose: "pay"}}
	nw.Browser = &Browser{Read: []string{"docs.example.com"},
		Credentials: []BrowserCredential{{Secret: "shop-login", Host: "docs.example.com"}}}
	nw.Cell = &Cell{Pictures: true}
	nw.Retrieval = Retrieval{Ref: "draft", Path: "", KeepInstructions: true}
	nw.Memory = Memory{Semantic: true, Retain: Duration(24 * time.Hour)}
	nw.Program = &Program{Command: []string{"/opt/agent/run", "--unsafe"}, Env: map[string]string{"TOKEN": "x"}}
	nw.Shell = &Shell{Workspace: "/"}
	nw.Kind = KindSupervisor

	got := DeltaOf(old, nw).Lines()
	for _, want := range []string{
		"stopped asking a person before browser_open",
		"no longer waits for a person's approval",
		"token budget raised from 1000 to 5000",
		"money budget raised from 0.50 to no cap",
		"may now call pay at pay.example.com",
		"crm may now change things at crm.example.com",
		"may now sign in with shop-login on docs.example.com",
		"pictures of the desktop",
		"now reads ref draft rather than the live site",
		"may now read all content types",
		"may now read everything rather than only help",
		"sentences addressed to an AI",
		"now remembers what it concluded",
		"now runs /opt/agent/run --unsafe",
		"environment now sets TOKEN",
		`its workspace is now "/" rather than "reports"`,
		"is now of kind supervisor rather than task",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("not named: %q\nin: %s", want, got)
		}
	}
	if strings.Contains(got, "=x") {
		t.Error("an environment value was written into the list")
	}
	// The same declaration, narrowed back, adds nothing to read.
	if d := DeltaOf(nw, old); strings.Contains(d.Lines(), "stopped asking") || strings.Contains(d.Lines(), "may now call") {
		t.Errorf("narrowing was listed as widening: %s", d.Lines())
	}
}
