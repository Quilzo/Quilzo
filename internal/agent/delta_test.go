// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
