// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"
)

// A run waiting on a person is listed with what deciding commits to and
// the command that decides it; somebody who may not decide it is shown
// nothing of it.
func TestApprovalsListWhatARunWaitsOnAndHowToDecideIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"}, [2]string{"rae", "reader"})
	standInModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	items, err := waitingFor(root, asAdmin("sam"), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items {
		if it.Source == "run" && it.Agent == "tidy" {
			found = true
			if it.Commits != "writes" || !strings.Contains(it.Decide, "quilzo agent approve "+id) {
				t.Errorf("the waiting run reads as %+v", it)
			}
		}
	}
	if !found {
		t.Fatalf("the waiting run is not listed: %+v", items)
	}
	nobody := human("rae")
	nobody.Role = "reader"
	others, err := waitingFor(root, nobody, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range others {
		if it.Source == "run" {
			t.Fatalf("a reader was shown a run's question: %+v", it)
		}
	}
}
