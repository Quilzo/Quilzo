// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A site with no chatbots lists none over the agent interface as it does
// on the command line: an empty list, not the JSON null a nil slice
// marshals to, which a client expecting a list had to special-case.
func TestNoChatbotsListAsAnEmptyListOverTheInterface(t *testing.T) {
	root := publishedShop(t)
	text, merr := callTool(t, assistantMCP(t, root), "quilzo_read", "list_assistants", map[string]any{})
	if merr != nil {
		t.Fatal(merr.Message)
	}
	if text != "[]" {
		t.Fatalf("a site with no chatbots listed %q", text)
	}
}

// An evaluation given a file that is not there says so. A missing file
// read as an empty one, so a mistyped path in a CI job was reported as a
// file that "holds no cases", and a decider's evaluation went on with
// none.
func TestAnEvaluationOfAFileThatIsNotThereSaysSo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "zz.jsonl")
	err := cmdAssistant(root, []string{"eval", "help", missing})
	if err == nil || !strings.Contains(err.Error(), "no such file: "+missing) {
		t.Errorf("a chatbot's evaluation of a missing file: %v", err)
	}
	file := filepath.Join(t.TempDir(), "d.json")
	if err := os.WriteFile(file, []byte(ticketDecider), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDecide(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	err = cmdDecide(root, []string{"eval", "ticket", missing})
	if err == nil || !strings.Contains(err.Error(), "no such file: "+missing) {
		t.Errorf("a decider's evaluation of a missing file: %v", err)
	}
}

// An identity action names a credential that is there. One named before
// it was sealed, or mistyped, was saved, and the action was then never
// offered to anybody with nothing to say why.
func TestAnIdentityActionNamesASealedCredential(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	err := cmdAssistant(root, []string{"action", "help", "mine", "--kind", "agent", "--target", "bookings",
		"--description", "Your bookings", "--identity", "--identity-secret", "shop-visitors"})
	if err == nil || !strings.Contains(err.Error(), "shop-visitors") {
		t.Fatalf("an identity action naming no credential there: %v", err)
	}
	if a, _ := loadAssistant(root, "help"); a.IdentitySecret != "" || len(a.Actions) != 0 {
		t.Fatalf("it was saved all the same: %+v", a)
	}
	// Once it is there, the same command is accepted.
	t.Setenv(secretEnvName("shop-visitors"), "a-visitor-signing-key")
	if err := cmdAssistant(root, []string{"action", "help", "mine", "--kind", "agent", "--target", "bookings",
		"--description", "Your bookings", "--identity", "--identity-secret", "shop-visitors"}); err != nil {
		t.Fatal(err)
	}
}
