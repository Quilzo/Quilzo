// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
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

// Declaring a chatbot that is already declared changes what the command
// names and keeps the rest. It was built again from the flags alone, with
// only its actions carried over: a chatbot with an identity action was
// refused ("names no credential the site signs with") the moment its title
// was changed, and what the command has no flag for, and what it was not
// given, went without a word.
func TestRedeclaringAChatbotKeepsWhatItDoesNotName(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	t.Setenv(secretEnvName("shop-visitors"), "a-visitor-signing-key")
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help", "--public", "--model",
		"--exclude", "secret", "--instructions", "Be brief.", "--launcher", "--nudge", "Delivery?",
		"--nudge-pages", "/delivery"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAssistant(root, []string{"action", "help", "mine", "--kind", "agent", "--target", "bookings",
		"--description", "Your bookings", "--identity", "--identity-secret", "shop-visitors"}); err != nil {
		t.Fatal(err)
	}
	set, _ := assistant.Load(assistantsPath(root))
	a, _ := set.Get("help")
	a.KeepInstructions = true // the Chatbots screen's checkbox
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}

	if err := cmdAssistant(root, []string{"add", "help", "--title", "Ask the shop", "--handoff"}); err != nil {
		t.Fatalf("a chatbot with an identity action retitled: %v", err)
	}
	a, _ = loadAssistant(root, "help")
	if a.Title != "Ask the shop" || !a.Handoff {
		t.Errorf("what was named did not change: %+v", a)
	}
	if a.IdentitySecret != "shop-visitors" || !a.KeepInstructions || len(a.Actions) != 1 {
		t.Errorf("what the command has no flag for went: %+v", a)
	}
	if !a.Public || !a.UseModel || strings.Join(a.Exclude, ",") != "secret" || a.Instructions != "Be brief." ||
		a.Launcher == nil || a.Launcher.Nudge != "Delivery?" {
		t.Errorf("what was not named went: %+v", a)
	}

	// Named, a setting is turned off as it is turned on.
	if err := cmdAssistant(root, []string{"add", "help", "--launcher=false", "--model=false", "--exclude", ""}); err != nil {
		t.Fatal(err)
	}
	if a, _ = loadAssistant(root, "help"); a.Launcher != nil || a.UseModel || len(a.Exclude) != 0 || !a.Public {
		t.Errorf("turned off: %+v", a)
	}
	if err := cmdAssistant(root, []string{"add", "help", "--keep-instructions=false"}); err != nil {
		t.Fatal(err)
	}
	if a, _ = loadAssistant(root, "help"); a.KeepInstructions {
		t.Error("--keep-instructions=false kept passages that address an AI")
	}
}
