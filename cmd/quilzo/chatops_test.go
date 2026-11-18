// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/mcp"
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

// chatbotMCPAs is the chatbot operations over the agent interface, as who, on a
// store whose policy says what each person may do.
func chatbotMCPAs(root, who string) *mcp.Server {
	srv := mcp.NewServer("quilzo", "test")
	srv.Authorise = func(mcp.Operation) error { return nil }
	registerAssistantOps(srv, root, &Caller{Name: who, Kind: audit.KindHuman, Verified: true})
	return srv
}

// Changing a private chatbot over the agent interface changes what it is
// given and keeps the rest, as the command line and the Chatbots screen
// do. Every setting it was not given was cleared: an agent renaming a
// chatbot wiped the pages it must never read and its instructions, and
// it then answered from the pages it had been kept from.
func TestDeclaringAChatbotOverTheInterfaceKeepsWhatItIsNotGiven(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help", "--exclude", "returns",
		"--instructions", "Be brief.", "--greeting", "Hello", "--refusal", "Ask us"}); err != nil {
		t.Fatal(err)
	}
	if _, merr := callTool(t, assistantMCP(t, root), "quilzo_write", "declare_assistant",
		map[string]any{"name": "help", "title": "Help, renamed"}); merr != nil {
		t.Fatal(merr.Message)
	}
	a, _ := loadAssistant(root, "help")
	if a.Title != "Help, renamed" {
		t.Errorf("the title given did not change: %q", a.Title)
	}
	if strings.Join(a.Exclude, ",") != "returns" || a.Instructions != "Be brief." || a.Greeting != "Hello" ||
		a.Refusal != "Ask us" {
		t.Errorf("what it was not given was cleared: %+v", a)
	}
	// A new one still needs its title, as everywhere.
	if _, merr := callTool(t, assistantMCP(t, root), "quilzo_write", "declare_assistant",
		map[string]any{"name": "other"}); merr == nil {
		t.Error("a chatbot was declared with no title")
	}
}

// budgetOf is the budget a caller has of its own in the store's gateway.
func budgetOf(t *testing.T, root, who string) gateway.Budget {
	t.Helper()
	cfg, err := gateway.Load(gatewayPath(root))
	if err != nil || cfg == nil {
		t.Fatalf("the gateway: %v %v", cfg, err)
	}
	for _, b := range cfg.Budgets {
		if b.Consumer == who {
			return b
		}
	}
	return gateway.Budget{}
}

// Changing one limit of a budget from the command line keeps the others,
// and naming a caller alone shows its budget. The budget was built again
// from the flags given, zero meaning unlimited: `--per-minute 30` lifted a
// public chatbot's money and character caps without a word, and
// `gateway budget chatbot:help`, typed to see it, lifted every limit.
func TestChangingOneLimitOfABudgetKeepsTheOthers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	if err := cmdGateway(root, []string{"currency", "GBP"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--money-per-day", "5.00",
		"--chars-per-day", "100000"}); err != nil {
		t.Fatal(err)
	}
	set := gateway.Budget{Consumer: "chatbot:help", CharsPerDay: 100000, MoneyPerDay: "5.00"}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--per-minute", "30"}); err != nil {
		t.Fatal(err)
	}
	set.PerMinute = 30
	if got := budgetOf(t, root, "chatbot:help"); got != set {
		t.Errorf("one limit changed left %+v", got)
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help"}); err != nil {
		t.Fatal(err)
	}
	if got := budgetOf(t, root, "chatbot:help"); got != set {
		t.Errorf("asking for the budget changed it to %+v", got)
	}
	// Named, a limit goes as it came; --remove is how the budget goes.
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--money-per-day", ""}); err != nil {
		t.Fatal(err)
	}
	set.MoneyPerDay = ""
	if got := budgetOf(t, root, "chatbot:help"); got != set {
		t.Errorf("a limit lifted by name left %+v", got)
	}
}
