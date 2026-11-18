// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
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

// chatbotMCPAs is the chatbot operations over the agent interface, as who
// holding a token for role, on a store whose policy says what each person
// may do.
func chatbotMCPAs(root, who string, role auth.Role) *mcp.Server {
	srv := mcp.NewServer("quilzo", "test")
	srv.Authorise = func(mcp.Operation) error { return nil }
	registerAssistantOps(srv, root, &Caller{Name: who, Role: role, Scope: "/", Kind: audit.KindHuman, Verified: true})
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

// ledgerPayers is who each model call in the store's ledger was charged to,
// its own caller first.
func ledgerPayers(t *testing.T, root string) [][]string {
	t.Helper()
	b, err := os.ReadFile(usagePath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var u gateway.Usage
		if err := json.Unmarshal([]byte(line), &u); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		out = append(out, append([]string{u.Consumer}, u.Also...))
	}
	return out
}

// Somebody trying a chatbot, on the command line or over the agent
// interface, is charged for it against their own budget, and the
// chatbot's budget is left for its visitors. Every ask was charged to
// chatbot:NAME: a reader's thirty-question evaluation used up a public
// chatbot's day, every visitor after it was answered from the pages
// without the model, and the gateway's status did not say who had spent it.
func TestTryingAChatbotIsChargedToWhoeverTriesIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USER", "rita")
	root := publishedShop(t)
	var calls int64
	up := modelServer(t, false, &calls)
	if err := cmdGateway(root, []string{"route", "add", "main", "--url", up.URL + "/v1", "--model", "small"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help", "--model", "--public"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAssistant(root, []string{"ask", "help", "can I return opened ink"}); err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(t.TempDir(), "cases.jsonl")
	if err := os.WriteFile(cases, []byte(`{"question": "can I return opened ink", "page": "returns"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdAssistant(root, []string{"eval", "help", cases}); err != nil {
		t.Fatal(err)
	}
	if _, merr := callTool(t, assistantMCP(t, root), "quilzo_read", "ask_assistant",
		map[string]any{"name": "help", "question": "can I return opened ink"}); merr != nil {
		t.Fatal(merr.Message)
	}
	tried := ledgerPayers(t, root)
	if len(tried) < 3 {
		t.Fatalf("the ledger holds %v", tried)
	}
	for _, who := range tried {
		if slices.Contains(who, "chatbot:help") {
			t.Errorf("trying the chatbot was charged to its visitors' budget: %v", who)
		}
	}
	if !slices.ContainsFunc(tried, func(who []string) bool { return who[0] == "person:rita" }) ||
		!slices.ContainsFunc(tried, func(who []string) bool { return who[0] == "person:dana" }) {
		t.Errorf("nobody who tried it was charged: %v", tried)
	}

	// A visitor's question is the chatbot's, as it was.
	a, _ := loadAssistant(root, "help")
	idx, err := assistantIndex(root, a)
	if err != nil {
		t.Fatal(err)
	}
	m, why := assistantModelAt(root, a)
	if m == nil {
		t.Fatal(why)
	}
	if _, err := assistant.Respond(context.Background(), a, idx, m, "can I return opened ink"); err != nil {
		t.Fatal(err)
	}
	all := ledgerPayers(t, root)
	if last := all[len(all)-1]; last[0] != "chatbot:help" {
		t.Errorf("a visitor's question was charged to %v", last)
	}

	// The admin's test console, a suggested reply in the Inbox and asking
	// unanswered questions again are the person's who does them.
	gui := assistantsCapability(root)
	idx, _, err = gui.Index(a, "sam")
	if err != nil {
		t.Fatal(err)
	}
	m, _ = gui.Model(a, "sam")
	if _, err := assistant.Respond(context.Background(), a, idx, m, "can I return opened ink"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inboxHooks(root).Suggest("help", "can I return opened ink", "sam"); err != nil {
		t.Fatal(err)
	}
	keepGaps(t, root)
	gapKeeper(root)("help", "how much is delivery to the moon")
	if asked, _, err := gui.CheckGaps(context.Background(), "help", "sam"); err != nil || asked == 0 {
		t.Fatalf("asked %d again: %v", asked, err)
	}
	all = ledgerPayers(t, root)
	if len(all) < len(tried)+4 {
		t.Fatalf("the console, the suggestion and the check made %d calls", len(all)-len(tried)-1)
	}
	for _, who := range all[len(tried)+1:] {
		if strings.Join(who, ",") != "person:sam" {
			t.Errorf("trying the chatbot on a screen was charged to %v", who)
		}
	}
}

// chatbotPeople is a published shop with a private chatbot, desk, and a
// person on each rung: dana the administrator, pat a publisher, ed an author
// and rita a reader, each with their own token.
func chatbotPeople(t *testing.T) (root string, tokens map[string]string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root = publishedShop(t)
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	if err := cmdAssistant(root, []string{"add", "desk", "--title", "Desk", "--exclude", "returns"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	tokens = map[string]string{"dana": personToken(t, root, "dana", auth.RoleAdmin)}
	flagToken = tokens["dana"]
	for who, role := range map[string]auth.Role{"pat": auth.RolePublisher, "ed": auth.RoleAuthor, "rita": auth.RoleReader} {
		if err := cmdAuth(root, []string{"grant", who, string(role)}); err != nil {
			t.Fatal(err)
		}
		tokens[who] = personToken(t, root, who, role)
	}
	return root, tokens
}

// chatbotAs runs `quilzo assistant ARGS` as who: through the gate in front
// of every command, as the binary does, and then the command.
func chatbotAs(t *testing.T, root string, tokens map[string]string, who string, args ...string) error {
	t.Helper()
	flagToken = tokens[who]
	if err := authoriseCommand(root, "assistant", args); err != nil {
		return err
	}
	return cmdAssistant(root, args)
}

// Reading and closing what a chatbot could not answer is an author's on
// the command line, as it is on the Chatbots screen and over the agent
// interface: the gaps are visitors' words, for whoever may read the Inbox.
// The command's gate took the row for declaring a chatbot, which is a
// publisher's, so an author was refused here what the browser let them do.
func TestAnAuthorReadsAndClosesAChatbotsGapsOnTheCommandLine(t *testing.T) {
	root, tokens := chatbotPeople(t)
	if err := chatbotAs(t, root, tokens, "ed", "gaps", "desk"); err != nil {
		t.Errorf("an author was refused the gaps: %v", err)
	}
	if err := chatbotAs(t, root, tokens, "rita", "gaps", "desk"); err == nil {
		t.Error("a reader read visitors' unanswered questions")
	}
}

// Building a private chatbot, what it is called and says and which pages
// it reads, is an author's on every surface, as it was over the agent
// interface; the rest of it is a publisher's everywhere. declare_assistant
// let an author's agent rename a chatbot and change what it reads, while
// `assistant add` refused the author the same ("publish needs publisher").
func TestAnAuthorBuildsAPrivateChatbotOnEverySurface(t *testing.T) {
	root, tokens := chatbotPeople(t)
	if err := chatbotAs(t, root, tokens, "ed", "add", "desk", "--title", "Front desk", "--greeting", "Hello"); err != nil {
		t.Fatalf("an author was refused building a private chatbot: %v", err)
	}
	if a, _ := loadAssistant(root, "desk"); a.Title != "Front desk" || a.Greeting != "Hello" || strings.Join(a.Exclude, ",") != "returns" {
		t.Errorf("built: %+v", a)
	}
	if err := chatbotAs(t, root, tokens, "ed", "add", "spare", "--title", "Spare", "--pages", "delivery"); err != nil {
		t.Errorf("an author was refused a new private chatbot: %v", err)
	}
	for _, flags := range [][]string{{"--public"}, {"--model"}, {"--collections", "orders"}, {"--handoff"}} {
		if err := chatbotAs(t, root, tokens, "ed", append([]string{"add", "desk"}, flags...)...); err == nil {
			t.Errorf("an author changed what is a publisher's: %v", flags)
		}
	}
	if err := chatbotAs(t, root, tokens, "rita", "add", "desk", "--title", "Mine"); err == nil {
		t.Error("a reader changed a chatbot")
	}
	if _, merr := callTool(t, chatbotMCPAs(root, "rita", auth.RoleReader), "quilzo_write", "declare_assistant",
		map[string]any{"name": "desk", "title": "Mine"}); merr == nil {
		t.Error("a reader's agent changed a chatbot")
	}
	if _, merr := callTool(t, chatbotMCPAs(root, "ed", auth.RoleAuthor), "quilzo_write", "declare_assistant",
		map[string]any{"name": "desk", "refusal": "Ask at the desk"}); merr != nil {
		t.Errorf("an author's agent was refused: %s", merr.Message)
	}

	// Public, it is a publisher's to change, everywhere.
	if err := chatbotAs(t, root, tokens, "pat", "add", "desk", "--public"); err != nil {
		t.Fatal(err)
	}
	if err := chatbotAs(t, root, tokens, "ed", "add", "desk", "--title", "Renamed"); err == nil {
		t.Error("an author changed a public chatbot")
	}
	if _, merr := callTool(t, chatbotMCPAs(root, "ed", auth.RoleAuthor), "quilzo_write", "declare_assistant",
		map[string]any{"name": "desk", "title": "Renamed"}); merr == nil {
		t.Error("an author's agent changed a public chatbot")
	}
	if a, _ := loadAssistant(root, "desk"); a.Title != "Front desk" || a.Refusal != "Ask at the desk" || !a.Public {
		t.Errorf("the chatbot is %+v", a)
	}
}
