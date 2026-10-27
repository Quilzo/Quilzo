// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// known is every operation a store here offers an agent, for checking the
// declarations an import makes as a store would.
var known = func() map[string]bool {
	k := map[string]bool{}
	for _, c := range []string{"read_page", "list_pages", "search_pages", "similar_pages", "write_page",
		"write_record", "publish", "remember", "recall"} {
		k[c] = true
	}
	for _, l := range [][]string{agent.ShellCapabilities, agent.BrowserCapabilities, agent.CellCapabilities[:]} {
		for _, c := range l {
			k[c] = true
		}
	}
	return k
}()

func read(t *testing.T, file string) *Imported {
	t.Helper()
	data, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Read(data, "", "")
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return out
}

func byName(t *testing.T, out *Imported, name string) Agent {
	t.Helper()
	for _, a := range out.Agents {
		if a.Manifest.Name == name {
			return a
		}
	}
	var got []string
	for _, a := range out.Agents {
		got = append(got, a.Manifest.Name)
	}
	t.Fatalf("no agent %s; the file gave %v", name, got)
	return Agent{}
}

// noted says one of the agent's notes of a kind says sub.
func noted(a Agent, kind, sub string) bool {
	return slices.ContainsFunc(a.Notes, func(n Note) bool { return n.Kind == kind && strings.Contains(n.Text, sub) })
}

func mustNote(t *testing.T, a Agent, kind, sub string) {
	t.Helper()
	if !noted(a, kind, sub) {
		t.Errorf("%s: no %s note saying %q in\n%s", a.Manifest.Name, kind, sub, notes(a))
	}
}

func notes(a Agent) string {
	var b strings.Builder
	for _, n := range a.Notes {
		b.WriteString("  " + n.Kind + ": " + n.Text + "\n")
	}
	return b.String()
}

var fixtures = map[string]string{
	"openai_assistants.json": "openai-assistant", "code-reviewer.md": "claude-subagent",
	"claude_agents.json": "claude-agents", "root_agent.yaml": "adk", "declarativeAgent.json": "m365",
	"agentspec.json": "agentspec", "memo.af": "letta", "bedrock_agent.json": "bedrock", "bedrock_cfn.json": "bedrock",
	"agents.yaml": "crewai", "autogen_team.json": "autogen", "quilzo_tidy.json": "quilzo",
}

// Each platform's file is recognised for what it is, without being told.
func TestEachPlatformsAgentIsRecognised(t *testing.T) {
	for file, want := range fixtures {
		data, err := os.ReadFile("testdata/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := Detect(data); err != nil || got != want {
			t.Errorf("%s was taken for %q (%v), not %s", file, got, err, want)
		}
	}
}

// Every agent an import makes is a declaration this program accepts, and
// every part of it is accounted for in a note.
func TestEveryImportedAgentIsAValidDeclaration(t *testing.T) {
	for file := range fixtures {
		out := read(t, file)
		for _, a := range out.Agents {
			m := a.Manifest
			if err := m.ValidateWith(known, nil); err != nil {
				t.Errorf("%s: %s is not a valid declaration: %v\n%s", file, m.Name, err, notes(a))
			}
			if len(a.Notes) == 0 || a.Source == "" {
				t.Errorf("%s: %s came with no account of itself", file, m.Name)
			}
			if m.Autonomy == agent.AutonomyPublish {
				t.Errorf("%s: %s may publish on its own, which nothing it came from said", file, m.Name)
			}
		}
	}
}

func TestOpenAIAssistants(t *testing.T) {
	out := read(t, "openai_assistants.json")
	if len(out.Agents) != 2 {
		t.Fatalf("%d agents from a list of two", len(out.Agents))
	}
	tutor := byName(t, out, "math-tutor")
	m := tutor.Manifest
	if m.Instructions != "You are a personal math tutor. When asked a question, write and run Python code to answer the question." ||
		m.Model != "gpt-4.1" || m.Purpose != "Helps students with algebra and geometry." {
		t.Errorf("%+v", m)
	}
	if !slices.Contains(m.Capabilities, "search_pages") {
		t.Errorf("file_search did not become searching: %v", m.Capabilities)
	}
	mustNote(t, tutor, Decide, "code interpreter")
	mustNote(t, tutor, Decide, "vs_2")
	mustNote(t, tutor, Decide, "get_grade")
	mustNote(t, tutor, Left, "temperature (0.2)")
	mustNote(t, tutor, Left, "metadata")
	// No name: called by its id, and it only converses.
	plain := byName(t, out, "asst-def456")
	if plain.Manifest.Kind != agent.KindRetrieval || plain.Manifest.Autonomy != agent.AutonomyPropose {
		t.Errorf("%+v", plain.Manifest)
	}
	mustNote(t, plain, Decide, "chatbot")
}

func TestClaudeCodeSubagent(t *testing.T) {
	a := read(t, "code-reviewer.md").Agents[0]
	m := a.Manifest
	if m.Name != "code-reviewer" || !strings.HasPrefix(m.Instructions, "You are a code reviewer.") ||
		!strings.HasSuffix(m.Instructions, "best practices.") || m.Model != "sonnet" || m.Budget.Steps != 12 {
		t.Errorf("%+v", m)
	}
	if !slices.Contains(m.Capabilities, "file_read") || slices.Contains(m.Capabilities, "file_write") || m.Shell == nil {
		t.Errorf("Read, Glob and Grep are a workspace it reads: %v %+v", m.Capabilities, m.Shell)
	}
	mustNote(t, a, Decide, "Bash ran any command")
	mustNote(t, a, Decide, "WebFetch reached the web")
	mustNote(t, a, Decide, "mcp__github__get_pull_request")
	mustNote(t, a, Changed, "alias")
	mustNote(t, a, Left, "color")
}

func TestClaudeAgentSDK(t *testing.T) {
	out := read(t, "claude_agents.json")
	runner := byName(t, out, "test-runner")
	if runner.Manifest.Model != "claude-sonnet-4-5" || !slices.Contains(runner.Manifest.Capabilities, "file_write") {
		t.Errorf("%+v", runner.Manifest)
	}
	// An empty tools list is no tools, which is a converser.
	mustNote(t, byName(t, out, "explainer"), Decide, "chatbot")
}

func TestGoogleADK(t *testing.T) {
	a := read(t, "root_agent.yaml").Agents[0]
	m := a.Manifest
	if m.Name != "travel-planner" || m.Model != "gemini-2.5-flash" || m.Kind != agent.KindSupervisor ||
		!reflect.DeepEqual(m.Delegates, []string{"hotel-agent", "weather-agent"}) ||
		!strings.Contains(m.Instructions, "plan the trip day by day") {
		t.Errorf("%+v", m)
	}
	mustNote(t, a, Decide, "{user:home_city}")
	mustNote(t, a, Decide, "google_search")
	mustNote(t, a, Decide, "my_tools.flights.search_flights")
	mustNote(t, a, Decide, "import hotel_agent.yaml as well")
	mustNote(t, a, Decide, "my_agents.weather.weather_agent")
	mustNote(t, a, Left, "output_key")
	mustNote(t, a, Left, "temperature (0.4)")
}

func TestMicrosoftCopilotDeclarativeAgent(t *testing.T) {
	a := read(t, "declarativeAgent.json").Agents[0]
	m := a.Manifest
	if m.Name != "repairs-helper" || m.Browser == nil ||
		!reflect.DeepEqual(m.Browser.Read, []string{"handbook.contoso.com", "status.contoso.com"}) ||
		!slices.Contains(m.Capabilities, "browser_read") || slices.Contains(m.Capabilities, "browser_click") {
		t.Errorf("web search limited to sites should read those sites and no more: %+v %+v", m, m.Browser)
	}
	if !strings.Contains(m.Instructions, "cite the handbook") || !strings.Contains(m.Instructions, "not from what you already know") {
		t.Errorf("instructions %q", m.Instructions)
	}
	mustNote(t, a, Decide, "OneDriveAndSharePoint and GraphConnectors")
	mustNote(t, a, Decide, "code interpreter")
	mustNote(t, a, Decide, "ai-plugin.json")
	mustNote(t, a, Left, "1 conversation starter")
	mustNote(t, a, Left, "disclaimer")
}

func TestOpenAgentSpec(t *testing.T) {
	a := read(t, "agentspec.json").Agents[0]
	m := a.Manifest
	if m.Model != "llama-3.3-70b" || len(m.Tools) != 1 || m.Tools[0].Host != "ops.example.com" || !m.Tools[0].Writes ||
		!slices.Contains(m.AskFirst, "restart_service") {
		t.Errorf("the referenced model and the remote tool: %+v", m)
	}
	mustNote(t, a, Decide, "http://10.0.0.5:8000")
	mustNote(t, a, Decide, "{{team}}")
	mustNote(t, a, Decide, "read_logs")
	mustNote(t, a, Decide, "search_runbooks")
	mustNote(t, a, Left, "temperature (0.1)")
	mustNote(t, a, Left, "human_in_the_loop")
}

func TestLettaAgentFile(t *testing.T) {
	a := read(t, "memo.af").Agents[0]
	m := a.Manifest
	if m.Model != "gpt-4o-mini" || !strings.Contains(m.Instructions, "You are Memo") ||
		!strings.Contains(m.Instructions, "<persona>\nI am Memo. I write short notes.\n</persona>") ||
		!strings.Contains(m.Instructions, "<human>\nThe team works on the payments service.\n</human>") {
		t.Errorf("%+v", m)
	}
	mustNote(t, a, Changed, "persona and human")
	mustNote(t, a, Left, "conversation_search")
	mustNote(t, a, Decide, "post_to_wiki")
	mustNote(t, a, Left, "2 messages")
	mustNote(t, a, Left, "1 tool rule, which is Letta's")
}

func TestAmazonBedrockAgent(t *testing.T) {
	a := read(t, "bedrock_agent.json").Agents[0]
	m := a.Manifest
	if m.Name != "order-support" || m.Model != "anthropic.claude-3-5-sonnet-20240620-v1:0" ||
		!strings.Contains(m.Instructions, "Never refund more than the order total") {
		t.Errorf("%+v", m)
	}
	tools := map[string]agent.Tool{}
	for _, tl := range m.Tools {
		tools[tl.Name] = tl
	}
	if g, r := tools["getOrder"], tools["createRefund"]; g.Host != "api.example-shop.com" || g.Writes || !r.Writes ||
		!slices.Contains(m.AskFirst, "createRefund") || slices.Contains(m.AskFirst, "getOrder") {
		t.Errorf("the OpenAPI action group's operations: %+v ask %v", m.Tools, m.AskFirst)
	}
	if doc := a.Files["orders.openapi.json"]; !json.Valid(doc) || !strings.Contains(string(doc), "createRefund") {
		t.Errorf("the action group's OpenAPI document was not kept for quilzo integrations import: %q", doc)
	}
	mustNote(t, a, Decide, "quilzo integrations import orders.openapi.json")
	mustNote(t, a, Decide, "add_points in loyalty ran in a Lambda, after the user confirmed it")
	mustNote(t, a, Left, "UserInput")
	mustNote(t, a, Decide, "KB9")
	mustNote(t, a, Left, "guardrail gr-1")

	cfn := read(t, "bedrock_cfn.json").Agents[0]
	if cfn.Manifest.Name != "faq-bot" || cfn.Manifest.Model != "amazon.nova-pro-v1:0" {
		t.Errorf("from CloudFormation: %+v", cfn.Manifest)
	}
	mustNote(t, cfn, Decide, "track in tracking")
}

func TestCrewAI(t *testing.T) {
	out := read(t, "agents.yaml")
	r := byName(t, out, "researcher")
	if r.Manifest.Model != "gpt-4o" || r.Manifest.Budget.Steps != 15 || r.Manifest.Budget.Duration != agent.Duration(300*time.Second) ||
		!strings.HasPrefix(r.Manifest.Instructions, "You are {topic} Senior Data Researcher. You're a seasoned researcher") ||
		!strings.HasSuffix(r.Manifest.Instructions, "Your personal goal is: Uncover cutting-edge developments in {topic}") {
		t.Errorf("%+v", r.Manifest)
	}
	mustNote(t, r, Changed, "openai/gpt-4o")
	mustNote(t, r, Decide, "{topic}")
	mustNote(t, r, Decide, "SerperDevTool")
	lead := byName(t, out, "lead")
	if lead.Manifest.Kind != agent.KindSupervisor || !reflect.DeepEqual(lead.Manifest.Delegates, []string{"researcher"}) {
		t.Errorf("allow_delegation: %+v", lead.Manifest)
	}
	mustNote(t, lead, Kept, "researcher, which this file declares too")
	mustNote(t, lead, Left, "max_rpm")
}

func TestAutoGenTeam(t *testing.T) {
	out := read(t, "autogen_team.json")
	if len(out.Agents) != 2 {
		t.Fatalf("%d agents from a team of two and a person", len(out.Agents))
	}
	w := byName(t, out, "writer")
	if w.Manifest.Model != "gpt-4o" || w.Manifest.Budget.Tools != 3 || !reflect.DeepEqual(w.Manifest.Delegates, []string{"editor"}) {
		t.Errorf("%+v", w.Manifest)
	}
	mustNote(t, w, Decide, "word_count")
	if !slices.ContainsFunc(out.Notes, func(n Note) bool { return strings.Contains(n.Text, "user is a person") }) ||
		!slices.ContainsFunc(out.Notes, func(n Note) bool { return strings.Contains(n.Text, "Writing team") }) {
		t.Errorf("the team and its person were not accounted for: %+v", out.Notes)
	}
}

// This program's own declaration comes back exactly as it went out.
func TestADeclarationComesBackWhole(t *testing.T) {
	data, _ := os.ReadFile("testdata/quilzo_tidy.json")
	var want agent.Manifest
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	got := read(t, "quilzo_tidy.json").Agents[0].Manifest
	if !reflect.DeepEqual(got, want) {
		t.Errorf("read back\n%+v\nwant\n%+v", got, want)
	}
	e, err := Write(got, "quilzo")
	if err != nil {
		t.Fatal(err)
	}
	again, err := Read(e.Files["tidy.json"], "", "")
	if err != nil || !reflect.DeepEqual(again.Agents[0].Manifest, want) {
		t.Errorf("written and read back: %+v %v", again, err)
	}
	// A field this program does not know is refused, not dropped.
	if _, err := Read([]byte(`{"name":"x","kind":"task","purpose":"p","budget":{},"surprise":1}`), "quilzo", ""); err == nil {
		t.Error("a declaration with a field nobody knows was read")
	}
}

// Written out to another platform and read back, an agent keeps its name,
// purpose, instructions and model, wherever that platform has a place for
// them; what it has no place for is said.
func TestWrittenOutAndReadBackItKeepsWhatTheFormatHolds(t *testing.T) {
	m := agent.Manifest{Name: "help-desk", Kind: agent.KindTask, Purpose: "Answers staff questions about the intranet.",
		Instructions: "You answer staff questions.\n\nCite the page you used.", Model: "gpt-4.1",
		Capabilities: []string{"browser_open", "browser_read", "file_list", "file_read"}, Autonomy: agent.AutonomyPropose,
		Browser: &agent.Browser{Read: []string{"intranet.example.com"}}, Shell: &agent.Shell{},
		Retrieval: agent.Retrieval{Ref: "live"}, Budget: agent.Budget{Steps: 9, Tools: 4, Duration: agent.Duration(3 * time.Minute)}}
	for _, f := range Formats {
		if !f.Export || f.Name == "quilzo" {
			continue
		}
		t.Run(f.Name, func(t *testing.T) {
			e, err := Write(m, f.Name)
			if err != nil {
				t.Fatal(err)
			}
			if len(e.Files) != 1 {
				t.Fatalf("%d files", len(e.Files))
			}
			if !slices.ContainsFunc(e.Notes, func(n Note) bool { return n.Kind == Left && strings.Contains(n.Text, "its budget") }) {
				t.Errorf("what the format does not hold was not said: %+v", e.Notes)
			}
			for name, body := range e.Files {
				back, err := Read(body, "", "")
				if err != nil {
					t.Fatalf("%s does not read back: %v\n%s", name, err, body)
				}
				if back.Format != f.Name {
					t.Errorf("%s reads back as %s", name, back.Format)
				}
				got := back.Agents[0].Manifest
				if got.Name != m.Name && f.Name != "crewai" {
					t.Errorf("name %q", got.Name)
				}
				if !strings.Contains(got.Instructions, m.Instructions) {
					t.Errorf("instructions\n%q\nnot in\n%q", m.Instructions, got.Instructions)
				}
				if f.Name != "m365" && got.Model != m.Model {
					t.Errorf("model %q", got.Model)
				}
				if got.Purpose != m.Purpose {
					t.Errorf("purpose %q", got.Purpose)
				}
				if err := got.ValidateWith(known, nil); err != nil {
					t.Errorf("read back, not valid: %v", err)
				}
			}
		})
	}
}

// What is not an agent definition is said to be, and an agent that runs
// elsewhere is pointed at the fleet.
func TestWhatIsNotAnAgentIsSaid(t *testing.T) {
	card := `{"name":"Booker","description":"Books rooms","url":"https://booker.example.com/a2a","skills":[{"id":"book"}],"capabilities":{}}`
	if _, err := Read([]byte(card), "", ""); err == nil || !strings.Contains(err.Error(), "quilzo fleet add") {
		t.Errorf("an A2A card: %v", err)
	}
	for _, s := range []string{`{"hello": "world"}`, `[1, 2]`, "just words", ""} {
		if _, err := Read([]byte(s), "", ""); err == nil || !errors.Is(err, ErrUnknown) {
			t.Errorf("%q: %v", s, err)
		}
	}
	if _, err := Read([]byte("{}"), "nonsense", ""); err == nil {
		t.Error("a format nobody knows was read")
	}
}

// Whatever arrives, cut off anywhere, is an error or agents: never a crash.
func TestNoFileCrashesTheImport(t *testing.T) {
	for file := range fixtures {
		data, _ := os.ReadFile("testdata/" + file)
		step := 1
		if len(data) > 1500 {
			step = 7
		}
		for i := 0; i <= len(data); i += step {
			_, _ = Read(data[:i], "", "")
			_, _ = Read(data[:i], fixtures[file], "")
		}
	}
}

func FuzzRead(f *testing.F) {
	for file := range fixtures {
		data, _ := os.ReadFile("testdata/" + file)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Read(data, "", "")
		if err != nil {
			return
		}
		for _, a := range out.Agents {
			// Whatever it made writes out again without a crash.
			for _, fm := range Formats {
				if fm.Export {
					_, _ = Write(a.Manifest, fm.Name)
				}
			}
		}
	})
}

// Delegates are declared before whoever hands them work, and a circle
// keeps the file's order rather than losing an agent.
func TestDelegatesAreDeclaredFirst(t *testing.T) {
	m := func(name string, delegates ...string) agent.Manifest {
		return agent.Manifest{Name: name, Delegates: delegates}
	}
	got := Order([]agent.Manifest{m("lead", "writer", "elsewhere"), m("writer", "checker"), m("checker")})
	if fmt.Sprint(got) != "[2 1 0]" {
		t.Fatalf("%v", got)
	}
	got = Order([]agent.Manifest{m("a", "b"), m("b", "a"), m("c")})
	if fmt.Sprint(got) != "[2 0 1]" {
		t.Fatalf("a circle: %v", got)
	}
}
