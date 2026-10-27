// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentport

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/yamlite"
)

// Exported is an agent written in another platform's format, and what of
// the declaration that format has no place for.
type Exported struct {
	// Files are the files written, by name: one, except for an ADK agent
	// whose delegates are written beside it as config paths.
	Files map[string][]byte `json:"-"`
	Notes []Note            `json:"notes"`
}

// Write writes a declaration in a format. A run here enforces what the
// declaration says; another platform enforces what its own format says,
// so everything that is not carried is named, and nothing is claimed that
// the other side will not hold the agent to.
func Write(m agent.Manifest, format string) (*Exported, error) {
	f, ok := FormatNamed(format)
	if !ok || !f.Export {
		var can []string
		for _, f := range Formats {
			if f.Export {
				can = append(can, f.Name)
			}
		}
		return nil, fmt.Errorf("%q is not a format this writes; it writes %s", format, strings.Join(can, ", "))
	}
	e := &Exported{Files: map[string][]byte{}}
	note := func(kind, f string, a ...any) { e.Notes = append(e.Notes, Note{kind, fmt.Sprintf(f, a...)}) }
	instructions := m.Instructions
	if strings.TrimSpace(instructions) == "" {
		instructions = m.Purpose
		note(Changed, "its purpose, as its instructions: it has none of its own")
	}
	// What no other platform enforces, said once for every format but this
	// program's own.
	if format != "quilzo" {
		// The parts of the budget a format has a field for are carried
		// there (below), and only the rest is said to be left.
		var budget, unheld []string
		if format != "claude-subagent" && format != "crewai" {
			budget = append(budget, fmt.Sprintf("%d steps", m.Budget.Steps))
		}
		budget = append(budget, fmt.Sprintf("%d tool calls", m.Budget.Tools))
		if format != "crewai" {
			budget = append(budget, "a run of "+fmtDuration(m.Budget.Duration))
		}
		unheld = append(unheld, "its budget ("+strings.Join(budget, ", ")+")")
		unheld = append(unheld, "its autonomy ("+string(m.Autonomy)+")")
		if len(m.AskFirst) > 0 {
			unheld = append(unheld, "asking a person before "+strings.Join(m.AskFirst, ", "))
		}
		if m.Retrieval.Ref != "" {
			unheld = append(unheld, "reading only the "+m.Retrieval.Ref+" pages")
		}
		note(Left, "%s: the gate here enforces these, and the %s format has no field for them", names(unheld), f.Title)
		var content []string
		for _, c := range m.Capabilities {
			if !agent.IsShell(c) && !agent.IsBrowser(c) {
				content = append(content, c)
			}
		}
		if len(content) > 0 {
			note(Left, "its operations on this site (%s): another platform reaches this site only through "+
				"Quilzo's MCP server, which it would be given as a tool", strings.Join(content, ", "))
		}
		if len(m.Tools) > 0 {
			var l []string
			for _, t := range m.Tools {
				l = append(l, t.Name+" on "+t.Host)
			}
			note(Left, "its tools (%s): declare them there in that platform's own way", strings.Join(l, ", "))
		}
	}
	var err error
	switch format {
	case "quilzo":
		var b []byte
		b, err = json.MarshalIndent(m, "", "  ")
		e.Files[m.Name+".json"] = append(b, '\n')
		note(Kept, "the whole declaration")
	case "claude-subagent":
		err = writeClaudeSubagent(e, m, instructions, note)
	case "claude-agents":
		d := map[string]any{"description": m.Purpose, "prompt": instructions}
		if tools := claudeToolsFor(m); len(tools) > 0 {
			d["tools"] = tools
		}
		if m.Model != "" {
			d["model"] = m.Model
		}
		var b []byte
		b, err = json.MarshalIndent(map[string]any{m.Name: d}, "", "  ")
		e.Files[m.Name+".agents.json"] = append(b, '\n')
		noteClaude(m, note)
	case "adk":
		err = writeADK(e, m, instructions, note)
	case "m365":
		err = writeM365(e, m, instructions, note)
	case "agentspec":
		err = writeAgentSpec(e, m, instructions, note)
	case "crewai":
		err = writeCrewAI(e, m, instructions, note)
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

// claudeToolsFor is the workspace here as Claude Code's tools.
func claudeToolsFor(m agent.Manifest) []string {
	var tools []string
	if slices.Contains(m.Capabilities, "file_read") || slices.Contains(m.Capabilities, "file_list") {
		tools = append(tools, "Read", "Glob", "Grep")
	}
	if slices.Contains(m.Capabilities, "file_write") {
		tools = append(tools, "Write", "Edit")
	}
	if slices.Contains(m.Capabilities, "shell_run") {
		tools = append(tools, "Bash")
	}
	if m.Browser != nil && len(m.Browser.Read) > 0 {
		tools = append(tools, "WebFetch")
	}
	return tools
}

func noteClaude(m agent.Manifest, note func(string, string, ...any)) {
	if slices.Contains(m.Capabilities, "shell_run") && m.Shell != nil && len(m.Shell.Programs) > 0 {
		note(Changed, "its programs (%s), as Bash, which runs any command: add a permission rule in Claude Code "+
			"to hold it to these", strings.Join(m.Shell.Programs, ", "))
	}
	if m.Browser != nil && len(m.Browser.Read) > 0 {
		note(Changed, "its browser, which reads %s, as WebFetch, which fetches any address: add a permission "+
			"rule in Claude Code to hold it to these", strings.Join(m.Browser.Read, ", "))
	}
	if len(m.Delegates) > 0 {
		note(Left, "its delegates (%s): a subagent does not start subagents", strings.Join(m.Delegates, ", "))
	}
}

func writeClaudeSubagent(e *Exported, m agent.Manifest, instructions string, note func(string, string, ...any)) error {
	fm := yamlite.Map{kv("name", m.Name), kv("description", m.Purpose)}
	if tools := claudeToolsFor(m); len(tools) > 0 {
		fm = append(fm, kv("tools", strings.Join(tools, ", ")))
	} else {
		// Omitted, a subagent inherits every tool; an agent with none here
		// is given none there.
		fm = append(fm, kv("tools", ""))
		note(Changed, "no Claude Code tools: given an empty tools list, since a subagent without one inherits every tool")
	}
	if m.Model != "" {
		fm = append(fm, kv("model", m.Model))
	}
	fm = append(fm, kv("maxTurns", m.Budget.Steps))
	note(Changed, "its budget of %d steps, as maxTurns", m.Budget.Steps)
	head, err := yamlite.Marshal(fm)
	if err != nil {
		return err
	}
	body := "---\n" + string(head) + "---\n\n" + strings.TrimSpace(instructions) + "\n"
	e.Files[m.Name+".md"] = []byte(body)
	noteClaude(m, note)
	return nil
}

// adkName is a name as ADK takes one: a Python identifier.
func adkName(s string) string {
	s = strings.ReplaceAll(Slug(s), "-", "_")
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		s = "agent_" + s
	}
	return s
}

func writeADK(e *Exported, m agent.Manifest, instructions string, note func(string, string, ...any)) error {
	doc := yamlite.Map{kv("agent_class", "LlmAgent"), kv("name", adkName(m.Name))}
	if m.Model != "" {
		doc = append(doc, kv("model", m.Model))
	} else {
		note(Decide, "it names no model, and ADK needs one: set model in %s.yaml", adkName(m.Name))
	}
	doc = append(doc, kv("description", m.Purpose), kv("instruction", instructions))
	if len(m.Delegates) > 0 {
		var subs []any
		for _, d := range m.Delegates {
			subs = append(subs, yamlite.Map{kv("config_path", adkName(d)+".yaml")})
		}
		doc = append(doc, kv("sub_agents", subs))
		note(Changed, "its delegates, as sub-agents by config path: export each of them to ADK beside it")
	}
	if adkName(m.Name) != m.Name {
		note(Changed, "named %s: ADK's names are Python identifiers", adkName(m.Name))
	}
	if strings.Contains(instructions, "{") {
		note(Decide, "its instructions hold braces, which ADK reads as session state ({name}): write {{ or check them")
	}
	b, err := yamlite.Marshal(doc)
	if err != nil {
		return err
	}
	e.Files[adkName(m.Name)+".yaml"] = append([]byte("# Google ADK agent config, from Quilzo's declaration of "+m.Name+"\n"), b...)
	return nil
}

func writeM365(e *Exported, m agent.Manifest, instructions string, note func(string, string, ...any)) error {
	if len(m.Name) > 100 {
		return fmt.Errorf("a declarative agent's name is at most 100 characters, and %s's is %d", m.Name, len(m.Name))
	}
	if len(instructions) > 8000 {
		return fmt.Errorf("a declarative agent's instructions are at most 8,000 characters, and %s's are %d: shorten them first", m.Name, len(instructions))
	}
	doc := map[string]any{
		"$schema": "https://developer.microsoft.com/json-schemas/copilot/declarative-agent/v1.5/schema.json",
		"version": "v1.5", "name": m.Name, "description": m.Purpose, "instructions": instructions,
	}
	if m.Browser != nil && len(m.Browser.Read) > 0 {
		var sites []map[string]string
		hosts := slices.Clone(m.Browser.Read)
		sort.Strings(hosts)
		for i, h := range hosts {
			if i == 4 {
				note(Decide, "its browser reads %d hosts and web search takes at most 4 sites: choose which (%s)", len(hosts), strings.Join(hosts, ", "))
				break
			}
			sites = append(sites, map[string]string{"url": "https://" + h})
		}
		doc["capabilities"] = []any{map[string]any{"name": "WebSearch", "sites": sites}}
		note(Changed, "its browser's hosts, as the sites its web search is limited to: Copilot searches them, and reads no page this program would not")
	}
	if len(m.Delegates) > 0 {
		note(Left, "its delegates (%s): name them as worker agents in Copilot once they are there", strings.Join(m.Delegates, ", "))
	}
	if m.Model != "" {
		note(Left, "its model (%s): Copilot chooses the model", m.Model)
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	e.Files[m.Name+".declarativeAgent.json"] = append(b, '\n')
	return err
}

// AgentSpecVersion is the Open Agent Specification version written: the
// one that introduced every field written here.
const AgentSpecVersion = "25.4.1"

func writeAgentSpec(e *Exported, m agent.Manifest, instructions string, note func(string, string, ...any)) error {
	llm := yamlite.Map{kv("component_type", "OpenAiCompatibleConfig"), kv("name", "model"),
		kv("model_id", m.Model), kv("url", "")}
	if m.Model == "" {
		note(Decide, "it names no model: fill in llm_config.model_id")
	}
	note(Decide, "fill in llm_config.url with where the model is served: a gateway route here is not part of the declaration")
	doc := yamlite.Map{
		kv("component_type", "Agent"),
		kv("id", m.Name),
		kv("name", m.Name),
		kv("description", m.Purpose),
		kv("metadata", yamlite.Map{kv("quilzo_kind", string(m.Kind))}),
		kv("llm_config", llm),
		kv("system_prompt", instructions),
		kv("tools", []any{}),
		kv("agentspec_version", AgentSpecVersion),
	}
	if len(m.Delegates) > 0 {
		note(Left, "its delegates (%s): Agent Spec composes agents in a Flow or a Swarm, which is written there", strings.Join(m.Delegates, ", "))
	}
	b, err := yamlite.Marshal(doc)
	e.Files[m.Name+".agentspec.yaml"] = b
	return err
}

func writeCrewAI(e *Exported, m agent.Manifest, instructions string, note func(string, string, ...any)) error {
	id := adkName(m.Name)
	a := yamlite.Map{
		kv("role", m.Name),
		kv("goal", m.Purpose),
		kv("backstory", instructions),
	}
	if m.Model != "" {
		a = append(a, kv("llm", m.Model))
	}
	a = append(a, kv("max_iter", m.Budget.Steps),
		kv("max_execution_time", int(int64(m.Budget.Duration)/1e9)),
		kv("allow_delegation", len(m.Delegates) > 0))
	note(Changed, "its name as its role, its purpose as its goal and its instructions as its backstory, as CrewAI asks for them")
	note(Changed, "its budget of %d steps and %s, as max_iter and max_execution_time", m.Budget.Steps, fmtDuration(m.Budget.Duration))
	if len(m.Delegates) > 0 {
		note(Changed, "its delegates, as allow_delegation: CrewAI lets it hand work to anyone in its crew, not only %s", strings.Join(m.Delegates, ", "))
	}
	if strings.ContainsAny(instructions, "{}") {
		note(Decide, "its instructions hold braces, which CrewAI fills in from the crew's inputs ({topic}): check them")
	}
	b, err := yamlite.Marshal(yamlite.Map{kv(id, a)})
	e.Files[id+".agents.yaml"] = b
	return err
}

func kv(key string, value any) yamlite.KV { return yamlite.KV{Key: key, Value: value} }
