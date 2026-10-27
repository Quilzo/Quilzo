// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/apiimport"
	"github.com/quilzo/quilzo/internal/yamlite"
)

// Each reader follows its platform's published schema; the field names are
// theirs, and a field this program has no use for is named in a note
// rather than passed over.

// -- this program ------------------------------------------------------------

func readQuilzo(data []byte) (*Imported, error) {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	dec.DisallowUnknownFields()
	var m agent.Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	a := Agent{Manifest: m, Source: "declaration " + m.Name}
	a.note(Kept, "the whole declaration, as written")
	return &Imported{Agents: []Agent{a}}, nil
}

// -- OpenAI Assistants -----------------------------------------------------

func readOpenAI(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	var items []any
	switch {
	case list(v) != nil:
		items = list(v)
	case str(obj(v)["object"]) == "list":
		items = list(obj(v)["data"])
	default:
		items = []any{v}
	}
	out := &Imported{}
	for i, it := range items {
		a := obj(it)
		if a == nil {
			return nil, fmt.Errorf("item %d is not an assistant", i)
		}
		out.Agents = append(out.Agents, openAIAssistant(a, i))
	}
	return out, nil
}

func openAIAssistant(a map[string]any, i int) Agent {
	id := str(a["id"])
	name := str(a["name"])
	if name == "" {
		name = id
	}
	src := fmt.Sprintf("assistant %d", i)
	if id != "" {
		src = "assistant " + id
	}
	b := newAgent("openai-assistant", src, name)
	b.purpose(str(a["description"]))
	b.instructions(str(a["instructions"]))
	b.model(str(a["model"]))
	b.generation("temperature", a["temperature"])
	b.generation("top_p", a["top_p"])
	if rf := a["response_format"]; rf != nil && str(rf) != "auto" {
		b.left("its response format: a run here answers in its own shape, and the run's answer is what it says when done")
	}
	res := obj(a["tool_resources"])
	for _, t := range list(a["tools"]) {
		tool := obj(t)
		switch str(tool["type"]) {
		case "code_interpreter":
			b.unmapped("it ran code in OpenAI's code interpreter: here code runs in a declared workspace " +
				"(a shell with named programs) or a program in a box (quilzo agent program); declare one if it needs to")
			if ids := list(obj(res["code_interpreter"])["file_ids"]); len(ids) > 0 {
				b.left("%s given to its code interpreter, which are OpenAI's", count(len(ids), "file", "files"))
			}
		case "file_search":
			b.read("it searched files (file_search)")
			if ids := list(obj(res["file_search"])["vector_store_ids"]); len(ids) > 0 {
				var l []string
				for _, id := range ids {
					l = append(l, str(id))
				}
				b.unmapped("its vector store %s is OpenAI's: publish what it holds here, or reach it through an integration", names(l))
			}
		case "function":
			f := obj(tool["function"])
			b.unmapped("its function %s ran in your own code: here a tool is a call to a host. Offer it through an "+
				"integration (quilzo integrations import an OpenAPI document or an MCP server), pin it, and add it "+
				"to the declaration's tools", str(f["name"]))
		default:
			b.left("its %s tool, which this program has no counterpart for", str(tool["type"]))
		}
	}
	if md := obj(a["metadata"]); len(md) > 0 {
		b.left("its metadata (%s)", count(len(md), "key", "keys"))
	}
	return b.finish()
}

// -- Claude ------------------------------------------------------------------

// splitFrontMatter splits a Markdown file into its YAML front matter and
// its body.
func splitFrontMatter(data []byte) (map[string]any, string, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return nil, "", errors.New("a subagent file starts with front matter between --- lines")
	}
	rest := text[4:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return nil, "", errors.New("the front matter never ends with a --- line")
	}
	fm, body := rest[:end], rest[end+4:]
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		if strings.TrimSpace(body[:i]) != "" {
			return nil, "", errors.New("something follows the closing --- on its line")
		}
		body = body[i+1:]
	} else {
		body = ""
	}
	v, err := yamlite.Parse([]byte(fm))
	if err != nil {
		return nil, "", fmt.Errorf("the front matter: %w", err)
	}
	m := obj(v)
	if m == nil {
		return nil, "", errors.New("the front matter is not a set of fields")
	}
	return m, body, nil
}

func readClaudeSubagent(data []byte) (*Imported, error) {
	fm, body, err := splitFrontMatter(data)
	if err != nil {
		return nil, err
	}
	name := str(fm["name"])
	if name == "" || str(fm["description"]) == "" {
		return nil, errors.New("a subagent needs a name and a description in its front matter")
	}
	b := newAgent("claude-subagent", "subagent "+name, name)
	b.purpose(str(fm["description"]))
	b.instructions(body)
	claudeModel(b, str(fm["model"]))
	if _, given := fm["tools"]; given {
		claudeTools(b, stringsOf(fm["tools"]))
	} else {
		b.unmapped("it inherits every tool of whatever runs it, and an agent here holds only what it declares: name what it uses")
	}
	if dis := stringsOf(fm["disallowedTools"]); len(dis) > 0 {
		b.left("its disallowed tools (%s): nothing is held here unless it is declared", strings.Join(dis, ", "))
	}
	if pm := str(fm["permissionMode"]); pm != "" && pm != "default" && pm != "manual" {
		b.left("its permission mode %s: here autonomy and what it asks first are declared, and start at proposing", pm)
	}
	if n, ok := num(fm["maxTurns"]); ok {
		b.steps(n, "its maxTurns")
	}
	if servers := list(fm["mcpServers"]); len(servers) > 0 {
		b.unmapped("it used %d MCP servers: register each as an integration (quilzo integrations import its server.json), "+
			"pin its tools, and add them to the declaration's tools", len(servers))
	}
	var rest []string
	for _, k := range []string{"skills", "hooks", "memory", "background", "effort", "isolation", "color",
		"initialPrompt", "omitClaudeMd", "autoCompactWindow", "experimental"} {
		if _, ok := fm[k]; ok {
			rest = append(rest, k)
		}
	}
	if len(rest) > 0 {
		b.left("Claude Code's %s, which %s to its runtime", names(rest), belong(len(rest)))
	}
	return &Imported{Agents: []Agent{b.finish()}}, nil
}

func readClaudeAgents(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	if a := obj(o["agents"]); a != nil {
		o = a
	}
	keys := sortedKeys(o)
	out := &Imported{}
	for _, name := range keys {
		d := obj(o[name])
		if d == nil {
			return nil, fmt.Errorf("%s is not an agent definition", name)
		}
		b := newAgent("claude-agents", "agent "+name, name)
		b.purpose(str(d["description"]))
		b.instructions(str(d["prompt"]))
		claudeModel(b, str(d["model"]))
		if _, given := d["tools"]; given {
			claudeTools(b, stringsOf(d["tools"]))
		} else {
			b.unmapped("it inherits every tool of whatever runs it, and an agent here holds only what it declares: name what it uses")
		}
		out.Agents = append(out.Agents, b.finish())
	}
	return out, nil
}

var claudeAliases = map[string]bool{"sonnet": true, "opus": true, "haiku": true, "fable": true}

func claudeModel(b *builder, m string) {
	switch {
	case m == "" || m == "inherit":
		if m == "inherit" {
			b.left("its model is inherit, whichever model starts it: a run here takes the gateway's routes in order")
		}
	case claudeAliases[m]:
		b.m.Model = m
		b.changed("its model %s is an alias: a run tries a gateway route named %s first, so name one so, "+
			"or give the model's full name", m, m)
	default:
		b.model(m)
	}
}

// claudeTools maps Claude Code's tools onto a workspace here.
func claudeTools(b *builder, tools []string) {
	var ws, web, shell, mcp, other []string
	for _, t := range tools {
		switch {
		case t == "Read" || t == "Glob" || t == "Grep" || t == "LS":
			b.addCaps("file_read", "file_list")
			ws = append(ws, t)
		case t == "Write" || t == "Edit" || t == "MultiEdit" || t == "NotebookEdit":
			b.addCaps("file_write", "file_read", "file_list")
			ws = append(ws, t)
		case t == "Bash" || t == "BashOutput" || t == "KillShell" || t == "KillBash":
			shell = append(shell, t)
		case t == "WebFetch" || t == "WebSearch":
			web = append(web, t)
		case strings.HasPrefix(t, "mcp__"):
			mcp = append(mcp, t)
		default:
			other = append(other, t)
		}
	}
	if len(ws) > 0 {
		if b.m.Shell == nil {
			b.m.Shell = &agent.Shell{}
		}
		b.changed("%s, as a workspace of its own (file_list, file_read%s): quilzo agent workspace %s says where",
			names(ws), map[bool]string{true: ", file_write", false: ""}[slices.Contains(b.m.Capabilities, "file_write")], b.m.Name)
	}
	if len(shell) > 0 {
		b.unmapped("%s ran any command: here a workspace runs only programs it names. Declare shell_run with its "+
			"programs (shell.programs) if it needs to", names(shell))
	}
	if len(web) > 0 {
		b.unmapped("%s reached the web: here its browser reads only hosts it names (browser.read)", names(web))
	}
	if len(mcp) > 0 {
		b.unmapped("%s came from MCP servers: register each as an integration, pin its tools, and add them to "+
			"the declaration's tools", names(mcp))
	}
	if len(other) > 0 {
		b.left("Claude Code's %s, which %s to its runtime", names(other), belong(len(other)))
	}
}

// stringsOf reads a list of names written as a list or as one
// comma-separated string.
func stringsOf(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		for _, s := range strings.Split(t, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	case []any:
		for _, e := range t {
			if s := strings.TrimSpace(str(e)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func sortedKeys(o map[string]any) []string {
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// -- Google ADK --------------------------------------------------------------

func readADK(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	name := str(o["name"])
	if name == "" {
		return nil, errors.New("an ADK agent config needs a name")
	}
	b := newAgent("adk", "agent "+name, name)
	class := str(o["agent_class"])
	switch class {
	case "", "LlmAgent", "Agent":
	case "SequentialAgent", "ParallelAgent", "LoopAgent":
		b.m.Kind = agent.KindSupervisor
		b.changed("a %s runs its sub-agents %s; a supervisor here hands each piece of work to the one it chooses",
			class, map[string]string{"SequentialAgent": "one after another", "ParallelAgent": "at once",
				"LoopAgent": "in a loop"}[class])
		if n, ok := num(o["max_iterations"]); ok {
			b.steps(n, "its max_iterations")
		}
	default:
		b.unmapped("its class %s is code of its own: what it does is that code's, and is not carried", class)
	}
	b.purpose(str(o["description"]))
	instr := str(o["instruction"])
	if s := str(o["static_instruction"]); s != "" {
		instr = strings.TrimSpace(s) + "\n\n" + instr
		b.changed("its static_instruction, put before its instruction as ADK sends them")
	}
	if strings.Contains(instr, "{") {
		if vars := regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_:.]*\??\}`).FindAllString(instr, -1); len(vars) > 0 {
			b.decide("its instruction reads %s from the session state ADK keeps: write those values in, or "+
				"say them in each goal", names(uniq(vars)))
		}
	}
	b.instructions(instr)
	b.model(str(o["model"]))
	if o["model_code"] != nil {
		b.unmapped("its model is made in code (model_code): add a gateway route for it")
	}
	if g := obj(o["generate_content_config"]); g != nil {
		for _, k := range []string{"temperature", "top_p", "top_k", "max_output_tokens"} {
			b.generation(k, g[k])
		}
	}
	for _, t := range list(o["tools"]) {
		tn := str(obj(t)["name"])
		if tn == "" {
			tn = str(t)
		}
		switch tn {
		case "google_search", "enterprise_web_search", "url_context", "VertexAiSearchTool":
			b.unmapped("its %s reached the web: here its browser reads only hosts it names (browser.read)", tn)
		case "load_memory", "preload_memory", "load_artifacts", "exit_loop", "get_user_choice":
			b.left("ADK's %s, which belongs to its runtime", tn)
		case "AgentTool":
			if cp := str(obj(firstArg(obj(t), "agent"))["config_path"]); cp != "" {
				b.delegate(strings.TrimSuffix(path.Base(cp), path.Ext(cp)))
				b.m.Kind = agent.KindSupervisor
			} else {
				b.unmapped("it calls another agent as a tool (AgentTool): declare that agent and name it as a delegate")
			}
		case "MCPToolset", "McpToolset":
			b.unmapped("its MCP toolset: register the server as an integration, pin its tools, and add them to the declaration's tools")
		default:
			b.unmapped("its tool %s is Python code: offer what it does through an integration, pin it, and add it to the declaration's tools", tn)
		}
	}
	for _, s := range list(o["sub_agents"]) {
		ref := obj(s)
		switch {
		case str(ref["config_path"]) != "":
			cp := str(ref["config_path"])
			b.delegate(strings.TrimSuffix(path.Base(cp), path.Ext(cp)))
			b.unmapped("import %s as well: it is the sub-agent %s", cp, Slug(strings.TrimSuffix(path.Base(cp), path.Ext(cp))))
		case str(ref["code"]) != "":
			c := str(ref["code"])
			b.delegate(c[strings.LastIndexByte(c, '.')+1:])
			b.unmapped("its sub-agent %s is defined in code: declare it here, under that name", c)
		}
	}
	if len(b.m.Delegates) > 0 {
		b.m.Kind = agent.KindSupervisor
	}
	var rest []string
	for _, k := range []string{"output_key", "output_schema", "input_schema", "include_contents", "planner",
		"disallow_transfer_to_parent", "disallow_transfer_to_peers", "before_agent_callbacks", "after_agent_callbacks",
		"before_model_callbacks", "after_model_callbacks", "before_tool_callbacks", "after_tool_callbacks"} {
		if o[k] != nil {
			rest = append(rest, k)
		}
	}
	if len(rest) > 0 {
		b.left("ADK's %s, which %s to its runtime", names(rest), belong(len(rest)))
	}
	return &Imported{Agents: []Agent{b.finish()}}, nil
}

func firstArg(t map[string]any, name string) any {
	switch args := t["args"].(type) {
	case map[string]any:
		return args[name]
	case []any:
		for _, a := range args {
			if str(obj(a)["name"]) == name {
				return obj(a)["value"]
			}
		}
	}
	return nil
}

func uniq(l []string) []string {
	sort.Strings(l)
	return slices.Compact(l)
}

// -- Microsoft 365 Copilot ---------------------------------------------------

func readM365(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	name := str(o["name"])
	if name == "" || str(o["instructions"]) == "" {
		return nil, errors.New("a declarative agent needs a name and instructions")
	}
	b := newAgent("m365", "declarative agent "+name, name)
	b.purpose(str(o["description"]))
	b.instructions(str(o["instructions"]))
	var m365 []string
	for _, c := range list(o["capabilities"]) {
		cap := obj(c)
		switch n := str(cap["name"]); n {
		case "WebSearch":
			var hosts []string
			for _, s := range list(cap["sites"]) {
				if h, ok := hostOf(str(obj(s)["url"])); ok && !slices.Contains(hosts, h) {
					hosts = append(hosts, h)
				}
			}
			if len(hosts) == 0 {
				b.unmapped("it searched the whole web: here its browser reads only hosts it names (browser.read)")
				continue
			}
			b.m.Browser = &agent.Browser{Read: hosts}
			b.addCaps("browser_open", "browser_read")
			b.changed("its web search, limited to %s: here its browser opens and reads those hosts and no others", names(hosts))
		case "CodeInterpreter":
			b.unmapped("it ran code in Copilot's code interpreter: here code runs in a declared workspace or program; declare one if it needs to")
		case "GraphicArt":
			b.left("it made pictures (GraphicArt): nothing here makes them")
		case "ScenarioModels":
			b.left("its task-specific models (ScenarioModels), which are Microsoft's")
		case "":
		default:
			m365 = append(m365, n)
		}
	}
	if len(m365) > 0 {
		b.unmapped("it read Microsoft 365 data (%s): that is not reachable from here. Reach it through an "+
			"integration (Microsoft Graph's OpenAPI document, or an MCP server), or publish what it needs here", names(m365))
	}
	if cs := list(o["conversation_starters"]); len(cs) > 0 {
		b.left("its %s: an agent here is given a goal, and a chatbot here has a greeting", count(len(cs), "conversation starter", "conversation starters"))
	}
	for _, a := range list(o["actions"]) {
		b.unmapped("its action %s is an API plugin (%s): import the plugin's OpenAPI document with quilzo integrations "+
			"import, pin its operations, and add them to the declaration's tools", str(obj(a)["id"]), str(obj(a)["file"]))
	}
	if w := list(o["worker_agents"]); len(w) > 0 {
		b.unmapped("it hands work to %d other Copilot agents: declare each here and name it as a delegate", len(w))
	}
	if bo := obj(o["behavior_overrides"]); bo != nil {
		if truthy(obj(bo["special_instructions"])["discourage_model_knowledge"]) {
			b.changed("it answered only from its sources (discourage_model_knowledge), which is now said in its instructions")
			b.m.Instructions += "\n\nAnswer only from what you read, not from what you already know."
		}
		if truthy(obj(bo["suggestions"])["disabled"]) {
			b.left("its suggestions setting, which is Copilot's")
		}
	}
	if d := str(obj(o["disclaimer"])["text"]); d != "" {
		b.left("its disclaimer (%q): a chatbot here can show one; an agent's runs are not a conversation", d)
	}
	if str(o["sensitivity_label"]) != "" || o["sensitivity_label"] != nil {
		b.left("its sensitivity label, which is Microsoft Purview's")
	}
	return &Imported{Agents: []Agent{b.finish()}}, nil
}

// -- Open Agent Specification ------------------------------------------------

func readAgentSpec(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	refs := obj(o["$referenced_components"])
	resolve := func(v any) map[string]any {
		m := obj(v)
		if id := str(m["$component_ref"]); id != "" {
			return obj(refs[id])
		}
		return m
	}
	if ct := str(o["component_type"]); ct != "Agent" {
		return nil, fmt.Errorf("its component is a %s; this reads an Agent", ct)
	}
	name := str(o["name"])
	b := newAgent("agentspec", "Agent "+name, name)
	b.purpose(str(o["description"]))
	prompt := str(o["system_prompt"])
	if vars := regexp.MustCompile(`\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}`).FindAllString(prompt, -1); len(vars) > 0 {
		b.decide("its system prompt is filled in from its inputs (%s): write those in, or say them in each goal", names(uniq(vars)))
	}
	b.instructions(prompt)
	llm := resolve(o["llm_config"])
	b.model(str(llm["model_id"]))
	if u := str(llm["url"]); u != "" {
		b.decide("it ran on a model at %s (%s): add a gateway route for it (quilzo gateway route add NAME --url %s --model %s)",
			u, str(llm["component_type"]), u, str(llm["model_id"]))
	}
	if g := obj(llm["default_generation_parameters"]); g != nil {
		for _, k := range []string{"temperature", "top_p", "max_tokens"} {
			b.generation(k, g[k])
		}
	}
	for _, t := range list(o["tools"]) {
		tool := resolve(t)
		tn := str(tool["name"])
		confirm := truthy(tool["requires_confirmation"])
		switch str(tool["component_type"]) {
		case "RemoteTool":
			method := strings.ToUpper(str(tool["http_method"]))
			if h, ok := hostOf(str(tool["url"])); ok {
				b.tool(tn, h, str(tool["description"]), method != "GET" && method != "HEAD", confirm)
				b.unmapped("its tool %s calls %s %s: declare that API as an integration (quilzo integrations import its "+
					"OpenAPI document) and pin %s, so a run can call it", tn, method, str(tool["url"]), tn)
			} else {
				b.unmapped("its tool %s calls %s, which names no host this can declare", tn, str(tool["url"]))
			}
		case "MCPTool":
			b.unmapped("its tool %s comes from an MCP server: register the server as an integration, pin %s, and add it to the declaration's tools", tn, tn)
		case "ClientTool":
			b.unmapped("its tool %s is run by the client that calls it: here a tool is a call to a host; offer it through an integration", tn)
		default:
			b.unmapped("its tool %s runs in the agent's own code (%s): offer it through an integration, pin it, and add it to the declaration's tools",
				tn, str(tool["component_type"]))
		}
	}
	if len(list(o["toolboxes"])) > 0 {
		b.unmapped("its %s: register each as an integration and add the tools it needs", count(len(list(o["toolboxes"])), "toolbox", "toolboxes"))
	}
	if truthy(o["human_in_the_loop"]) {
		b.left("human_in_the_loop: it could ask the person it worked for mid-run; here a run asks a person before what it declares to ask first")
	}
	if len(list(o["inputs"])) > 0 || len(list(o["outputs"])) > 0 {
		b.left("its typed inputs and outputs: a run here is given a goal and answers in words")
	}
	return &Imported{Agents: []Agent{b.finish()}}, nil
}

// -- Letta -------------------------------------------------------------------

func lettaFile(o map[string]any) bool {
	agents := list(o["agents"])
	if len(agents) == 0 {
		return false
	}
	a := obj(agents[0])
	return a["system"] != nil || a["llm_config"] != nil || a["agent_type"] != nil
}

func readLetta(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	byID := func(key string) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, e := range list(o[key]) {
			m := obj(e)
			out[str(m["id"])] = m
		}
		return out
	}
	blocks, tools := byID("blocks"), byID("tools")
	out := &Imported{}
	if n := len(list(o["mcp_servers"])); n > 0 {
		out.Notes = append(out.Notes, Note{Decide, fmt.Sprintf("the file declares %d MCP servers: register each as an integration", n)})
	}
	for i, e := range list(o["agents"]) {
		a := obj(e)
		name := str(a["name"])
		b := newAgent("letta", fmt.Sprintf("agent %d (%s)", i, name), name)
		b.purpose(str(a["description"]))
		instr := str(a["system"])
		var labels []string
		var memory []map[string]any
		for _, id := range list(a["block_ids"]) {
			if blk := blocks[str(id)]; blk != nil {
				memory = append(memory, blk)
			}
		}
		for _, blk := range list(a["memory_blocks"]) {
			memory = append(memory, obj(blk))
		}
		for _, blk := range memory {
			if val := strings.TrimSpace(str(blk["value"])); val != "" {
				instr += "\n\n<" + str(blk["label"]) + ">\n" + val + "\n</" + str(blk["label"]) + ">"
				labels = append(labels, str(blk["label"]))
			}
		}
		b.instructions(instr)
		if len(labels) > 0 {
			b.changed("its memory blocks %s, carried in its instructions as they stood: Letta lets an agent "+
				"edit them as it goes, and here they are fixed", names(labels))
		}
		llm := obj(a["llm_config"])
		model := str(llm["model"])
		if model == "" {
			model = str(a["model"])
		}
		b.model(model)
		b.generation("temperature", llm["temperature"])
		if ep := str(llm["model_endpoint"]); ep != "" && str(llm["model_endpoint_type"]) != "openai" &&
			str(llm["model_endpoint_type"]) != "anthropic" {
			b.decide("it ran on a model at %s (%s): add a gateway route for it", ep, str(llm["model_endpoint_type"]))
		}
		var runtime, custom []string
		for _, id := range list(a["tool_ids"]) {
			t := tools[str(id)]
			if t == nil {
				continue
			}
			switch tt := str(t["tool_type"]); {
			case strings.HasPrefix(tt, "letta_"):
				runtime = append(runtime, str(t["name"]))
			case tt == "external_mcp":
				b.unmapped("its tool %s comes from an MCP server: register the server as an integration, pin it, "+
					"and add it to the declaration's tools", str(t["name"]))
			default:
				custom = append(custom, str(t["name"]))
			}
		}
		if len(runtime) > 0 {
			b.left("Letta's own %s, which %s to its runtime (its memory editing and messaging)", names(runtime), belong(len(runtime)))
		}
		for _, c := range custom {
			b.unmapped("its tool %s is Python code Letta ran: offer what it does through an integration, pin it, "+
				"and add it to the declaration's tools", c)
		}
		if len(list(a["tool_rules"])) > 0 {
			b.left("its %s, which %s Letta's", count(len(list(a["tool_rules"])), "tool rule", "tool rules"),
				map[bool]string{true: "is", false: "are"}[len(list(a["tool_rules"])) == 1])
		}
		if n := len(list(a["messages"])); n > 0 {
			b.left("its %s: a run here starts from its goal, with no conversation behind it", count(n, "message", "messages"))
		}
		if len(list(a["source_ids"])) > 0 || len(list(a["folder_ids"])) > 0 || len(list(a["files_agents"])) > 0 {
			b.read("it read attached files and folders")
		}
		out.Agents = append(out.Agents, b.finish())
	}
	return out, nil
}

// -- Amazon Bedrock Agents ---------------------------------------------------

func bedrockFile(o map[string]any) bool {
	if a := obj(o["agent"]); a != nil && a["agentName"] != nil {
		return true
	}
	if o["agentName"] != nil && (o["instruction"] != nil || o["foundationModel"] != nil) {
		return true
	}
	for _, r := range obj(o["Resources"]) {
		if str(obj(r)["Type"]) == "AWS::Bedrock::Agent" {
			return true
		}
	}
	return false
}

// camel makes a CloudFormation property's name the API's: AgentName,
// agentName.
func camel(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if k != "" && k[0] >= 'A' && k[0] <= 'Z' {
				k = strings.ToLower(k[:1]) + k[1:]
			}
			out[k] = camel(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = camel(e)
		}
		return out
	}
	return v
}

func readBedrock(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	out := &Imported{}
	if res := obj(o["Resources"]); res != nil {
		for _, id := range sortedKeys(res) {
			r := obj(res[id])
			if str(r["Type"]) != "AWS::Bedrock::Agent" {
				continue
			}
			p := obj(camel(r["Properties"]))
			out.Agents = append(out.Agents, bedrockAgent(p, list(p["actionGroups"]), list(p["knowledgeBases"]), "resource "+id))
		}
		return out, nil
	}
	a := obj(o["agent"])
	if a == nil {
		a = o
	}
	var groups []any
	for _, g := range list(o["actionGroups"]) {
		if inner := obj(obj(g)["agentActionGroup"]); inner != nil {
			g = inner
		}
		groups = append(groups, g)
	}
	out.Agents = append(out.Agents, bedrockAgent(a, groups, list(o["knowledgeBases"]), "agent "+str(a["agentId"])))
	return out, nil
}

func bedrockAgent(a map[string]any, groups, kbs []any, src string) Agent {
	b := newAgent("bedrock", src+" "+str(a["agentName"]), str(a["agentName"]))
	b.purpose(str(a["description"]))
	b.instructions(str(a["instruction"]))
	b.model(str(a["foundationModel"]))
	for _, g := range groups {
		bedrockGroup(b, obj(g))
	}
	if len(kbs) > 0 {
		var ids []string
		for _, k := range kbs {
			ids = append(ids, str(obj(k)["knowledgeBaseId"]))
		}
		b.read("it answered from knowledge bases")
		b.unmapped("its knowledge base %s is Bedrock's: publish what it holds here, or reach it through an integration", names(ids))
	}
	if g := obj(a["guardrailConfiguration"]); g != nil {
		b.left("its Bedrock guardrail %s: here Quilzo's own checks screen every run, and an outside classifier "+
			"is one setting for all of them (quilzo config set guardrail.kind)", str(g["guardrailIdentifier"]))
	}
	if c := str(a["agentCollaboration"]); c != "" && c != "DISABLED" {
		b.m.Kind = agent.KindSupervisor
		b.unmapped("it supervises other Bedrock agents (%s): import each and name it as a delegate", c)
	}
	if a["memoryConfiguration"] != nil {
		b.left("its session memory, which is Bedrock's")
	}
	if a["promptOverrideConfiguration"] != nil {
		b.left("its prompt overrides, which replace Bedrock's own prompt templates")
	}
	if str(a["orchestrationType"]) == "CUSTOM_ORCHESTRATION" {
		b.unmapped("its orchestration is a Lambda of your own: what it decides is that code's, and is not carried")
	}
	if n, ok := num(a["idleSessionTTLInSeconds"]); ok {
		b.left("its idle session time (%ds), which is Bedrock's", int(n))
	}
	return b.finish()
}

func bedrockGroup(b *builder, g map[string]any) {
	name := str(g["actionGroupName"])
	if str(g["actionGroupState"]) == "DISABLED" {
		b.left("its action group %s, switched off there", name)
		return
	}
	switch str(g["parentActionGroupSignature"]) {
	case "AMAZON.UserInput":
		b.left("its UserInput action group: here a run asks a person before what it declares to ask first")
		return
	case "AMAZON.CodeInterpreter":
		b.unmapped("it ran code in Bedrock's code interpreter: here code runs in a declared workspace or program; declare one if it needs to")
		return
	}
	if schema := obj(g["apiSchema"]); schema != nil {
		if s3 := obj(schema["s3"]); s3 != nil {
			b.unmapped("its action group %s is described by an OpenAPI document in S3 (%s/%s): fetch it and "+
				"quilzo integrations import it", name, str(s3["s3BucketName"]), str(s3["s3ObjectKey"]))
			return
		}
		openAPIActions(b, name, str(schema["payload"]), "its action group "+name, "a Lambda")
		return
	}
	for _, f := range list(obj(g["functionSchema"])["functions"]) {
		fn := obj(f)
		confirm := ""
		if str(fn["requireConfirmation"]) == "ENABLED" {
			confirm = ", after the user confirmed it"
		}
		b.unmapped("its function %s in %s ran in a Lambda%s: offer it through an integration, pin it, and add "+
			"it to the declaration's tools (asked first)", str(fn["name"]), name, confirm)
	}
}

// openAPIActions declares the operations an inline OpenAPI document
// offers, and keeps the document for quilzo integrations import.
func openAPIActions(b *builder, name, payload, what, via string) {
	v, err := decode([]byte(payload))
	if err != nil {
		b.unmapped("%s carries an OpenAPI document this cannot read (%v): import it with quilzo integrations import", what, err)
		return
	}
	body, _ := json.Marshal(v)
	slug := Slug(name)
	imp, err := apiimport.OpenAPI(body, apiimport.Options{Name: slug})
	if err != nil {
		b.unmapped("%s carries an OpenAPI document quilzo integrations import cannot read yet (%v)", what, err)
		return
	}
	host := imp.Integration.Endpoint
	for _, op := range imp.Available {
		b.tool(op.Name, host, op.Summary, op.Writes, false)
	}
	file := slug + ".openapi.json"
	if b.a.Files == nil {
		b.a.Files = map[string][]byte{}
	}
	pretty, _ := json.MarshalIndent(v, "", "  ")
	b.a.Files[file] = append(pretty, '\n')
	b.changed("%s, %d operations on %s, as tools (those that write are asked about first): it called them "+
		"through %s, and here Quilzo calls the API itself", what, len(imp.Available), host, via)
	b.unmapped("register the API: quilzo integrations import %s, give it its credential (--secret), and pin its "+
		"operations, so a run can call them", file)
}

// -- CrewAI ------------------------------------------------------------------

var reCrewVar = regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_]*\}`)

func readCrewAI(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	ids := sortedKeys(o)
	out := &Imported{}
	for _, id := range ids {
		a := obj(o[id])
		b := newAgent("crewai", "agent "+id, id)
		role, goal, story := strings.TrimSpace(str(a["role"])), strings.TrimSpace(str(a["goal"])), strings.TrimSpace(str(a["backstory"]))
		// CrewAI's own prompt for an agent: "You are {role}. {backstory}
		// Your personal goal is: {goal}".
		b.instructions(fmt.Sprintf("You are %s. %s\nYour personal goal is: %s", role, story, goal))
		b.changed("its role, goal and backstory, put together as CrewAI puts them to its model")
		b.m.Purpose = oneLine(goal)
		if len(b.m.Purpose) > 300 {
			b.m.Purpose = b.m.Purpose[:297] + "..."
		}
		if vars := reCrewVar.FindAllString(role+" "+goal+" "+story, -1); len(vars) > 0 {
			b.decide("its text has %s, which CrewAI fills in when the crew starts: write the values in, or "+
				"say them in each goal", names(uniq(vars)))
		}
		b.model(str(a["llm"]))
		if a["function_calling_llm"] != nil {
			b.left("its function_calling_llm: a run here uses one model for every decision")
		}
		for _, t := range stringsOf(a["tools"]) {
			b.unmapped("its tool %s is Python code: offer what it does through an integration, pin it, and add "+
				"it to the declaration's tools", t)
		}
		if truthy(a["allow_delegation"]) {
			for _, other := range ids {
				if other != id {
					b.delegate(other)
				}
			}
			if len(b.m.Delegates) > 0 {
				b.m.Kind = agent.KindSupervisor
				b.changed("allow_delegation: it may hand work to the crew's other agents, as a supervisor here")
			}
		}
		if n, ok := num(a["max_iter"]); ok {
			b.steps(n, "its max_iter")
		}
		if n, ok := num(a["max_execution_time"]); ok {
			b.duration(n, "its max_execution_time")
		}
		if truthy(a["allow_code_execution"]) {
			b.unmapped("it ran code (allow_code_execution): here code runs in a declared workspace or program; declare one if it needs to")
		}
		if a["knowledge_sources"] != nil {
			b.read("it read knowledge sources")
		}
		var rest []string
		for _, k := range []string{"max_rpm", "memory", "reasoning", "planning", "system_template", "prompt_template",
			"response_template", "respect_context_window", "multimodal", "inject_date", "max_retry_limit", "guardrail"} {
			if a[k] != nil {
				rest = append(rest, k)
			}
		}
		if len(rest) > 0 {
			b.left("CrewAI's %s, which %s to its runtime", names(rest), belong(len(rest)))
		}
		out.Agents = append(out.Agents, b.finish())
	}
	return out, nil
}

// -- AutoGen -----------------------------------------------------------------

func readAutoGen(data []byte) (*Imported, error) {
	v, err := decode(data)
	if err != nil {
		return nil, err
	}
	o := obj(v)
	out := &Imported{}
	var walk func(c map[string]any, where string)
	walk = func(c map[string]any, where string) {
		provider := str(c["provider"])
		cfg := obj(c["config"])
		switch {
		case str(c["component_type"]) == "team" || cfg["participants"] != nil:
			ps := list(cfg["participants"])
			out.Notes = append(out.Notes, Note{Changed, fmt.Sprintf("the team %s (%s) of %d: each is imported; "+
				"the order they take turns in was the team's, and a supervisor here would choose who acts",
				str(c["label"]), provider[strings.LastIndexByte(provider, '.')+1:], len(ps))})
			for i, p := range ps {
				walk(obj(p), fmt.Sprintf("%s participant %d", where, i))
			}
		case strings.HasSuffix(provider, "UserProxyAgent"):
			out.Notes = append(out.Notes, Note{Left, fmt.Sprintf("%s is a person (UserProxyAgent), not an agent", str(cfg["name"]))})
		case strings.HasSuffix(provider, "AssistantAgent") || cfg["system_message"] != nil:
			out.Agents = append(out.Agents, autogenAgent(cfg, where))
		default:
			name := str(cfg["name"])
			out.Notes = append(out.Notes, Note{Decide, fmt.Sprintf("%s is a %s, which is code of its own: declare what it does here", name, provider)})
		}
	}
	walk(o, "component")
	return out, nil
}

func autogenAgent(cfg map[string]any, where string) Agent {
	name := str(cfg["name"])
	b := newAgent("autogen", where+" "+name, name)
	b.purpose(str(cfg["description"]))
	b.instructions(str(cfg["system_message"]))
	mc := obj(obj(cfg["model_client"])["config"])
	b.model(str(mc["model"]))
	b.generation("temperature", mc["temperature"])
	for _, t := range list(cfg["tools"]) {
		tc := obj(obj(t)["config"])
		b.unmapped("its tool %s is Python code: offer what it does through an integration, pin it, and add it to "+
			"the declaration's tools", str(tc["name"]))
	}
	for range list(cfg["workbench"]) {
		b.unmapped("its workbench (an MCP server): register the server as an integration, pin its tools, and add them to the declaration's tools")
	}
	for _, h := range list(cfg["handoffs"]) {
		target := str(h)
		if target == "" {
			target = str(obj(h)["target"])
		}
		b.delegate(target)
	}
	if len(b.m.Delegates) > 0 {
		b.m.Kind = agent.KindSupervisor
		b.changed("its handoffs, as the agents it may hand work to")
	}
	if n, ok := num(cfg["max_tool_iterations"]); ok && n > 1 {
		b.toolCalls(n, "its max_tool_iterations")
	}
	var rest []string
	for _, k := range []string{"memory", "model_context", "reflect_on_tool_use", "tool_call_summary_format",
		"structured_message_factory", "model_client_stream", "metadata"} {
		if cfg[k] != nil {
			rest = append(rest, k)
		}
	}
	if len(rest) > 0 {
		b.left("AutoGen's %s, which %s to its runtime", names(rest), belong(len(rest)))
	}
	return b.finish()
}
