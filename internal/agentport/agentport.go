// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package agentport brings agents in from other platforms and takes them
// out again.
//
// An agent somebody built elsewhere is mostly words: instructions, a model,
// tools named for that platform's runtime. Here an agent is a declaration of
// what it may do (internal/agent): operations, hosts, autonomy and a budget
// that a gate enforces. So an import is a translation, and the translation
// is said in full: every part of the original is kept as written, changed
// into this program's terms, left out because nothing here holds it, or
// handed to a person to decide, with what to do. Nothing is guessed silently
// and nothing is granted that the original did not have: an agent that only
// talked is given the read-only operations of a retrieval agent and told so,
// tools that write are asked about first, and autonomy starts at proposing.
//
// The formats are each platform's own, read from their published schemas
// and source: OpenAI Assistants, Claude Code subagents and the Claude Agent
// SDK, Google's ADK agent config, Microsoft 365 Copilot declarative agents,
// Oracle's Open Agent Specification, Letta's Agent File, Amazon Bedrock
// Agents, CrewAI and AutoGen, and this program's own declaration, which
// round-trips whole. The format is recognised from the file.
package agentport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/yamlite"
)

// Format is one platform's way of writing an agent down.
type Format struct {
	Name   string `json:"name"`
	Title  string `json:"title"`
	Import bool   `json:"import"`
	Export bool   `json:"export"`
	// What is where the definition comes from, for the person looking.
	What string `json:"what"`
}

// Formats are the formats, in the order people look for them.
var Formats = []Format{
	{"quilzo", "Quilzo declaration", true, true, "quilzo agent show NAME --json, or a declaration written by hand: carried whole"},
	{"openai-assistant", "OpenAI Assistants", true, false, "an assistant object, or a list of them, as GET /v1/assistants returns it"},
	{"claude-subagent", "Claude Code subagent", true, true, "a .claude/agents/NAME.md file: front matter and the system prompt"},
	{"claude-agents", "Claude Agent SDK", true, true, "the agents a query or claude --agents is given, as JSON: name to description, prompt, tools, model"},
	{"adk", "Google ADK agent config", true, true, "a root_agent.yaml: agent_class, name, model, instruction, tools, sub_agents"},
	{"m365", "Microsoft 365 Copilot declarative agent", true, true, "a declarativeAgent.json manifest (schema v1.x)"},
	{"agentspec", "Open Agent Specification", true, true, "an Agent component in JSON or YAML (component_type: Agent)"},
	{"letta", "Letta Agent File", true, false, "an .af file: agents, their memory blocks, tools and model"},
	{"bedrock", "Amazon Bedrock Agents", true, false, "aws bedrock-agent get-agent output (with action groups), or a CloudFormation template"},
	{"crewai", "CrewAI agents", true, true, "an agents.yaml: role, goal and backstory for each agent"},
	{"autogen", "AutoGen AgentChat", true, false, "an AssistantAgent component, or a team of them, as AutoGen Studio exports it"},
}

// FormatNamed is a format by its name.
func FormatNamed(name string) (Format, bool) {
	for _, f := range Formats {
		if f.Name == name {
			return f, true
		}
	}
	return Format{}, false
}

// The kinds of note an import makes about each part of the original.
const (
	// Kept is carried over as it was written.
	Kept = "kept"
	// Changed is carried over in this program's terms.
	Changed = "changed"
	// Left is left out: nothing here holds it.
	Left = "left"
	// Decide is for a person to settle before the agent works as it did.
	Decide = "decide"
)

// Note is what became of one part of the original.
type Note struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// Agent is one agent read from another platform: the declaration it
// becomes here, and what became of each part of it.
type Agent struct {
	Manifest agent.Manifest `json:"manifest"`
	// Source is where in the file it was, and what the platform called it.
	Source string `json:"source"`
	Notes  []Note `json:"notes"`
	// Files are documents it came with that are brought in on their own:
	// the OpenAPI description of its actions, for quilzo integrations
	// import. Named for where they would be written.
	Files map[string][]byte `json:"-"`
}

// Imported is what a file held.
type Imported struct {
	Format string  `json:"format"`
	Agents []Agent `json:"agents"`
	// Notes are about the file rather than one agent in it.
	Notes []Note `json:"notes,omitempty"`
}

// MaxFile is the largest file read.
const MaxFile = 16 << 20

// ErrUnknown is a file in no format this reads.
var ErrUnknown = errors.New("this is not an agent in a format this reads")

// Read reads the agents in data. from names the format, or is empty for it
// to be recognised; name, when set, names a file's only agent.
func Read(data []byte, from, name string) (*Imported, error) {
	if len(data) > MaxFile {
		return nil, fmt.Errorf("the file is over %d MiB", MaxFile>>20)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if from == "" {
		var err error
		if from, err = Detect(data); err != nil {
			return nil, err
		}
	}
	read, ok := readers[from]
	if !ok {
		return nil, fmt.Errorf("%q is not a format this reads; quilzo agent formats lists them", from)
	}
	out, err := read(data)
	if err != nil {
		return nil, fmt.Errorf("reading it as %s: %w", title(from), err)
	}
	out.Format = from
	if len(out.Agents) == 0 {
		return nil, fmt.Errorf("the %s file holds no agent", title(from))
	}
	if name != "" {
		if len(out.Agents) > 1 {
			return nil, fmt.Errorf("the file holds %d agents; --name names one", len(out.Agents))
		}
		out.Agents[0].note(Changed, "named %s, as asked, rather than %s", name, out.Agents[0].Manifest.Name)
		out.Agents[0].Manifest.Name = Slug(name)
	}
	linkDelegates(out)
	return out, nil
}

func title(format string) string {
	if f, ok := FormatNamed(format); ok {
		return f.Title
	}
	return format
}

var readers = map[string]func([]byte) (*Imported, error){
	"quilzo":           readQuilzo,
	"openai-assistant": readOpenAI,
	"claude-subagent":  readClaudeSubagent,
	"claude-agents":    readClaudeAgents,
	"adk":              readADK,
	"m365":             readM365,
	"agentspec":        readAgentSpec,
	"letta":            readLetta,
	"bedrock":          readBedrock,
	"crewai":           readCrewAI,
	"autogen":          readAutoGen,
}

// Detect recognises a file's format from what it holds.
func Detect(data []byte) (string, error) {
	trim := bytes.TrimSpace(data)
	if bytes.HasPrefix(trim, []byte("---")) && !looksLikeYAMLMapping(trim) {
		return "claude-subagent", nil
	}
	v, err := decode(data)
	if err != nil {
		if bytes.HasPrefix(trim, []byte("---")) {
			return "claude-subagent", nil
		}
		return "", fmt.Errorf("%w: it reads as neither JSON nor YAML (%v)", ErrUnknown, err)
	}
	o, isMap := v.(map[string]any)
	if !isMap {
		return "", fmt.Errorf("%w: it is not an object", ErrUnknown)
	}
	switch {
	case str(o["component_type"]) == "Agent" || (o["$referenced_components"] != nil && str(o["component_type"]) != ""):
		return "agentspec", nil
	case strings.HasPrefix(str(o["provider"]), "autogen") || str(o["component_type"]) == "agent" || str(o["component_type"]) == "team":
		return "autogen", nil
	case lettaFile(o):
		return "letta", nil
	case str(o["object"]) == "assistant" || (str(o["object"]) == "list" && listOf(o["data"], "object", "assistant")):
		return "openai-assistant", nil
	case strings.HasPrefix(str(o["version"]), "v1.") && o["instructions"] != nil && o["name"] != nil:
		return "m365", nil
	case bedrockFile(o):
		return "bedrock", nil
	case o["agent_class"] != nil || (o["instruction"] != nil && o["name"] != nil):
		return "adk", nil
	case o["kind"] != nil && o["budget"] != nil && o["purpose"] != nil:
		return "quilzo", nil
	case o["instructions"] != nil && o["model"] != nil && o["tools"] != nil:
		return "openai-assistant", nil
	case len(o) > 0 && allValues(o, func(e map[string]any) bool { return e["role"] != nil && e["goal"] != nil }):
		return "crewai", nil
	case len(o) > 0 && allValues(o, func(e map[string]any) bool { return e["prompt"] != nil && e["description"] != nil }):
		return "claude-agents", nil
	case o["skills"] != nil && o["url"] != nil && o["name"] != nil:
		return "", fmt.Errorf("%w: this is an A2A agent card, for an agent that runs elsewhere; "+
			"register it with quilzo fleet add CARD_URL", ErrUnknown)
	}
	return "", fmt.Errorf("%w; quilzo agent formats lists the formats, and --from names one", ErrUnknown)
}

// looksLikeYAMLMapping says a document that starts with a marker is a YAML
// document, not Markdown with front matter: nothing follows a second marker.
func looksLikeYAMLMapping(b []byte) bool {
	rest := bytes.TrimPrefix(b, []byte("---"))
	i := bytes.Index(rest, []byte("\n---"))
	if i < 0 {
		return true
	}
	return len(bytes.TrimSpace(rest[i+4:])) == 0
}

func allValues(o map[string]any, ok func(map[string]any) bool) bool {
	for _, v := range o {
		e, isMap := v.(map[string]any)
		if !isMap || !ok(e) {
			return false
		}
	}
	return true
}

func listOf(v any, key, want string) bool {
	l, ok := v.([]any)
	if !ok || len(l) == 0 {
		return false
	}
	for _, e := range l {
		if m, ok := e.(map[string]any); !ok || str(m[key]) != want {
			return false
		}
	}
	return true
}

// decode reads JSON or YAML into what encoding/json would make of it. A
// JSON string that is itself a JSON document, as some agent files are
// written, is read once more.
func decode(data []byte) (any, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) > 0 && (trim[0] == '{' || trim[0] == '[' || trim[0] == '"') {
		var v any
		if err := json.Unmarshal(trim, &v); err != nil {
			return nil, err
		}
		if s, ok := v.(string); ok {
			if err := json.Unmarshal([]byte(s), &v); err != nil {
				return nil, fmt.Errorf("a JSON string that is not a JSON document: %w", err)
			}
		}
		return v, nil
	}
	return yamlite.Parse(data)
}

// -- building an agent -------------------------------------------------------

// builder makes one agent, noting as it goes.
type builder struct {
	a *Agent
	m *agent.Manifest
	// format is the platform's name, for the notes.
	format    string
	knowledge bool
	// unmapped says it used something that does not carry over as an
	// operation here: a tool, code, the web, a knowledge base.
	unmapped_ bool
}

func newAgent(format, source, name string) *builder {
	a := &Agent{Source: source}
	b := &builder{a: a, m: &a.Manifest, format: title(format)}
	b.m.Name = Slug(name)
	if b.m.Name != name && name != "" {
		b.changed("named %s, which is %q as a name here", b.m.Name, name)
	} else if name != "" {
		b.kept("its name, %s", name)
	}
	return b
}

func (a *Agent) note(kind, format string, args ...any) {
	a.Notes = append(a.Notes, Note{Kind: kind, Text: fmt.Sprintf(format, args...)})
}

func (b *builder) kept(f string, a ...any)    { b.a.note(Kept, f, a...) }
func (b *builder) changed(f string, a ...any) { b.a.note(Changed, f, a...) }
func (b *builder) left(f string, a ...any)    { b.a.note(Left, f, a...) }
func (b *builder) decide(f string, a ...any)  { b.a.note(Decide, f, a...) }

// unmapped is a decision about something it used that does not carry over.
func (b *builder) unmapped(f string, a ...any) {
	b.unmapped_ = true
	b.a.note(Decide, f, a...)
}

// instructions carries the system prompt.
func (b *builder) instructions(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	if len(s) > agent.MaxInstructions {
		b.decide("its instructions are %d bytes, and a run here carries at most %d: shorten them before "+
			"declaring it; they are kept whole in the declaration until then", len(s), agent.MaxInstructions)
	}
	b.m.Instructions = s
	b.kept("its instructions (%s), which go to the model with every decision", size(len(s)))
}

func size(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d bytes", n)
	}
	return fmt.Sprintf("%.1f KiB", float64(n)/1024)
}

// purpose is what the agent is for, from its description.
func (b *builder) purpose(s string) {
	s = oneLine(s)
	if s == "" {
		return
	}
	if len(s) > 300 {
		s = s[:297] + "..."
		b.changed("its description, cut to 300 characters as its purpose")
	} else {
		b.kept("its description, as its purpose")
	}
	b.m.Purpose = s
}

// providerPrefix is the provider a router names before a model, as LiteLLM
// and CrewAI write them ("openai/gpt-4o").
var providerPrefix = regexp.MustCompile(`^(openai|anthropic|gemini|google|vertex_ai|azure|bedrock|mistral|groq|ollama|together_ai|deepseek|xai|openrouter)/`)

// model records the model it was written for.
func (b *builder) model(m string) {
	m = strings.TrimSpace(m)
	if m == "" {
		return
	}
	if p := providerPrefix.FindString(m); p != "" {
		b.m.Model = strings.TrimPrefix(m, p)
		b.changed("its model %s, as %s: a run tries the gateway route serving that model first", m, b.m.Model)
		return
	}
	b.m.Model = m
	b.kept("its model, %s: a run tries the gateway route serving it first, and the others after", m)
}

// generation notes a sampling setting, which belongs to a route here.
func (b *builder) generation(name string, v any) {
	if v == nil {
		return
	}
	b.left("its %s (%s): set on the model's route here (quilzo gateway route add, --%s)",
		name, fmt.Sprint(v), strings.ReplaceAll(name, "_", "-"))
}

// read gives it the read-only operations of a retrieval agent, for what it
// did with a knowledge base or files of its own.
func (b *builder) read(why string) {
	b.knowledge = true
	b.addCaps("read_page", "list_pages", "search_pages", "similar_pages")
	b.changed("%s: here it reads and searches the site's published pages (read_page, list_pages, "+
		"search_pages, similar_pages)", why)
}

func (b *builder) addCaps(caps ...string) {
	for _, c := range caps {
		if !slices.Contains(b.m.Capabilities, c) {
			b.m.Capabilities = append(b.m.Capabilities, c)
		}
	}
}

// tool declares a tool on a host.
func (b *builder) tool(name, host, purpose string, writes, ask bool) {
	purpose = oneLine(purpose)
	if purpose == "" {
		purpose = "called by the agent as " + name
	}
	if len(purpose) > 300 {
		purpose = purpose[:297] + "..."
	}
	for _, t := range b.m.Tools {
		if t.Name == name {
			return
		}
	}
	b.m.Tools = append(b.m.Tools, agent.Tool{Name: name, Host: host, Purpose: purpose, Writes: writes})
	if ask || writes {
		b.m.AskFirst = append(b.m.AskFirst, name)
	}
}

// delegate names an agent it hands work to.
func (b *builder) delegate(name string) {
	n := Slug(name)
	if n == "" || n == b.m.Name || slices.Contains(b.m.Delegates, n) {
		return
	}
	b.m.Delegates = append(b.m.Delegates, n)
}

// budget sets one part of the budget from the original.
func (b *builder) steps(n float64, from string) {
	if n >= 1 && n <= 10000 {
		b.m.Budget.Steps = int(n)
		b.changed("%s %d, as its budget of steps", from, int(n))
	}
}

func (b *builder) duration(seconds float64, from string) {
	if seconds >= 1 && seconds <= 86400 {
		b.m.Budget.Duration = agent.Duration(int64(seconds * 1e9))
		b.changed("%s %ds, as how long a run may last", from, int(seconds))
	}
}

func (b *builder) toolCalls(n float64, from string) {
	if n >= 1 && n <= 10000 {
		b.m.Budget.Tools = int(n)
		b.changed("%s %d, as its budget of tool calls", from, int(n))
	}
}

// finish fills what the original did not say from the agent's kind, the
// way this program's own templates do, and says so.
func (b *builder) finish() Agent {
	m := b.m
	if m.Name == "" {
		m.Name = "imported-agent"
		b.changed("named imported-agent: the original names none")
	}
	if m.Kind == "" {
		switch {
		case len(m.Delegates) > 0:
			m.Kind = agent.KindSupervisor
		case len(m.Tools) > 0 || m.Shell != nil || m.Browser != nil:
			m.Kind = agent.KindTask
		default:
			m.Kind = agent.KindRetrieval
		}
		b.changed("declared as a %s agent, from what it holds", m.Kind)
	}
	t, _ := agent.For(m.Kind)
	if m.Purpose == "" {
		if s := firstSentence(m.Instructions); s != "" {
			m.Purpose = s
			b.changed("its purpose taken from the first sentence of its instructions; the original states none")
		} else {
			m.Purpose = "Imported from " + b.format + "."
			b.decide("say what it is for: the original states no purpose, and a declaration is reviewed against one")
		}
	}
	if len(m.Capabilities) == 0 && len(m.Tools) == 0 && len(m.Delegates) == 0 && m.Shell == nil && m.Browser == nil {
		if b.unmapped_ {
			b.read("nothing it used carries over as an operation until the decisions below are made")
		} else {
			b.read("it only converses")
			b.decide("a run here acts through operations: to answer from its instructions alone, with nothing of this " +
				"site's, declare it as a chatbot instead (the Chatbots screen, or quilzo assistant)")
		}
	}
	if m.Kind == agent.KindSupervisor {
		for _, c := range t.Manifest.Capabilities {
			if !agent.IsWrite(c) {
				b.addCaps(c)
			}
		}
	}
	sort.Strings(m.Capabilities)
	if m.Autonomy == "" {
		m.Autonomy = agent.AutonomyPropose
		for _, c := range m.Capabilities {
			if agent.IsWrite(c) {
				m.Autonomy = agent.AutonomyDraft
			}
		}
		b.changed("autonomy %s: it %s, and a person decides whether it may go further", m.Autonomy,
			map[agent.Autonomy]string{agent.AutonomyPropose: "proposes and writes nothing here",
				agent.AutonomyDraft: "writes drafts"}[m.Autonomy])
	}
	if m.Retrieval.Ref == "" {
		m.Retrieval.Ref = "live"
	}
	var defaulted []string
	if m.Budget.Steps <= 0 {
		m.Budget.Steps = t.Manifest.Budget.Steps
		defaulted = append(defaulted, fmt.Sprintf("%d steps", m.Budget.Steps))
	}
	if m.Budget.Tools <= 0 {
		m.Budget.Tools = t.Manifest.Budget.Tools
		defaulted = append(defaulted, fmt.Sprintf("%d tool calls", m.Budget.Tools))
	}
	if m.Budget.Duration <= 0 {
		m.Budget.Duration = t.Manifest.Budget.Duration
		defaulted = append(defaulted, "a run of "+fmtDuration(m.Budget.Duration))
	}
	if len(defaulted) > 0 {
		b.changed("a budget of %s, a %s agent's, where the original sets none", strings.Join(defaulted, ", "), m.Kind)
	}
	if len(m.AskFirst) > 0 {
		sort.Strings(m.AskFirst)
		m.AskFirst = slices.Compact(m.AskFirst)
		b.changed("asks a person before %s, which %s", strings.Join(m.AskFirst, ", "),
			map[bool]string{true: "write or were confirmed in the original", false: "writes or was confirmed in the original"}[len(m.AskFirst) > 1])
	}
	return *b.a
}

func fmtDuration(d agent.Duration) string {
	s := int64(d) / 1e9
	switch {
	case s%3600 == 0 && s >= 3600:
		return fmt.Sprintf("%dh", s/3600)
	case s%60 == 0 && s >= 60:
		return fmt.Sprintf("%dm", s/60)
	}
	return fmt.Sprintf("%ds", s)
}

// linkDelegates says, for each delegate, whether the file declared it.
func linkDelegates(out *Imported) {
	names := map[string]bool{}
	for _, a := range out.Agents {
		names[a.Manifest.Name] = true
	}
	for i := range out.Agents {
		for _, d := range out.Agents[i].Manifest.Delegates {
			if names[d] {
				out.Agents[i].note(Kept, "hands work to %s, which this file declares too", d)
			} else {
				out.Agents[i].note(Decide, "hands work to %s, which this file does not declare: declare it first", d)
			}
		}
	}
}

// Order is the order a file's agents are declared in: each after the
// agents of the same file it hands work to, since a declaration naming a
// delegate that is not declared yet is refused. Agents that hand work to
// each other in a circle keep the file's order, and the first of the
// circle is refused, as it would be declared by hand.
func Order(ms []agent.Manifest) []int {
	in := map[string]int{}
	for i, m := range ms {
		in[m.Name] = i
	}
	done := make([]bool, len(ms))
	var order []int
	for len(order) < len(ms) {
		progressed := false
		for i, m := range ms {
			if done[i] {
				continue
			}
			ready := true
			for _, d := range m.Delegates {
				if j, ok := in[d]; ok && j != i && !done[j] {
					ready = false
				}
			}
			if ready {
				done[i], progressed = true, true
				order = append(order, i)
			}
		}
		if !progressed {
			for i := range ms {
				if !done[i] {
					done[i] = true
					order = append(order, i)
				}
			}
		}
	}
	return order
}

// -- helpers -----------------------------------------------------------------

var reSlug = regexp.MustCompile(`[^a-z0-9]+`)

// Slug is a name as an agent's name here: lower-case letters, digits and
// hyphens, at most 41 characters, starting with a letter or digit.
func Slug(s string) string {
	s = strings.Trim(reSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-"), "-")
	if len(s) > 41 {
		s = strings.TrimRight(s[:41], "-")
	}
	return s
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || strings.EqualFold(t, "enabled")
	}
	return false
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// firstSentence is the first sentence of s, up to 300 characters.
func firstSentence(s string) string {
	s = oneLine(s)
	for i := 0; i < len(s); i++ {
		if (s[i] == '.' || s[i] == '!' || s[i] == '?') && (i+1 == len(s) || s[i+1] == ' ') {
			s = s[:i+1]
			break
		}
	}
	if len(s) > 300 {
		s = s[:297] + "..."
	}
	return s
}

// hostOf is the host a URL names, when it is an https URL with a plain
// host this program can declare.
func hostOf(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || strings.ContainsAny(u.Hostname(), "{}*") {
		return "", false
	}
	return u.Hostname(), true
}

// names lists strings for a note.
func names(l []string) string {
	if len(l) == 0 {
		return ""
	}
	if len(l) == 1 {
		return l[0]
	}
	return strings.Join(l[:len(l)-1], ", ") + " and " + l[len(l)-1]
}

// count is n of something, in words that agree with it.
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// belong agrees with how many things belong.
func belong(n int) string {
	if n == 1 {
		return "belongs"
	}
	return "belong"
}
