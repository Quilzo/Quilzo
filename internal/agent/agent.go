// Package agent declares what an AI agent may do, before it does anything.
//
// # Why a declaration rather than a framework
//
// The agent ecosystem of 2026 converged on a small set of shapes — retrieval
// bots, task runners, goal-seeking autonomous agents, copilots, supervisor
// hierarchies — and every framework implements them as code you write and then
// hope you configured correctly. The credential the agent runs with is usually
// the operator's, so a prompt injection in a page the agent reads is a route to
// whatever the operator can do.
//
// This package does not orchestrate anything. It is a manifest: a declaration,
// validated and stored under its own hash, of the capabilities an agent holds,
// the content it may retrieve, what it may do without a person, what it
// remembers, and which hosts it may reach. The runner — whichever one somebody
// brings — is handed a narrowed credential built from the manifest and cannot
// exceed it, for the same reason a token cannot exceed the policy.
//
// # The security argument, and where it comes from
//
// Google DeepMind's CaMeL (arXiv:2503.18813) defeats prompt injection by
// design rather than by filtering: a privileged model plans from the trusted
// request only, a quarantined model handles untrusted data with no tool
// access, and an interpreter checks a policy before every tool call. It solved
// 77% of AgentDojo tasks with provable security against 84% undefended, and
// that gap is the honest price of the guarantee.
//
// The reason filtering is not the alternative: the defence literature keeps
// finding the filters. A 2026 systematisation catalogues 42 distinct attack
// techniques across input manipulation, tool poisoning, protocol exploitation
// and cross-origin context poisoning. A blocklist is a list of the attacks
// somebody had already seen.
//
// So the parts of CaMeL that are a *data model* live here — the capability set,
// the trust boundary between the operator's instruction and content read out of
// the store, the policy checked before a tool call. What this package refuses
// to do is pretend the model itself is trustworthy: an agent's capabilities are
// what it may do when it has been successfully talked into anything.
//
// # Three tiers of memory, because that is what the field settled on
//
// Episodic (what happened), semantic (what was learned from it), procedural
// (skills worth repeating) is the taxonomy the ecosystem converged on across
// 2025-26, mirroring cognitive science and implemented in Letta/MemGPT's
// core/archival/recall tiers among others. It is declared per agent rather than
// assumed, because memory is the part with the privacy consequences: an agent
// that remembers everything it ever read has made a copy of the store with none
// of the store's access control on it.
package agent

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind is an agent archetype.
//
// A closed set, deliberately. An open one would be a string somebody types, and
// the archetype decides the defaults for capability, autonomy and memory — the
// three fields where a wrong default is a security problem rather than a bug.
type Kind string

const (
	// KindRetrieval answers questions from published content. The RAG bot.
	KindRetrieval Kind = "retrieval"
	// KindTask performs one bounded operation on request.
	KindTask Kind = "task"
	// KindAutonomous pursues a goal across many steps without being asked
	// each time.
	KindAutonomous Kind = "autonomous"
	// KindCopilot works alongside a person, in their session, on what they are
	// looking at.
	KindCopilot Kind = "copilot"
	// KindSupervisor decomposes work and delegates it to other agents.
	KindSupervisor Kind = "supervisor"
	// KindArchivist keeps long-horizon memory across all three tiers.
	KindArchivist Kind = "archivist"
	// KindLearner improves by keeping what worked as reusable procedure.
	KindLearner Kind = "learner"
	// KindOperator reaches outside this system to do errands on somebody's
	// behalf, in the messaging apps they already use.
	KindOperator Kind = "operator"
)

// Kinds in the order they are presented, simplest first.
var Kinds = []Kind{
	KindRetrieval, KindTask, KindCopilot, KindAutonomous,
	KindSupervisor, KindArchivist, KindLearner, KindOperator,
}

func (k Kind) Valid() bool {
	for _, v := range Kinds {
		if v == k {
			return true
		}
	}
	return false
}

// Autonomy is how far an agent gets without a person.
//
// A ladder, like the role ladder, and for the same reason: a total order is
// something somebody can hold in their head, and there is no pair whose
// relationship has to be looked up.
type Autonomy string

const (
	// AutonomyPropose writes nothing. It returns a suggestion for a person.
	AutonomyPropose Autonomy = "propose"
	// AutonomyDraft writes to the draft ref. Nothing it does is public.
	AutonomyDraft Autonomy = "draft"
	// AutonomyPublish moves the live pointer. The one action with an outside
	// observer.
	AutonomyPublish Autonomy = "publish"
)

var autonomyRank = map[Autonomy]int{
	AutonomyPropose: 0, AutonomyDraft: 1, AutonomyPublish: 2,
}

func (a Autonomy) Valid() bool { _, ok := autonomyRank[a]; return ok }

// AtMost reports whether this autonomy is within another.
func (a Autonomy) AtMost(other Autonomy) bool {
	return autonomyRank[a] <= autonomyRank[other]
}

// Memory is which tiers an agent keeps.
//
// Episodic, semantic and procedural, the taxonomy the field converged on. Each
// one off by default: an agent that remembers nothing is the version with no
// privacy surface, and every tier turned on is a decision somebody made.
type Memory struct {
	// Episodic keeps what happened — the trajectory, turn by turn.
	Episodic bool `json:"episodic,omitempty"`
	// Semantic keeps what was concluded from it, which is the tier that
	// silently accumulates personal data: "the user prefers X" is a profile
	// nobody agreed to have built.
	Semantic bool `json:"semantic,omitempty"`
	// Procedural keeps skills — reusable named procedures distilled from what
	// worked. This is what "self-improving" means in the literature, and it is
	// the tier that changes the agent's behaviour over time.
	Procedural bool `json:"procedural,omitempty"`
	// Retain bounds how long any of it is kept. Zero is refused when any tier
	// is on: memory with no expiry is a personal-data store with no retention
	// policy, which is the thing the forms subsystem already refuses to be.
	Retain Duration `json:"retain,omitempty"`
}

// Any reports whether this agent remembers anything at all.
func (m Memory) Any() bool { return m.Episodic || m.Semantic || m.Procedural }

// Duration is a duration that survives JSON as "720h" rather than as a count of
// nanoseconds nobody can read in a stored manifest.
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "0" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("%q is not a duration like 720h or 30m: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MaxRetain caps how long an agent may remember.
//
// Ninety days, the same ceiling the posture suppressions use. A memory that
// outlives the reason it was kept is the one that turns up in a subject access
// request nobody was prepared for.
const MaxRetain = Duration(90 * 24 * time.Hour)

// Retrieval is what an agent may read.
//
// Narrowing only. An empty list means "no restriction from this dimension",
// intersected with whatever the credential already allows — never unioned, so
// a manifest cannot widen what its token grants.
type Retrieval struct {
	// Ref is which ref it reads. Live by default: an agent reading the draft
	// answers questions from content nobody has published, and "it is only the
	// bot" is not a distinction the editor made when they saved.
	Ref string `json:"ref,omitempty"`
	// Types limits it to particular content types.
	Types []string `json:"types,omitempty"`
	// Locales limits it to particular languages.
	Locales []string `json:"locales,omitempty"`
	// Path limits it to a subtree.
	Path string `json:"path,omitempty"`
}

// Tool is a third-party API an agent may call.
//
// The host is declared, not derived from a URL the model produces at runtime.
// That is the whole control: an agent that can be talked into calling a host is
// an exfiltration channel, and the literature calls this cross-origin context
// poisoning. Naming the hosts in advance means a successful injection reaches
// an allowlist rather than the internet.
type Tool struct {
	Name string `json:"name"`
	// Host is exactly one hostname. No wildcards: "*.example.com" is a
	// promise about DNS that whoever registers a subdomain gets to break.
	Host string `json:"host"`
	// Purpose is why this agent needs it, for the person reviewing the
	// manifest rather than for the machine.
	Purpose string `json:"purpose"`
	// Writes marks a tool that changes something on the other side. A read
	// tool that turns out to write is the surprise worth making explicit.
	Writes bool `json:"writes,omitempty"`
	// Secret names the credential in the vault. The value is never in the
	// manifest, which is stored in a content-addressed object that cannot be
	// deleted.
	Secret string `json:"secret,omitempty"`
}

// Budget bounds one run.
//
// Every field is required to be non-zero. An agent with no ceiling is one whose
// cost is decided by whatever it read, and a goal-seeking agent that has been
// talked into a loop is the ordinary way that bill arrives.
type Budget struct {
	Steps    int      `json:"steps"`
	Tools    int      `json:"tool_calls"`
	Duration Duration `json:"duration"`
}

// Manifest is the whole declaration.
type Manifest struct {
	Name    string `json:"name"`
	Kind    Kind   `json:"kind"`
	Purpose string `json:"purpose"`

	// Capabilities are the operation names this agent may call, from the same
	// set the machine interface registers. An empty list means it may call
	// nothing, which is the right default for a thing that has not said what
	// it needs.
	Capabilities []string `json:"capabilities"`

	Autonomy  Autonomy  `json:"autonomy"`
	Retrieval Retrieval `json:"retrieval,omitempty"`
	Memory    Memory    `json:"memory,omitempty"`
	Tools     []Tool    `json:"tools,omitempty"`
	Budget    Budget    `json:"budget"`

	// Delegates are the agents a supervisor may hand work to. Named, so the
	// graph is a declaration rather than something a model decides at runtime.
	Delegates []string `json:"delegates,omitempty"`

	// HumanApproval requires a person to agree before anything this agent did
	// becomes public. Forced on for publish autonomy; see Validate.
	HumanApproval bool `json:"human_approval,omitempty"`
}

// writeOps are capabilities that change stored content.
//
// Named here rather than inferred from the operation name, because inferring
// from a prefix is how "check_provenance" and "content_id" end up classified by
// whoever names the next operation.
var writeOps = map[string]bool{
	"write_page":   true,
	"write_record": true,
	"publish":      true,
}

// IsWrite reports whether a capability changes stored content.
func IsWrite(op string) bool { return writeOps[op] }

// Validate refuses a manifest that cannot mean what it appears to.
//
// Every rule here is a refusal rather than a default, with one exception noted
// below. A manifest that is quietly corrected is one whose author believes
// something false about what they deployed.
func (m *Manifest) Validate(known map[string]bool) error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("an agent needs a name, so a log entry can say which one acted")
	}
	if !m.Kind.Valid() {
		return fmt.Errorf("%q is not an agent kind; use one of %s",
			m.Kind, kindList())
	}
	if strings.TrimSpace(m.Purpose) == "" {
		return fmt.Errorf(
			"%s has no stated purpose. A capability list nobody can review "+
				"against an intention is a capability list nobody reviews", m.Name)
	}
	if !m.Autonomy.Valid() {
		return fmt.Errorf("%q is not an autonomy level; use propose, draft or publish",
			m.Autonomy)
	}

	// Capabilities have to exist. An operation name that no interface
	// registers is a claim that this agent can do something it cannot, and it
	// will read as a working configuration until the day it is needed.
	for _, c := range m.Capabilities {
		if known != nil && !known[c] {
			return fmt.Errorf(
				"%s asks for the capability %q and no interface offers it",
				m.Name, c)
		}
	}

	// The autonomy level and the capability list have to agree. Declaring
	// propose-only and holding write_page is a manifest that reads as safe in
	// review and is not.
	for _, c := range m.Capabilities {
		if !IsWrite(c) {
			continue
		}
		if m.Autonomy == AutonomyPropose {
			return fmt.Errorf(
				"%s is propose-only and holds %q, which writes. Raise the "+
					"autonomy deliberately or drop the capability — a manifest "+
					"whose two halves disagree is one that was reviewed as the "+
					"safer half", m.Name, c)
		}
		if c == "publish" && m.Autonomy != AutonomyPublish {
			return fmt.Errorf(
				"%s holds \"publish\" at %s autonomy", m.Name, m.Autonomy)
		}
	}

	// Publishing is the one action with an outside observer, so it carries a
	// person. This is the single field that is forced rather than refused: the
	// alternative is refusing the manifest, and an author who wanted publish
	// autonomy would then set human_approval themselves and learn nothing.
	if m.Autonomy == AutonomyPublish {
		m.HumanApproval = true
	}

	if m.Memory.Any() {
		if m.Memory.Retain <= 0 {
			return fmt.Errorf(
				"%s remembers and states no retention period. Memory with no "+
					"expiry is a personal-data store nobody wrote a policy for",
				m.Name)
		}
		if m.Memory.Retain > MaxRetain {
			return fmt.Errorf(
				"%s would remember for %s and the ceiling is %s",
				m.Name, m.Memory.Retain, MaxRetain)
		}
	}

	for _, t := range m.Tools {
		if strings.TrimSpace(t.Host) == "" {
			return fmt.Errorf("the tool %q on %s names no host", t.Name, m.Name)
		}
		if strings.ContainsAny(t.Host, "*?") {
			return fmt.Errorf(
				"the tool %q on %s reaches %q. A wildcard host is a promise "+
					"about DNS that whoever registers a subdomain gets to break",
				t.Name, m.Name, t.Host)
		}
		if strings.Contains(t.Host, "/") || strings.Contains(t.Host, ":") {
			return fmt.Errorf(
				"the tool %q on %s should name a host, not a URL: %q",
				t.Name, m.Name, t.Host)
		}
		if strings.TrimSpace(t.Purpose) == "" {
			return fmt.Errorf(
				"the tool %q on %s has no stated purpose", t.Name, m.Name)
		}
	}

	if m.Budget.Steps <= 0 || m.Budget.Tools <= 0 || m.Budget.Duration <= 0 {
		return fmt.Errorf(
			"%s has no budget. An agent with no ceiling costs whatever it was "+
				"talked into, and a goal-seeking one in a loop is the ordinary "+
				"way that happens", m.Name)
	}

	if len(m.Delegates) > 0 && m.Kind != KindSupervisor {
		return fmt.Errorf(
			"%s delegates to other agents and is not a supervisor", m.Name)
	}
	for _, d := range m.Delegates {
		if d == m.Name {
			return fmt.Errorf("%s delegates to itself", m.Name)
		}
	}

	return nil
}

// Narrow returns the manifest further restricted by another.
//
// Used when a supervisor hands work to a delegate: the child can be narrower
// than the parent and never wider, which is the same rule a token exchange
// follows. Without it, a supervisor is a way to launder capability — delegate
// to an agent that holds more, and the restriction on the supervisor was
// decoration.
func (m Manifest) Narrow(by Manifest) Manifest {
	out := by

	// Capabilities: the intersection, because either side may only remove.
	held := map[string]bool{}
	for _, c := range m.Capabilities {
		held[c] = true
	}
	var caps []string
	for _, c := range by.Capabilities {
		if held[c] {
			caps = append(caps, c)
		}
	}
	sort.Strings(caps)
	out.Capabilities = caps

	// Autonomy: the lower of the two.
	if !by.Autonomy.AtMost(m.Autonomy) {
		out.Autonomy = m.Autonomy
	}

	// Budget: the smaller of each, so a delegate cannot spend more than its
	// parent was allowed in total.
	out.Budget = Budget{
		Steps:    minInt(m.Budget.Steps, by.Budget.Steps),
		Tools:    minInt(m.Budget.Tools, by.Budget.Tools),
		Duration: Duration(minInt64(int64(m.Budget.Duration), int64(by.Budget.Duration))),
	}

	// Memory: a delegate may not remember what its parent does not.
	out.Memory = Memory{
		Episodic:   m.Memory.Episodic && by.Memory.Episodic,
		Semantic:   m.Memory.Semantic && by.Memory.Semantic,
		Procedural: m.Memory.Procedural && by.Memory.Procedural,
		Retain:     Duration(minInt64(int64(m.Memory.Retain), int64(by.Memory.Retain))),
	}

	// Approval is sticky: a parent that needs one cannot delegate its way out.
	if m.HumanApproval {
		out.HumanApproval = true
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func kindList() string {
	parts := make([]string, len(Kinds))
	for i, k := range Kinds {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}
