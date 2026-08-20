// Package a2a publishes what this store's agents are, and what they may do.
//
// # Why an Agent Card at all
//
// A2A reached v1.0 in 2026 under the Linux Foundation and settled agent
// discovery on a static JSON document at a well-known path. That is a good fit
// here for a reason that has nothing to do with fashion: it is a file. No
// runtime, no client script, no long-lived connection — the same shape as
// robots.txt, llms.txt and the RSL licence this server already publishes.
//
// # The part that is not in the protocol
//
// "Governance Gaps in Agent Interoperability Protocols" (arXiv 2606.31498)
// catalogues what MCP, A2A and ACP cannot express: fine-grained permissions,
// delegation with accountability, resource budgets, provenance, revocation, and
// responsibility in a chain of delegated decisions. A card that says only "this
// agent can answer questions about products" tells a caller nothing about what
// happens if it is asked to do something else.
//
// Quilzo enforces all six already, because they are what CaMeL requires. So the
// card carries them, in a namespaced extension: per skill, the capabilities it
// holds, the content it may read, the budget it is bound by, whether it may
// publish, and whether its output needs a person. A caller can decide whether
// to delegate before spending anything, and an auditor can read what was
// promised without access to the store.
//
// # It cannot lie
//
// Every field is derived from the manifest the session actually enforces. There
// is no second declaration to drift: if the card says an agent cannot write,
// that is because Authorize refuses the write, and a test asserts the two agree.
// An API Evangelist survey in July 2026 found most published agent cards are not
// valid A2A at all, which is what happens when a card is hand-written beside the
// thing it describes rather than generated from it.
//
// # Off unless somebody turns it on
//
// A card is a public statement about what this deployment will do for a
// stranger. That is a decision an operator makes, not a default — the same rule
// the catalogue feed follows.
package a2a

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
)

// ProtocolVersion is the A2A revision this card claims.
//
// Stated rather than omitted. A card with no protocolVersion is a card a
// consumer has to guess at, and guessing is how "most published agent cards are
// not actually A2A" happens.
const ProtocolVersion = "0.3.0"

// GovernanceExtension is the URI naming the extension below.
//
// Namespaced to this project rather than invented in A2A's own space: it is not
// a standard, it is a proposal with an implementation behind it, and saying so
// in the identifier is the honest way to publish an extension.
const GovernanceExtension = "https://quilzo.github.io/spec/agent-governance/v1"

// Card is an A2A Agent Card.
//
// Field names and shapes follow the published v0.3.0 sample exactly, including
// the ones that look redundant — preferredTransport beside additionalInterfaces
// — because a consumer validates against the spec and not against what would
// have been tidier.
type Card struct {
	ProtocolVersion    string       `json:"protocolVersion"`
	Name               string       `json:"name"`
	Description        string       `json:"description"`
	URL                string       `json:"url"`
	PreferredTransport string       `json:"preferredTransport"`
	Provider           *Provider    `json:"provider,omitempty"`
	Version            string       `json:"version"`
	DocumentationURL   string       `json:"documentationUrl,omitempty"`
	Capabilities       Capabilities `json:"capabilities"`
	DefaultInputModes  []string     `json:"defaultInputModes"`
	DefaultOutputModes []string     `json:"defaultOutputModes"`
	Skills             []Skill      `json:"skills"`

	// Governance is the extension this project adds, keyed by its URI so a
	// consumer that does not know it can ignore it and one that does can find
	// it without guessing at a field name.
	Governance map[string]Governance `json:"extensions,omitempty"`
}

// Provider is who runs this.
type Provider struct {
	Organization string `json:"organization"`
	URL          string `json:"url,omitempty"`
}

// Capabilities are the A2A transport features. All false here, and truthfully:
// this server publishes a card and does not implement streaming or push.
type Capabilities struct {
	Streaming              bool `json:"streaming"`
	PushNotifications      bool `json:"pushNotifications"`
	StateTransitionHistory bool `json:"stateTransitionHistory"`
}

// Skill is one declared agent, described for a caller deciding whether to use it.
type Skill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// Governance is what the protocols cannot say.
//
// One entry per skill id. Every field is read from the enforced manifest, so
// this is a description of the gate rather than a promise beside it.
type Governance struct {
	// Capabilities is the closed list of operations. Anything else is refused
	// at the chokepoint, whatever the caller asks for and however it is
	// phrased.
	Capabilities []string `json:"capabilities"`

	// Autonomy is propose, draft or publish — what the agent may do with what
	// it produces, as distinct from what it may read.
	Autonomy string `json:"autonomy"`

	// Writes is whether any held capability changes stored content. Derived
	// rather than declared, so it cannot disagree with the list above.
	Writes bool `json:"writes"`

	// HumanApproval is whether a person must agree before anything this agent
	// did becomes public. Forced on for publish autonomy.
	HumanApproval bool `json:"humanApproval"`

	// TaintsOnRead says the run is marked once it reads stored content, and
	// that a marked run cannot publish itself. This is the CaMeL property and
	// it is the one a delegating caller most needs to know: output from this
	// agent is downstream of input somebody else may have written.
	TaintsOnRead bool `json:"taintsOnRead"`

	// Scope is the content this agent may read: which ref, which types, which
	// locales. Empty lists mean unrestricted, which is stated rather than left
	// to inference.
	Scope Scope `json:"scope"`

	// Budget bounds one run. A caller delegating work can price it before
	// spending anything, which is the whole point of publishing it.
	Budget Budget `json:"budget"`

	// Delegates are the agents this one may hand work to, by name. The graph is
	// declared, not chosen at runtime, so an accountability chain is readable
	// in advance rather than reconstructed from logs afterwards.
	Delegates []string `json:"delegates,omitempty"`

	// Hosts is the outside systems it may reach. Empty means none.
	Hosts []string `json:"hosts,omitempty"`

	// Memory is what it retains and for how long. Absent when it retains
	// nothing, because "no memory" and "memory with no stated retention" must
	// not look the same.
	Memory *Memory `json:"memory,omitempty"`

	// Revocation says where a caller learns that this changed. A card is a
	// snapshot; the protocols have no revocation story at all, and the least
	// this can do is say the snapshot has an origin that can be re-read.
	Revocation string `json:"revocation"`

	// Accountability is where the record of what happened lives.
	Accountability string `json:"accountability"`
}

// Scope is the content boundary.
type Scope struct {
	Ref     string   `json:"ref,omitempty"`
	Types   []string `json:"types,omitempty"`
	Locales []string `json:"locales,omitempty"`
}

// Budget is the per-run ceiling.
type Budget struct {
	Steps     int    `json:"steps"`
	ToolCalls int    `json:"toolCalls"`
	Duration  string `json:"duration"`
}

// Memory is what an agent keeps between runs.
type Memory struct {
	Episodic   bool   `json:"episodic"`
	Semantic   bool   `json:"semantic"`
	Procedural bool   `json:"procedural"`
	Retain     string `json:"retain"`
}

// Options are the deployment facts the manifests do not carry.
type Options struct {
	// SiteName is what this deployment calls itself.
	SiteName string
	// BaseURL is the origin the card is served from, without a trailing slash.
	BaseURL string
	// Version is the build.
	Version string
	// DocumentationURL, if the operator publishes one.
	DocumentationURL string
	// Provider is the organisation running it.
	Provider string
	// ProviderURL is theirs, not this project's.
	ProviderURL string
}

// From builds a card from the agents a store has declared.
//
// Only agents that validate are included. A manifest this build would refuse to
// run is not a skill this deployment offers, and advertising one would be the
// card lying in the direction that matters — a caller delegating to something
// that cannot start.
func From(manifests map[string]agent.Manifest, known map[string]bool, o Options) Card {
	names := make([]string, 0, len(manifests))
	for name := range manifests {
		names = append(names, name)
	}
	sort.Strings(names)

	base := strings.TrimRight(o.BaseURL, "/")
	c := Card{
		ProtocolVersion:    ProtocolVersion,
		Name:               nonEmpty(o.SiteName, "A Quilzo store"),
		URL:                base + "/.well-known/agent-card.json",
		PreferredTransport: "HTTP+JSON",
		Version:            nonEmpty(o.Version, "0.0.0"),
		DocumentationURL:   o.DocumentationURL,
		Capabilities: Capabilities{
			// All false, and true. This server publishes a discovery document;
			// it does not implement A2A task transport. A card claiming
			// streaming it does not have is the failure mode that makes
			// published cards untrustworthy.
			Streaming: false, PushNotifications: false,
			StateTransitionHistory: false,
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Governance:         map[string]Governance{},
	}
	if o.Provider != "" {
		c.Provider = &Provider{Organization: o.Provider, URL: o.ProviderURL}
	}
	c.Description = fmt.Sprintf(
		"Content held in a merkle store, and the agents allowed to touch it. "+
			"Each skill below is an enforced manifest: the %s extension states "+
			"the capabilities, scope, budget and accountability that A2A itself "+
			"cannot express.", GovernanceExtension)

	for _, name := range names {
		m := manifests[name]
		// Refused manifests are not advertised. Validate copies nothing, so
		// this cannot mutate what the store holds.
		check := m
		if err := check.Validate(known); err != nil {
			continue
		}
		c.Skills = append(c.Skills, Skill{
			ID:          name,
			Name:        nonEmpty(m.Name, name),
			Description: m.Purpose,
			Tags:        append([]string(nil), m.Capabilities...),
			InputModes:  []string{"text/plain"},
			OutputModes: []string{"text/plain"},
		})
		c.Governance[name] = governanceOf(m, base)
	}
	if len(c.Skills) == 0 {
		// An explicit empty list rather than a missing key: "this deployment
		// offers no agents" is an answer, and a card with no skills field looks
		// like a card that failed to render one.
		c.Skills = []Skill{}
	}
	return c
}

func governanceOf(m agent.Manifest, base string) Governance {
	g := Governance{
		Capabilities:  append([]string(nil), m.Capabilities...),
		Autonomy:      string(m.Autonomy),
		HumanApproval: m.HumanApproval,
		// Every agent that can read taints on read. Stated per skill rather
		// than once at the top, because a caller reads one skill.
		TaintsOnRead: true,
		Scope: Scope{
			Ref:     m.Retrieval.Ref,
			Types:   append([]string(nil), m.Retrieval.Types...),
			Locales: append([]string(nil), m.Retrieval.Locales...),
		},
		Budget: Budget{
			Steps:     m.Budget.Steps,
			ToolCalls: m.Budget.Tools,
			Duration:  m.Budget.Duration.String(),
		},
		Delegates: append([]string(nil), m.Delegates...),
		// A snapshot with an origin. The protocols have no revocation
		// mechanism; re-reading the card is the weakest useful substitute and
		// saying so is better than implying more.
		Revocation: base + "/.well-known/agent-card.json",
		Accountability: "every run is recorded in this store's append-only " +
			"audit log, with a receipt naming what was done, refused and spent",
	}
	for _, c := range m.Capabilities {
		if agent.IsWrite(c) {
			g.Writes = true
			break
		}
	}
	for _, t := range m.Tools {
		if h := strings.TrimSpace(t.Host); h != "" {
			g.Hosts = append(g.Hosts, h)
		}
	}
	sort.Strings(g.Hosts)
	if m.Memory.Episodic || m.Memory.Semantic || m.Memory.Procedural {
		g.Memory = &Memory{
			Episodic: m.Memory.Episodic, Semantic: m.Memory.Semantic,
			Procedural: m.Memory.Procedural,
			Retain:     m.Memory.Retain.String(),
		}
	}
	return g
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
