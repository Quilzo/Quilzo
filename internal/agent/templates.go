package agent

import (
	"sort"
	"time"
)

// Ready-made agents, one per archetype.
//
// A template is a starting manifest, not a product. It exists because the
// fields that matter are the ones nobody thinks about until something goes
// wrong — the capability list, the retention period, the host allowlist, the
// budget — and a blank manifest is a form where those are all empty and the
// author fills in the two they care about.
//
// So each template is the archetype with its defaults already set to the
// narrow answer, and the person widens what they actually need. That is the
// direction that fails safe: a template that is too tight produces a bug
// report, and one that is too loose produces an incident.
//
// Every one of these validates. A template that has to be edited before it
// passes is a template that teaches people to edit until the error stops.

// Template is an archetype with a description of when to reach for it.
type Template struct {
	// Summary is one line, for a list.
	Summary string
	// When says what this is for, and — as importantly — what it is not.
	When string
	// Research names where the shape comes from, so somebody can check the
	// claim rather than take it.
	Research string
	Manifest Manifest
}

func hours(n int) Duration { return Duration(time.Duration(n) * time.Hour) }
func mins(n int) Duration  { return Duration(time.Duration(n) * time.Minute) }

// templates is the set, keyed by kind.
var templates = map[Kind]Template{

	KindRetrieval: {
		Summary: "answers questions from published content, and cannot write",
		When: "A support bot, a docs assistant, a site search that explains " +
			"itself. Reach for this first: most things people describe as " +
			"an agent are this, and this is the shape with almost no blast " +
			"radius.",
		Research: "Retrieval-augmented generation. The security property here " +
			"is not the model — it is that retrieval is scoped by the asking " +
			"credential, so the bot cannot surface a draft, an embargoed page " +
			"or a locale the reader may not see, whatever it is asked.",
		Manifest: Manifest{
			Kind:    KindRetrieval,
			Purpose: "Answer questions using published content only.",
			// Read operations only. This is the entire point of the archetype.
			Capabilities: []string{
				"read_page", "list_pages", "run_listing", "list_terms",
			},
			Autonomy: AutonomyPropose,
			// Live, never draft. A bot answering from unpublished content is
			// a disclosure with a friendly interface.
			Retrieval: Retrieval{Ref: "live"},
			Memory:    Memory{}, // stateless: nothing to leak, nothing to retain
			Budget:    Budget{Steps: 8, Tools: 4, Duration: mins(2)},
		},
	},

	KindTask: {
		Summary: "performs one bounded operation on request",
		When: "Retagging a batch, running the accessibility check, exporting " +
			"a report. Use when the work is known in advance and the agent " +
			"is deciding how rather than what.",
		Research: "The task-oriented shape is the one with a checkable " +
			"definition of done, which is why it is the easiest to run " +
			"unattended and the one worth reaching for before autonomy.",
		Manifest: Manifest{
			Kind:    KindTask,
			Purpose: "Carry out one named operation and report what it did.",
			Capabilities: []string{
				"read_page", "list_pages", "write_page", "check_accessibility",
			},
			Autonomy:  AutonomyDraft,
			Retrieval: Retrieval{Ref: "draft"},
			Memory:    Memory{Episodic: true, Retain: hours(24 * 7)},
			Budget:    Budget{Steps: 25, Tools: 15, Duration: mins(10)},
		},
	},

	KindCopilot: {
		Summary: "works alongside a person, on what they are looking at",
		When: "Drafting, rewriting, suggesting structure — with somebody " +
			"watching. The person is the approval step, so this is the one " +
			"archetype where propose-only is not a limitation.",
		Research: "A copilot's risk is not autonomy but suggestion bias: it " +
			"proposes and a tired person accepts. Proposals are marked as " +
			"AI-written when they land, which is what keeps the provenance " +
			"record honest about who wrote the page.",
		Manifest: Manifest{
			Kind:    KindCopilot,
			Purpose: "Suggest edits to the page a person is working on.",
			Capabilities: []string{
				"read_page", "list_pages", "diff", "check_accessibility",
			},
			Autonomy:  AutonomyPropose,
			Retrieval: Retrieval{Ref: "draft"},
			// Semantic only, and briefly: a copilot that remembers how you
			// like things is useful; one that remembers what you wrote is a
			// profile of an employee.
			Memory: Memory{Semantic: true, Retain: hours(24 * 30)},
			Budget: Budget{Steps: 12, Tools: 6, Duration: mins(3)},
		},
	},

	KindAutonomous: {
		Summary: "pursues a goal across many steps, without being asked each time",
		When: "Keeping a section current, watching for stale translations, " +
			"maintaining a changelog. Use when the goal is stable and the " +
			"steps are not — and only with a budget you would be willing to " +
			"spend on a loop.",
		Research: "This is the archetype the prompt-injection literature is " +
			"about. It reads content it did not choose, so anything it reads " +
			"is untrusted input to a thing holding capabilities. The defence " +
			"here is structural: the capability list is fixed before the run " +
			"and no instruction found in content can widen it.",
		Manifest: Manifest{
			Kind: KindAutonomous,
			Purpose: "Work towards a stated goal over multiple steps and " +
				"report what changed.",
			Capabilities: []string{
				"read_page", "list_pages", "diff", "write_page",
				"check_accessibility", "check_translations",
			},
			Autonomy:      AutonomyDraft,
			Retrieval:     Retrieval{Ref: "draft"},
			Memory:        Memory{Episodic: true, Semantic: true, Retain: hours(24 * 14)},
			Budget:        Budget{Steps: 60, Tools: 40, Duration: mins(30)},
			HumanApproval: true,
		},
	},

	KindSupervisor: {
		Summary: "decomposes work and hands it to named specialists",
		When: "A pipeline with distinct stages — research, draft, check, " +
			"translate. Use when the stages genuinely differ; a supervisor " +
			"over one agent is a slower version of that agent.",
		Research: "The supervisor pattern is one of the shapes that survived " +
			"into production in 2026: a lead decomposes, delegates " +
			"non-overlapping subtasks, and aggregates. Delegates are named " +
			"here rather than chosen at runtime, so the graph is reviewable " +
			"and a compromised supervisor cannot invent a new worker.",
		Manifest: Manifest{
			Kind:    KindSupervisor,
			Purpose: "Break work into stages and delegate each to a named agent.",
			Capabilities: []string{
				"read_page", "list_pages", "diff",
			},
			Autonomy:      AutonomyDraft,
			Retrieval:     Retrieval{Ref: "draft"},
			Memory:        Memory{Episodic: true, Retain: hours(24 * 7)},
			Budget:        Budget{Steps: 40, Tools: 20, Duration: mins(20)},
			HumanApproval: true,
		},
	},

	KindArchivist: {
		Summary: "keeps long-horizon memory across all three tiers",
		When: "Institutional knowledge — why a decision was made, what was " +
			"tried. Use deliberately: this is the archetype that accumulates " +
			"personal data as a side effect of being useful.",
		Research: "Episodic, semantic and procedural is the taxonomy the " +
			"field converged on across 2025-26, mirroring cognitive science " +
			"and implemented in Letta/MemGPT's core/archival/recall tiers. " +
			"The semantic tier is the one to watch: 'the user prefers X' is a " +
			"profile that nobody consented to and that no screen shows them.",
		Manifest: Manifest{
			Kind:    KindArchivist,
			Purpose: "Remember what happened and what was concluded, and recall it on request.",
			Capabilities: []string{
				"read_page", "list_pages", "diff", "agent_activity",
			},
			Autonomy:  AutonomyPropose,
			Retrieval: Retrieval{Ref: "live"},
			Memory: Memory{
				Episodic: true, Semantic: true, Procedural: true,
				Retain: MaxRetain,
			},
			Budget: Budget{Steps: 15, Tools: 8, Duration: mins(5)},
		},
	},

	KindLearner: {
		Summary: "keeps what worked as reusable procedure, and gets better at it",
		When: "Repeated work with a checkable outcome, where the second " +
			"hundred should cost less than the first. Not for one-off tasks: " +
			"there is nothing to distil.",
		Research: "Self-improvement in the literature means a growing skill " +
			"library rather than a changing model — Voyager builds one from " +
			"environment feedback, Reflexion stores verbal self-critique " +
			"across episodes, ExpeL extracts insights from trajectories. " +
			"Procedural memory is where that lives, which is why this " +
			"archetype is the procedural tier turned on and the others left " +
			"alone.",
		Manifest: Manifest{
			Kind: KindLearner,
			Purpose: "Distil successful runs into named, reusable procedures " +
				"and apply them next time.",
			Capabilities: []string{
				"read_page", "list_pages", "diff", "write_page",
				"check_accessibility",
			},
			Autonomy:  AutonomyDraft,
			Retrieval: Retrieval{Ref: "draft"},
			// Procedural and episodic; deliberately not semantic. A skill is
			// about the work. A conclusion about a person is not a skill.
			Memory:        Memory{Episodic: true, Procedural: true, Retain: MaxRetain},
			Budget:        Budget{Steps: 40, Tools: 25, Duration: mins(15)},
			HumanApproval: true,
		},
	},

	KindOperator: {
		Summary: "does errands outside this system, in the apps you already use",
		When: "The personal-assistant shape — reachable from a chat app, " +
			"acting across services. The most useful archetype and by a " +
			"distance the most dangerous.",
		Research: "OpenClaw made this shape mainstream in 2026, reaching " +
			"250,000 GitHub stars in sixty days by running locally, " +
			"remembering across conversations, and acting through WhatsApp " +
			"or Telegram. What it also demonstrated is the exposure: an " +
			"agent reachable from a messaging app, holding your credentials, " +
			"acting on messages other people send you. Every message is " +
			"untrusted input. So this template ships with no tools at all — " +
			"each host is added deliberately, and the manifest refuses a " +
			"wildcard.",
		Manifest: Manifest{
			Kind:    KindOperator,
			Purpose: "Carry out errands on request through named external services.",
			Capabilities: []string{
				"read_page", "list_pages",
			},
			Autonomy:  AutonomyPropose,
			Retrieval: Retrieval{Ref: "live"},
			Memory:    Memory{Episodic: true, Retain: hours(24 * 7)},
			// No tools. Adding one is the decision, and it is made per host.
			Tools:  nil,
			Budget: Budget{Steps: 20, Tools: 10, Duration: mins(5)},
		},
	},
}

// For returns the template for a kind.
func For(k Kind) (Template, bool) { t, ok := templates[k]; return t, ok }

// New returns a validated manifest for a kind, under a name.
func New(k Kind, name string, known map[string]bool) (Manifest, error) {
	t, ok := templates[k]
	if !ok {
		return Manifest{}, errUnknownKind(k)
	}
	m := t.Manifest
	m.Name = name
	// Copied rather than shared: the template's slices would otherwise be
	// aliased by every agent made from it, so editing one agent's capability
	// list would edit the template and every sibling.
	m.Capabilities = append([]string(nil), t.Manifest.Capabilities...)
	m.Tools = append([]Tool(nil), t.Manifest.Tools...)
	m.Delegates = append([]string(nil), t.Manifest.Delegates...)
	if err := m.Validate(known); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func errUnknownKind(k Kind) error {
	return &UnknownKindError{Kind: k}
}

// UnknownKindError names a kind that has no template.
type UnknownKindError struct{ Kind Kind }

func (e *UnknownKindError) Error() string {
	return string(e.Kind) + " is not an agent kind; use one of " + kindList()
}

// Catalogue lists every template, in presentation order.
func Catalogue() []Template {
	out := make([]Template, 0, len(templates))
	for _, k := range Kinds {
		if t, ok := templates[k]; ok {
			out = append(out, t)
		}
	}
	return out
}

// KindNames lists the kinds as strings, sorted, for help text.
func KindNames() []string {
	out := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}
