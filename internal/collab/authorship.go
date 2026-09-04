package collab

import "strings"

// Who wrote a change, as opposed to who is offering it for review.
//
// # The gap this closes
//
// RequireHumanForAI exists so that a model's work cannot reach the public on
// two service accounts agreeing with each other. It turns on Proposal.
// AuthorKind, and the two surfaces that set that field disagreed about what it
// meant.
//
// The command line read the commit: a message beginning "agent: ", "assist:"
// or "mcp:" is machine-written, whoever runs the command. The admin read the
// principal: whoever pressed Propose. So a person opening the review screen
// on a draft a model had just written proposed it as "human", the rule never
// fired, and the one control designed to stop two machines approving each
// other was bypassed by the ordinary path of a person clicking a button.
//
// The admin is the surface that matters here. approval.go says as much about
// dual authorisation itself: a control only reachable from a terminal is one
// the people it constrains route around by using the interface.
//
// # The rule
//
// Authorship is a property of the content. A proposal is AI-authored when the
// commit says a machine wrote it, regardless of who is offering it; otherwise
// it takes the kind of whoever is proposing, which may itself be a service.
// Those two are combined in one function so there is nowhere for them to
// disagree again.

// AgentPrefix marks a commit written by an agent through agentexec.
//
// Defined here rather than there because this is the package that decides what
// a machine-written change requires, and a constant on the far side of that
// decision is one that can be changed without anybody noticing this depends
// on it.
const AgentPrefix = "agent: "

// machinePrefixes are every commit-message marker meaning "not typed by a
// person": an agent run, the writing assistant, and a change made over MCP.
var machinePrefixes = []string{AgentPrefix, "assist:", "mcp:"}

// MachineWrote reports whether a commit message says a machine produced it.
func MachineWrote(message string) bool {
	for _, p := range machinePrefixes {
		if strings.HasPrefix(message, p) {
			return true
		}
	}
	return false
}

// AuthorKindFor decides what a proposal's AuthorKind should be.
//
// proposerKind is what the principal offering the change is -- human, service
// or ai -- and is used only when the content itself does not say. Content
// wins: a person may propose a model's work, and it is still a model's work.
func AuthorKindFor(commitMessage, proposerKind string) string {
	if MachineWrote(commitMessage) {
		return "ai"
	}
	if proposerKind == "" {
		return "human"
	}
	return proposerKind
}
