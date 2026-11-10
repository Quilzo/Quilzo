// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package collab

import (
	"fmt"
	"slices"
	"strings"
)

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

// # Who a machine wrote for
//
// The machine interface and the writing assistant commit under the name of
// the person they act for: a change a client makes over MCP is recorded as
// by the person whose token it holds, and one `quilzo assist --author dana`
// makes as by dana. An agent run commits as the agent ("agent/NAME"), and
// names the person who started the run in its message (AgentMessage): what
// a model does for a person is the model's, and that person is who asked
// for it, whichever way it reached the draft.
//
// Read as written by that person, what dana's client wrote was dana's own
// work: she was told "dana wrote this change and cannot approve it", it was
// left out of what waits for her, and on an installation run by one person
// it could never be published. It is a model's work, made for her, and what
// the approval gate asks of a model's work is that a person reads it; dana
// reading what her client wrote is that. So such a commit names the machine
// as its writer and the person as who it was written for (WrittenFor), and
// where a count of approvals is set that person is who asked for it, as
// they are for their own work, and somebody else approves it
// (Policy.Requested).

// actingFor are the machines that commit under the name of the person they
// act for: the prefix their commits carry, the name a proposal gives them
// as its author, and what the person would call them.
var actingFor = []struct{ prefix, writer, called string }{
	{"mcp:", "mcp-client", "client"},
	{"assist:", "assistant", "writing assistant"},
}

// machineFor is the entry in actingFor a commit was made by, when a
// machine made it for the person it is recorded under.
func machineFor(message, author string) (writer, called string, ok bool) {
	if author == "" {
		return "", "", false
	}
	for _, a := range actingFor {
		if strings.HasPrefix(message, a.prefix) {
			return a.writer, a.called, true
		}
	}
	return "", "", false
}

// WrittenFor reads who wrote a commit, as a proposal names its author, and
// the person a machine wrote it for: the machine and the person it is
// recorded under, for a commit a machine made for somebody; the agent and
// the person who started its run, for an agent's (AgentMessage); and
// otherwise the author it is recorded under and nobody.
func WrittenFor(message, author string) (writer, person string) {
	if w, _, ok := machineFor(message, author); ok {
		return w, author
	}
	if p := agentFor(message, author); p != "" {
		return author, p
	}
	return author, ""
}

// AgentMessage is the message of a commit an agent run makes: the agent,
// the page, and the person who started the run, as its record names them.
//
// An agent commits as itself ("agent/NAME"), so the commit named nobody it
// was written for, and with a count of approvals set the person who
// started the run approved what it wrote as though it were somebody else's.
// The person goes in the message, which every surface that asks who wrote
// a commit already reads (MachineWrote), and is read back only from a
// commit the agent it names is recorded as making (agentFor). Made here,
// where it is read, so the two cannot come to disagree.
func AgentMessage(agent, page, person string) string {
	msg := AgentPrefix + agent + " wrote " + page
	if person != "" {
		msg += " for " + person
	}
	return msg
}

// agentFor is the person an agent's commit says its run was started by, or
// nobody: an older commit says none, and a commit whose message names an
// agent other than the one it is recorded as made by is not that agent's.
func agentFor(message, author string) string {
	rest, ok := strings.CutPrefix(message, AgentPrefix)
	if !ok {
		return ""
	}
	name, after, ok := strings.Cut(rest, " wrote ")
	if !ok || author != "agent/"+name {
		return ""
	}
	_, person, _ := strings.Cut(after, " for ")
	return strings.TrimSpace(person)
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

// MachineChange is a commit a machine wrote among those a publish would put
// live, named so a refusal can say which change a person is being asked to
// read and who it is recorded as written by.
//
// # Why not only the newest commit
//
// AuthorKindFor reads one commit message, and every surface handed it the
// commit being published. A draft is a chain of commits. An agent rewrote
// the pricing, a person then fixed a typo on another page, and the draft's
// newest commit was the person's: RequireHumanForAI never applied, and the
// admin, the command line, the machine interface, scheduled publishing and
// promotion all put the agent's pricing live with no person having read
// it. Nothing about the typo made the pricing a person's work, so the
// question is asked of every commit the publish would put live
// (site.MachineWroteSince), and this is its answer.
type MachineChange struct {
	Commit  string `json:"commit"`
	Author  string `json:"author,omitempty"`
	Message string `json:"message,omitempty"`
	// Unread is why the history was not read to the end, when it was not,
	// and Commit is then where the reading stopped. Nothing was found and
	// nothing was ruled out either, and the answer given is the one that
	// asks a person: a history too long to read, or one holding a commit
	// that cannot be, is no evidence that a person wrote it.
	Unread string `json:"unread,omitempty"`
	// People are everybody a machine wrote for (WrittenFor) among all the
	// commits the publish would put live, newest first, and not only the
	// person this one was made for: what a proposal names as who asked for
	// it (Proposal.MarkMachine). Named by this commit alone, a change dana's
	// client made was hers to approve once lee's client wrote after it.
	People []string `json:"people,omitempty"`
}

// Describe says, for whoever is refused, which change a person is being
// asked to read: content is the commit being published, so a model's change
// further back is said to be one.
func (m MachineChange) Describe(content string) string {
	if m.Unread != "" {
		return fmt.Sprintf("Not all of what this would put live could be read "+
			"to see who wrote it (%s), so a person reads it first.", m.Unread)
	}
	if m.Commit == content {
		return fmt.Sprintf("It is commit %s, recorded as written by %s: %q.",
			short(m.Commit), m.writtenBy(), m.Message)
	}
	// "Not yet published" rather than "since the last publish", which a
	// first publish has none of.
	return fmt.Sprintf("A model's change not yet published goes live with it: "+
		"commit %s, recorded as written by %s: %q.", short(m.Commit), m.writtenBy(), m.Message)
}

// Writer is who wrote the change, as a proposal names its author: the
// machine, when it was made for the person it is recorded under.
func (m MachineChange) Writer() string {
	w, _ := WrittenFor(m.Message, m.Author)
	return w
}

// For is the person a machine made the change for, or nobody.
func (m MachineChange) For() string {
	_, p := WrittenFor(m.Message, m.Author)
	return p
}

// writtenBy is who a refusal says wrote the change. "dana's client" rather
// than "dana": said as dana's, the person reading a refusal about a model's
// change was told it was their own.
func (m MachineChange) writtenBy() string {
	if _, called, ok := machineFor(m.Message, m.Author); ok {
		return m.Author + "'s " + called
	}
	return m.Author
}

// MarkMachine records on a proposal that a machine wrote some of what it
// would put live, which makes it AI-authored whoever proposed it, and for
// whom, when the changes say: every person, added to whoever the proposal
// already names and never in their place. A nil change leaves the
// proposal as it was: finding no machine's commit is no reason to call a
// proposal a person's when a model is what proposed it.
func (prop *Proposal) MarkMachine(m *MachineChange) {
	if m == nil {
		return
	}
	prop.AuthorKind = "ai"
	prop.Machine = m
	people := m.People
	if len(people) == 0 && m.For() != "" {
		// A change worked out by somebody who named only its own person.
		people = []string{m.For()}
	}
	for _, person := range people {
		switch {
		case person == "" || slices.Contains(prop.ForWhom(), person):
		case prop.OnBehalfOf == "":
			prop.OnBehalfOf = person
		default:
			// Clipped, so a copy of the proposal marked here (the review
			// screen judges one) never writes into the list it was copied
			// from.
			prop.AlsoOnBehalfOf = append(slices.Clip(prop.AlsoOnBehalfOf), person)
		}
	}
}

// ForWhom is everybody a machine wrote some of the change for: OnBehalfOf,
// and the others after it.
func (prop Proposal) ForWhom() []string {
	var out []string
	if prop.OnBehalfOf != "" {
		out = append(out, prop.OnBehalfOf)
	}
	for _, p := range prop.AlsoOnBehalfOf {
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// WrittenBy is who a refusal says wrote the change made for person:
// "dana's client", or a model working for them when which is not known.
func (prop Proposal) WrittenBy(person string) string {
	if prop.Machine != nil && prop.Machine.For() == person {
		return prop.Machine.writtenBy()
	}
	return "a model working for " + person
}

// Requested reports whether by asked for the change rather than may approve
// it: its author, always, and anybody a machine wrote some of it for
// (ForWhom) wherever a count of approvals is set, as they would be for
// their own work. Where none is, the one approval asked for is a person's
// reading of a model's work, and a person it was written for reading it is
// that.
func (p Policy) Requested(prop Proposal, by string) bool {
	if by == prop.Author {
		return true
	}
	return by != "" && max(p.Required, p.RequiredHumans) > 0 && slices.Contains(prop.ForWhom(), by)
}
