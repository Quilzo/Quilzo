// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

// What this executor can actually do, said once so something can check.
//
// # The gap this closes
//
// A manifest's capabilities are validated against the MCP server's operation
// registry — twenty-five names — because that registry is what an agent could
// in principle be granted. The executor performs six of them. Everything else
// validated, appeared on the A2A card as a capability, and failed at runtime
// with
//
//	"run_listing" is permitted for this agent and not implemented here
//
// Seven of the eight shipped archetypes declared at least one. `quilzo agent
// new a-retrieval --kind retrieval` produced an agent that could do neither of
// the two things its purpose describes.
//
// The error string was honest and nothing read it. There was no list to check
// a manifest against, so the mismatch could only be found by running an agent
// and reading its failures — which is how this was found.
//
// # Why a list rather than a check at dispatch
//
// Because the useful moment is when the manifest is written, not when the
// agent runs. A refusal at dispatch is a correct refusal at the worst possible
// time: a nightly agent that reports four failures is one somebody investigates
// next week. Validate can refuse the manifest instead, and an archetype that
// declares something unperformable cannot be shipped.

// Performs lists the operations Dispatch carries out.
//
// Kept beside the switches it describes, and checked against them by a test
// that reads the source — so an operation added to one and not the other is a
// build failure rather than a runtime surprise.
func Performs() []string {
	return []string{
		// Reads, from exec.go.
		"list_pages",
		"read_page",
		"search_pages",
		"similar_pages",
		// Writes, from write.go. publish does not publish: it proposes.
		"write_page",
		"publish",
	}
}

// PerformsTools reports whether a tool call can be carried out.
//
// Separate from Performs because a tool is not an operation name: the
// manifest declares tools by their own names, per agent, and this executor
// performs whichever of them the install has an integration for. There is no
// fixed list to compare a manifest against — Integrations.Resolve answers that
// per call — so what can be said here is only whether the surface exists at
// all.
//
// It did not. Dispatch had no branch for Action.Tool, so every tool call this
// program was capable of authorising came back "is permitted for this agent
// and not implemented here".
func PerformsTools() bool { return true }

// Refuses lists the operations this executor deliberately will not perform.
//
// Separate from "not implemented" because the two mean different things to
// whoever is writing a manifest. diff spans two refs and a scoped agent has
// been granted one; that is an argument, not a gap, and an archetype that
// declares it is asking for something this design will not give.
func Refuses() map[string]string {
	return map[string]string{
		"diff": "a diff spans two refs and a scoped agent holds one, so " +
			"answering would quietly include the ref it was not granted",
	}
}
