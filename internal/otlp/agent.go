// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package otlp

import (
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// Turning a run into spans.
//
// # What a span says that a log line does not
//
// The audit log already records that an agent ran and what it did. What it
// cannot show is shape: which step took the time, whether the refusals came at
// the start or after the budget was nearly spent, how a delegated run nests
// inside the one that asked for it. That is what a trace is for, and it is the
// question somebody actually has at three in the morning.
//
// # The attributes are chosen to answer one question each
//
// Not everything available — everything that changes a decision. An attribute
// nobody filters on is a byte on somebody's bill and a column in their backend.
//
// # In OpenTelemetry's words as well as Quilzo's
//
// A run is an invoke_agent span and each step an execute_tool span, with the
// gen_ai.* attributes of OpenTelemetry's GenAI semantic conventions, so a
// backend that knows agents from any other vendor reads Quilzo's the same
// way: the agent's name, the tool each step called, the error that ended
// it. The conventions are still marked as in development, so the quilzo.*
// attributes stay beside them, and a dashboard built on either keeps
// working when the other changes.

// FromTrace renders one agent run as a parent span with a child per step.
//
// The receipt supplies the totals; the trace supplies the sequence. Both are
// needed: a run that did four things in eight steps spent half its budget on
// refusals, and only the per-step view says which.
func FromTrace(t agent.Trace, r agent.Receipt, m agent.Manifest,
	start time.Time) ([]Span, error) {

	traceID, err := NewTraceID()
	if err != nil {
		return nil, err
	}
	rootID, err := NewSpanID()
	if err != nil {
		return nil, err
	}

	end := start
	spans := make([]Span, 0, len(t.Steps)+1)

	// Children first, so the root's end time is the last step's.
	for i, st := range t.Steps {
		id, serr := NewSpanID()
		if serr != nil {
			return nil, serr
		}
		// The step's own timestamp. Steps are recorded in order and each
		// carries when it happened, so a span covers from this step to the
		// next — which is the interval somebody is actually looking at when
		// they ask which step was slow.
		at := st.At
		if at.IsZero() {
			at = start
		}
		stop := at
		if i+1 < len(t.Steps) && !t.Steps[i+1].At.IsZero() {
			stop = t.Steps[i+1].At
		}
		// What the step called: one of Quilzo's own operations, or a tool
		// on another system an integration reaches.
		tool, toolType := st.Action.Op, "function"
		if st.Action.Tool != "" {
			tool, toolType = st.Action.Tool, "extension"
		}
		s := Span{
			TraceID: traceID, SpanID: id, ParentID: rootID,
			Name: "execute_tool " + tool, Kind: KindInternal,
			Start: at, End: stop,
			Attrs: []Attr{
				String("gen_ai.operation.name", "execute_tool"),
				String("gen_ai.tool.name", tool),
				String("gen_ai.tool.type", toolType),
				String("gen_ai.tool.call.id", fmt.Sprintf("%s-%d", rootID, st.N)),
				Int("quilzo.step.n", int64(st.N)),
				String("quilzo.step.op", st.Action.Op),
			},
		}
		if st.Action.Tool != "" {
			s.Attrs = append(s.Attrs, String("quilzo.step.tool", st.Action.Tool))
		}
		switch {
		case !st.Allowed:
			// The attribute that matters most on this whole trace: a refusal
			// is the gate working, not an error, and a backend that shows it
			// as a failure teaches operators to silence it.
			s.Attrs = append(s.Attrs, Bool("quilzo.step.refused", true))
			s.StatusCode = StatusUnset
			s.StatusMsg = st.Why
		case st.Err != "":
			s.StatusCode = StatusError
			s.StatusMsg = st.Err
			s.Attrs = append(s.Attrs, String("error.type", "tool_error"))
		default:
			s.StatusCode = StatusOK
		}
		spans = append(spans, s)
		if stop.After(end) {
			end = stop
		}
	}

	root := Span{
		TraceID: traceID, SpanID: rootID,
		Name: "invoke_agent " + m.Name, Kind: KindInternal,
		Start: start, End: end,
		Attrs: []Attr{
			String("gen_ai.operation.name", "invoke_agent"),
			String("gen_ai.agent.name", m.Name),
			String("gen_ai.agent.id", "quilzo/agent/"+m.Name),
			String("gen_ai.provider.name", "quilzo"),
			String("quilzo.agent", m.Name),
			String("quilzo.agent.kind", string(m.Kind)),
			String("quilzo.agent.autonomy", string(m.Autonomy)),
			// What it cost, so a bill can be attributed without joining
			// against anything.
			Int("quilzo.did", int64(r.Did)),
			Int("quilzo.refused", int64(r.Refused)),
			Int("quilzo.failed", int64(r.Failed)),
			Int("quilzo.steps.spent", int64(r.Spend.Steps)),
			Int("quilzo.steps.budget", int64(m.Budget.Steps)),
			Int("quilzo.tools.spent", int64(r.Spend.Tools)),
			Int("quilzo.tokens.reported", int64(r.Spend.Tokens)),
			// Reported by a provider, not measured here. The distinction is
			// on the span because a billing number nobody can source is a
			// number nobody should trust.
			Bool("quilzo.tokens.metered", r.Spend.Metered),
			// The CaMeL property. A run downstream of untrusted content
			// cannot publish itself, and this is the field somebody filters
			// on when asking which runs needed a person.
			Bool("quilzo.tainted", r.Tainted),
		},
	}
	if billable, _ := r.Billable(); !billable {
		root.Attrs = append(root.Attrs, Bool("quilzo.billable", false))
	}
	if r.Refused > 0 {
		// Unset, not Error. A run that was refused things did what it was
		// designed to do.
		root.StatusCode = StatusUnset
		root.StatusMsg = fmt.Sprintf("%d refused", r.Refused)
	} else if r.Failed > 0 {
		root.StatusCode = StatusError
		root.Attrs = append(root.Attrs, String("error.type", "tool_error"))
	} else {
		root.StatusCode = StatusOK
	}

	// Root first, which is the order a collector expects to see a parent in.
	return append([]Span{root}, spans...), nil
}
