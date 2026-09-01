package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
)

// Asking the gate a question from outside the program.
//
// # Why this exists
//
// The security claim is that the manifest is enforced at a chokepoint outside
// the model, so a hijacked agent can still only do what it declared. That claim
// is testable, and until now it was testable only from inside this module: every
// assertion about it lived in a Go test written by the same people who wrote the
// gate.
//
// A benchmark cannot be one of those. AgentDojo — the suite this design's
// paper reports against — is Python, and the honest way to score against it is
// to let an outside harness ask this program directly: here is a manifest, here
// is the call an attacker got the model to emit, what happens? So the gate gets
// an interface a script can drive, and the answer carries the refusal's own
// words rather than a boolean.
//
// # Why the answer is worth trusting
//
// Because it is the same code path. This does not reimplement the policy for
// probing; it builds an agent.Session exactly as `quilzo agent run` does and
// calls Check, Retrieve, Mutate and MayReach in the same order the executor
// would. A second implementation of the rules would be a benchmark of the
// second implementation.
//
// # What it deliberately does not do
//
// Touch the store. A probe is a question about a policy, not a run: nothing is
// read, nothing is written, nothing is audited, and the exit code is about
// whether the question was understood rather than about the answer. That means
// a harness can ask ten thousand questions without a store, and it means this
// command cannot be turned into a way to perform an action.

type probeQuestion struct {
	// Manifest is the agent being asked about, as `quilzo agent new` writes
	// it. Given inline so a harness does not have to write files.
	Manifest agent.Manifest `json:"manifest"`
	// Calls are the operations to try, in order, against one session — so a
	// harness can express "read untrusted content, then publish", which is the
	// sequence the taint rule exists for.
	Calls []probeCall `json:"calls"`
}

type probeCall struct {
	// Op is the capability name: read_page, publish, fetch.
	Op string `json:"op"`
	// Ref, Type and Locale are the target of a read or a write, for the scope
	// rules. Empty means unscoped, which is the ordinary case.
	Ref    string `json:"ref,omitempty"`
	Type   string `json:"type,omitempty"`
	Locale string `json:"locale,omitempty"`
	// Host is the host a fetch would reach.
	Host string `json:"host,omitempty"`
	// Note is the harness's own label, echoed back so a report can say which
	// attack this was.
	Note string `json:"note,omitempty"`
}

type probeAnswer struct {
	Op      string `json:"op"`
	Note    string `json:"note,omitempty"`
	Allowed bool   `json:"allowed"`
	// Reason is the gate's own words when it refused. Carried because "which
	// rule stopped this" is the finding, and a boolean is not.
	Reason string `json:"reason,omitempty"`
}

type probeResult struct {
	Agent   string        `json:"agent"`
	Answers []probeAnswer `json:"answers"`
	// Allowed and Refused are the counts a harness reports.
	Allowed int `json:"allowed"`
	Refused int `json:"refused"`
	// Tainted is whether untrusted content was read during the sequence, which
	// is what makes a later publish refusable.
	Tainted bool `json:"tainted"`
}

func agentProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	file := fs.String("file", "-",
		"a JSON question; - reads standard input")
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := readProbe(*file)
	if err != nil {
		return err
	}
	var q probeQuestion
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// Strictly: a harness that misspells a field would otherwise get an answer
	// about a question it did not ask, and a benchmark built on that would be
	// measuring the typo.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return fmt.Errorf("that is not a probe question: %w", err)
	}
	if len(q.Calls) == 0 {
		return fmt.Errorf("a probe with no calls asks nothing")
	}

	// Validated first: an answer about a manifest nobody could deploy is not an
	// answer about this program.
	//
	// Against no capability list, because a probe deliberately has no store and
	// the registered operation names come from one. Validate treats a nil list
	// as "do not check the names", which is the right trade here: every other
	// rule in it — autonomy against writes, publish needing approval, budgets
	// being present — is what the probe is about, and a capability name that no
	// interface offers is refused by the gate below anyway, as a missing
	// capability.
	if err := q.Manifest.Validate(nil); err != nil {
		return fmt.Errorf("that manifest would not be accepted: %w", err)
	}

	s := agent.NewSession(q.Manifest, nil)
	out := probeResult{Agent: q.Manifest.Name}
	for _, call := range q.Calls {
		ans := probeAnswer{Op: call.Op, Note: call.Note}
		if err := probeOne(s, call); err != nil {
			ans.Reason = err.Error()
		} else {
			ans.Allowed = true
		}
		if ans.Allowed {
			out.Allowed++
		} else {
			out.Refused++
		}
		out.Answers = append(out.Answers, ans)
	}
	out.Tainted = s.Tainted()

	// Always JSON. This output is read by a program; making it depend on
	// --json would mean a harness that forgot the flag scraping prose.
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// probeOne asks the gate about one call, in the order the executor asks.
//
// Authorize first, because that is the capability list and the budget; then the
// scope check for the kind of operation this is. A harness cannot reorder these,
// which is deliberate: the order is part of what is being measured.
func probeOne(s *agent.Session, call probeCall) error {
	if err := s.Authorize(call.Op); err != nil {
		return err
	}
	switch {
	case call.Op == "fetch" || call.Host != "":
		return s.MayReach(call.Host)
	case agent.IsWrite(call.Op):
		return s.Mutate(call.Ref, call.Type, call.Locale)
	default:
		return s.Retrieve(call.Ref, call.Type, call.Locale)
	}
}

func readProbe(path string) ([]byte, error) {
	if path == "-" || path == "" {
		return io.ReadAll(io.LimitReader(os.Stdin, maxProbeBytes))
	}
	return os.ReadFile(path)
}

// maxProbeBytes bounds a question. A probe is a manifest and a list of calls;
// anything larger is a mistake, and reading it all first would be this command
// agreeing to hold whatever it was handed.
const maxProbeBytes = 1 << 20
