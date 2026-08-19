package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// What an agent run achieved, in a form somebody can be billed for.
//
// # Why a CMS has an opinion about this
//
// The pricing model for agentic software is moving from seats to outcomes —
// per resolved case, per completed transaction, per prevented error — and
// Gartner expects a large share of enterprise spend to follow it. Two facts
// from that market decide the shape of this file.
//
// The first is that 78% of IT leaders reported unexpected charges from
// consumption-based AI features. The complaint is not the price. It is that
// the buyer cannot check the bill.
//
// The second is that outcome-linked contracts are arriving with clawback
// clauses attached. A clawback is a claim that the outcome did not happen, and
// neither side can settle it without a record both of them trust.
//
// So an outcome you cannot prove is not a billable outcome, it is an invoice.
// A receipt is the proof: what the agent was asked, what it did, what it was
// refused, what it cost, and whether it finished — written into the audit log,
// which is hash-chained and can be anchored. Neither party has to trust the
// other's copy, because the log says whether it has been altered.
//
// # Refusals are part of the outcome, not an embarrassment
//
// A run that tried to publish four times and was stopped is a different product
// from one that did the work asked of it, and a buyer paying per outcome is
// entitled to know which they got. Recording refusals is also the only honest
// basis for a clawback conversation: "it was refused eleven times" is a fact
// about the run rather than an argument about it.

// Receipt is the billable, checkable summary of one run.
type Receipt struct {
	Agent string
	Kind  Kind
	Goal  string
	// Complete is whether the agent finished rather than being stopped.
	Complete bool
	// Stopped names why it did not, when it did not.
	Stopped string
	// Did counts the operations that were carried out.
	Did int
	// Refused counts the ones that were not, and Attempted names the distinct
	// operations behind those refusals — "it tried to publish" rather than
	// "eleven refusals".
	Refused   int
	Attempted []string
	// Tainted says the run read stored content, so its output is downstream of
	// input somebody else may have written. A buyer paying for an outcome
	// should know whether a person still has to look.
	Tainted bool
	Spend   Spend
}

// Receipt summarises a run.
func (t Trace) Receipt(s *Session) Receipt {
	r := Receipt{
		Agent: t.Agent, Goal: t.Goal,
		Complete: t.Complete, Stopped: t.Stopped,
		Tainted: t.Tainted, Spend: t.Spent,
	}
	if s != nil {
		r.Kind = s.Manifest().Kind
	}

	seen := map[string]bool{}
	for _, step := range t.Steps {
		if step.Allowed {
			// The finishing step is not work; counting it would bill a caller
			// for the agent saying it was done.
			if !step.Action.Done() {
				r.Did++
			}
			continue
		}
		r.Refused++
		what := step.Action.Op
		if what == "" {
			what = step.Action.Tool
		}
		if what != "" && !seen[what] {
			seen[what] = true
			r.Attempted = append(r.Attempted, what)
		}
	}
	sort.Strings(r.Attempted)
	return r
}

// Detail renders a receipt for the audit log.
//
// Sorted keys and stable formatting, because the log is hash-chained: the same
// run has to produce the same bytes or the record is evidence of nothing. That
// is also why nothing here carries a timestamp — the log stamps its own
// entries, and a second clock inside the payload would make two identical runs
// hash differently for a reason nobody cares about.
func (r Receipt) Detail() map[string]string {
	d := map[string]string{
		"agent":     r.Agent,
		"kind":      string(r.Kind),
		"goal":      r.Goal,
		"complete":  strconv.FormatBool(r.Complete),
		"did":       strconv.Itoa(r.Did),
		"refused":   strconv.Itoa(r.Refused),
		"tainted":   strconv.FormatBool(r.Tainted),
		"steps":     strconv.Itoa(r.Spend.Steps),
		"toolcalls": strconv.Itoa(r.Spend.Tools),
	}
	if r.Stopped != "" {
		d["stopped"] = r.Stopped
	}
	if len(r.Attempted) > 0 {
		d["attempted"] = strings.Join(r.Attempted, " ")
	}
	return d
}

// Billable reports whether this run produced an outcome somebody may be
// charged for, and says why when it did not.
//
// Deliberately strict. A run that did not finish has not produced the thing
// that was bought, and a run that did no work has produced nothing whatever it
// says about itself — charging for either is how consumption billing earned
// its reputation.
//
// Refusals do not make a run unbillable. An agent that overreached and was
// stopped may still have done the work asked of it, and treating every refusal
// as a failed outcome would price the safety controls as defects.
func (r Receipt) Billable() (bool, string) {
	if !r.Complete {
		why := r.Stopped
		if why == "" {
			why = "it did not finish"
		}
		return false, fmt.Sprintf("%s produced no outcome: %s", r.Agent, why)
	}
	if r.Did == 0 {
		return false, fmt.Sprintf(
			"%s finished without doing anything; there is no outcome to charge for",
			r.Agent)
	}
	return true, ""
}

// Fingerprint is a stable hash of the receipt.
//
// So an invoice line can name the run it came from, and the run can be found in
// a log that proves it was not edited afterwards. Computed over the same sorted
// detail that goes into the log, so the two cannot disagree.
func (r Receipt) Fingerprint() string {
	d := r.Detail()
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		// Length-prefixed, so that a value containing a separator cannot be
		// arranged to hash the same as a different pair of fields.
		fmt.Fprintf(h, "%d:%s%d:%s", len(k), k, len(d[k]), d[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}
