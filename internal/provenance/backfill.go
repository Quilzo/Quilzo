package provenance

import (
	"fmt"
	"sort"
	"strings"
)

// Marking content that was published before anybody was recording provenance.
//
// # The deadline
//
// Article 50's marking obligation applied to new output from 2 August 2026.
// From 2 December 2026 it covers content generated before that date as well.
// Provenance has been recorded per commit for a while, so for recent content
// the answer is written down. For anything older it is not, and the whole
// difficulty is in what to do about that.
//
// # The rule this refuses to break
//
// An absence of evidence is never written down as human authorship.
//
// That is the single decision the rest follows from. A page with no record is
// a page whose provenance is unknown, and "unknown" recorded as "a person
// wrote this" is worse than no record at all: the mark exists to be believed,
// and a false negative is the failure that matters. Article 50 is a
// transparency obligation, and quietly asserting human authorship to clear a
// report is the opposite of transparency.
//
// So a backfill has three outcomes and never two. Already recorded. Inferred,
// with the evidence named. Undecidable, reported and left alone.
//
// # Why an inference is still an inference
//
// The only evidence surviving in an old commit is its message. Assistant
// writes are prefixed "assist: ", agent writes "agent: ", machine-interface
// writes "mcp: ". That is real evidence and it is also forgeable: a person can
// type those characters, and a project could have used the prefix for
// something else entirely.
//
// So an inferred record says so, in its Note, naming the commit it was
// inferred from. Somebody auditing the mark can follow it back. A record that
// looked identical to an observed one would be a record that overstates what
// was known, and the point of binding provenance to a content hash was to stop
// exactly that.
//
// # What this deliberately does not decide
//
// Article 50 exempts output where the model "performs an assistive function
// for standard editing or does not substantially alter the input data or its
// semantics". Fixing a typo is assistive; writing the page is not.
//
// A truncated instruction in a commit message is not enough to tell those
// apart, and guessing would devalue the mark on the pages that need it. So an
// inferred record carries the instruction verbatim where it survives, says the
// exemption was not assessed, and leaves that judgement to a person.
//
// # Nothing is mutated
//
// The store is append-only and content-addressed, so marking existing content
// cannot mean editing it. A backfill writes new provenance records that name
// content hashes that already exist. If a design here required changing a
// stored object it would be the wrong design.

// Prefixes that a machine wrote a commit.
//
// Kept here rather than imported from the packages that write them: this list
// is evidence about history, and it has to keep describing prefixes that were
// used in the past even if a package stops using one tomorrow. A constant that
// tracks current behaviour is the wrong shape for reading old commits.
var machinePrefixes = []struct {
	Prefix string
	What   string
}{
	{"assist: ", "the built-in assistant"},
	{"agent: ", "an autonomous agent"},
	{"mcp: ", "the machine interface"},
}

// Verdict is what could be established about one page.
type Verdict string

const (
	// AlreadyRecorded: a record exists and is bound to this exact content.
	AlreadyRecorded Verdict = "recorded"
	// Inferred: no record, but the history says a machine wrote it.
	Inferred Verdict = "inferred"
	// Undecidable: no record and nothing in the history settles it. Reported,
	// never guessed, and never written down as human authorship.
	Undecidable Verdict = "undecidable"
)

// Appearance is one page as it existed at one commit.
//
// The evidence, gathered by walking history. A page that was published and
// later replaced still went out under the old rules, so its commit is worth
// reading even though the content is no longer served.
type Appearance struct {
	Page        string
	ContentHash string
	Commit      string
	Message     string
	Author      string
	At          int64
}

// Proposal is one record a backfill would write.
type Proposal struct {
	Page    string
	Verdict Verdict
	Record  Record
	// Evidence says what made this decidable, in words somebody can check.
	// Empty when nothing did.
	Evidence string
	// Why explains an undecidable verdict.
	Why string
}

// Plan is the outcome of a backfill, before anything is written.
type Plan struct {
	Recorded    []Proposal
	Inferred    []Proposal
	Undecidable []Proposal
}

// Total is how many pages were considered.
//
// Reported because a plan that examined nothing produces no proposals and
// looks exactly like a plan that found nothing to do.
func (p Plan) Total() int {
	return len(p.Recorded) + len(p.Inferred) + len(p.Undecidable)
}

// BuildPlan decides what a backfill would do, and writes nothing.
//
// `current` maps page name to the object id being served now — that is what
// carries an obligation, because Article 50 is about content made available to
// people. `history` is every appearance of every page, used only as evidence.
func BuildPlan(current map[string]string, history []Appearance, idx *Index,
	now int64) Plan {

	// Evidence indexed by the content hash it concerns. A hash rather than a
	// page name, because a page renamed or restored still has the same bytes,
	// and the bytes are what a provenance record names.
	byHash := map[string][]Appearance{}
	for _, a := range history {
		byHash[a.ContentHash] = append(byHash[a.ContentHash], a)
	}
	for h := range byHash {
		as := byHash[h]
		sort.SliceStable(as, func(i, j int) bool { return as[i].At < as[j].At })
	}

	names := make([]string, 0, len(current))
	for n := range current {
		names = append(names, n)
	}
	sort.Strings(names)

	var plan Plan
	for _, name := range names {
		hash := current[name]

		// An existing record counts only when it is bound to these bytes. One
		// describing an older version is evidence about that version, and
		// treating it as covering this one is the error the hash binding
		// exists to prevent.
		if r, ok := idx.Get(name); ok && r.ContentHash == hash {
			plan.Recorded = append(plan.Recorded, Proposal{
				Page: name, Verdict: AlreadyRecorded, Record: r,
				Evidence: "a record already names this content",
			})
			continue
		}

		if a, what, ok := machineWrote(byHash[hash]); ok {
			plan.Inferred = append(plan.Inferred, Proposal{
				Page: name, Verdict: Inferred,
				Record: Record{
					ContentHash: hash,
					// The model wrote it. Whether the assistive exemption
					// applies is a judgement this cannot make, and the note
					// says so rather than the type quietly implying either
					// answer.
					SourceType: TrainedAlgorithmicMedia,
					Author:     a.Author,
					At:         now,
					Note: fmt.Sprintf(
						"inferred at backfill from commit %s (%q), written by "+
							"%s. Not observed at the time of writing. The "+
							"Article 50 assistive-editing exemption has NOT "+
							"been assessed: review and re-record if this was "+
							"an edit rather than authorship.",
						short(a.Commit), a.Message, what),
				},
				Evidence: fmt.Sprintf("commit %s begins %q, which is how %s "+
					"identifies its writes", short(a.Commit),
					prefixOf(a.Message), what),
			})
			continue
		}

		plan.Undecidable = append(plan.Undecidable, Proposal{
			Page: name, Verdict: Undecidable,
			Why: whyUndecidable(byHash[hash]),
		})
	}
	return plan
}

// machineWrote reports whether any appearance of this content was written by a
// machine, and which one.
//
// The earliest such appearance wins. The question is who produced the bytes,
// and a later commit that merely carried them forward is not that.
func machineWrote(as []Appearance) (Appearance, string, bool) {
	for _, a := range as {
		for _, p := range machinePrefixes {
			if strings.HasPrefix(a.Message, p.Prefix) {
				return a, p.What, true
			}
		}
	}
	return Appearance{}, "", false
}

func prefixOf(message string) string {
	for _, p := range machinePrefixes {
		if strings.HasPrefix(message, p.Prefix) {
			return p.Prefix
		}
	}
	return ""
}

// whyUndecidable says what was looked at, so "undecidable" is a finding rather
// than a shrug.
func whyUndecidable(as []Appearance) string {
	if len(as) == 0 {
		return "this content appears in no commit that could be read, so " +
			"there is nothing to infer from. It may predate the history that " +
			"survives."
	}
	commits := make([]string, 0, len(as))
	for _, a := range as {
		commits = append(commits, short(a.Commit))
		if len(commits) == 3 {
			break
		}
	}
	return fmt.Sprintf(
		"%d commit(s) carry this content (%s) and none was written through a "+
			"machine interface. That is not evidence a person wrote it — it "+
			"is the absence of evidence either way, and it is left unrecorded "+
			"rather than recorded as human authorship.",
		len(as), strings.Join(commits, ", "))
}

// Apply writes the inferred records into an index.
//
// Only the inferred ones. Already-recorded pages are left exactly as they are,
// and undecidable pages are left with no record at all, which is the state
// that honestly describes them.
func (p Plan) Apply(idx *Index) (int, error) {
	n := 0
	for _, prop := range p.Inferred {
		if err := idx.Set(prop.Page, prop.Record); err != nil {
			return n, fmt.Errorf("%s: %w", prop.Page, err)
		}
		n++
	}
	return n, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
