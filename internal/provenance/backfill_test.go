package provenance_test

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/provenance"
)

const (
	hAbout = "aaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
	hIndex = "bbbb111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
	hNews  = "cccc111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
)

func appearance(page, hash, commit, msg, author string, at int64) provenance.Appearance {
	return provenance.Appearance{
		Page: page, ContentHash: hash, Commit: commit,
		Message: msg, Author: author, At: at,
	}
}

// The rule the whole design rests on: an absence of evidence is never written
// down as human authorship.
//
// A page with no record and nothing in its history is a page whose provenance
// is unknown. Recording "a person wrote this" to clear a report is the exact
// inversion of what a transparency obligation asks for, and the mark exists to
// be believed.
func TestNoEvidenceIsNeverRecordedAsHumanAuthorship(t *testing.T) {
	plan := provenance.BuildPlan(
		map[string]string{"about": hAbout},
		[]provenance.Appearance{
			appearance("about", hAbout, "c1", "add the about page", "dana", 100),
		},
		provenance.NewIndex(), 500)

	if len(plan.Undecidable) != 1 {
		t.Fatalf("a page with no evidence produced %d undecidable, %d inferred, "+
			"%d recorded", len(plan.Undecidable), len(plan.Inferred),
			len(plan.Recorded))
	}
	// And nothing is written for it.
	idx := provenance.NewIndex()
	if n, err := plan.Apply(idx); err != nil || n != 0 {
		t.Fatalf("Apply wrote %d record(s) (err %v); undecidable pages must "+
			"get none", n, err)
	}
	if _, ok := idx.Get("about"); ok {
		t.Error("an undecidable page got a record, so absence of evidence " +
			"became a claim")
	}
	// The report has to say what was looked at, or "undecidable" is a shrug.
	why := plan.Undecidable[0].Why
	if !strings.Contains(why, "absence of evidence") {
		t.Errorf("the reason does not distinguish absence of evidence from "+
			"evidence of human authorship: %q", why)
	}
}

// A machine prefix is real evidence, and the inference is worth making.
func TestAMachineWrittenCommitIsInferred(t *testing.T) {
	plan := provenance.BuildPlan(
		map[string]string{"news": hNews},
		[]provenance.Appearance{
			appearance("news", hNews, "c9", "assist: write a launch note", "dana", 100),
		},
		provenance.NewIndex(), 500)

	if len(plan.Inferred) != 1 {
		t.Fatalf("got %d inferred, %d undecidable", len(plan.Inferred),
			len(plan.Undecidable))
	}
	p := plan.Inferred[0]
	if p.Record.SourceType != provenance.TrainedAlgorithmicMedia {
		t.Errorf("source type is %q, want trainedAlgorithmicMedia",
			p.Record.SourceType)
	}
	if p.Record.ContentHash != hNews {
		t.Errorf("the record is bound to %q, not the content it describes",
			p.Record.ContentHash)
	}
	if !p.Record.SourceType.RequiresDisclosure() {
		t.Error("the inferred type does not require disclosure, which is the " +
			"whole point of marking it")
	}
}

// An inferred record must not look like an observed one. Somebody auditing the
// mark has to be able to follow it back to what it was inferred from.
func TestAnInferredRecordSaysItWasInferredAndFromWhat(t *testing.T) {
	plan := provenance.BuildPlan(
		map[string]string{"news": hNews},
		[]provenance.Appearance{
			appearance("news", hNews, "abcdef123456789", "agent: draft the notice", "bot", 100),
		},
		provenance.NewIndex(), 500)

	note := plan.Inferred[0].Record.Note
	for _, want := range []string{"inferred", "abcdef123456"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note does not contain %q, so the mark cannot be "+
				"audited: %q", want, note)
		}
	}
	// The Article 50 assistive exemption is a judgement this cannot make from a
	// truncated instruction, and the record has to say so rather than let the
	// type imply an answer either way.
	if !strings.Contains(note, "NOT been assessed") {
		t.Errorf("the note does not flag that the assistive-editing exemption "+
			"was not assessed: %q", note)
	}
	if ev := plan.Inferred[0].Evidence; !strings.Contains(ev, "agent: ") {
		t.Errorf("the evidence does not name the prefix it relied on: %q", ev)
	}
}

// A record describing different bytes is evidence about those bytes. Treating
// it as covering the current content is the error the hash binding exists to
// prevent.
func TestAStaleRecordDoesNotCountAsRecorded(t *testing.T) {
	idx := provenance.NewIndex()
	if err := idx.Set("about", provenance.Record{
		ContentHash: hIndex, SourceType: provenance.HumanEdits,
		Author: "dana", At: 1,
	}); err != nil {
		t.Fatal(err)
	}

	plan := provenance.BuildPlan(
		map[string]string{"about": hAbout},
		[]provenance.Appearance{
			appearance("about", hAbout, "c2", "assist: rewrite it", "dana", 200),
		},
		idx, 500)

	if len(plan.Recorded) != 0 {
		t.Fatalf("a record naming different bytes was counted as recorded")
	}
	if len(plan.Inferred) != 1 {
		t.Fatalf("got %d inferred", len(plan.Inferred))
	}
}

// Content already bound to a record is left exactly alone. A backfill that
// overwrote observed provenance with an inference would destroy the better
// evidence to satisfy a report.
func TestAnExistingRecordIsNotOverwritten(t *testing.T) {
	idx := provenance.NewIndex()
	original := provenance.Record{
		ContentHash: hNews, SourceType: provenance.HumanEdits,
		Author: "dana", At: 1, Note: "written at the desk",
	}
	if err := idx.Set("news", original); err != nil {
		t.Fatal(err)
	}

	plan := provenance.BuildPlan(
		map[string]string{"news": hNews},
		[]provenance.Appearance{
			// History says a machine touched it, but a person recorded
			// otherwise at the time. The record wins: it was observed.
			appearance("news", hNews, "c3", "assist: tidy", "dana", 100),
		},
		idx, 500)

	if len(plan.Recorded) != 1 || len(plan.Inferred) != 0 {
		t.Fatalf("recorded %d, inferred %d — an observed record must win over "+
			"an inference", len(plan.Recorded), len(plan.Inferred))
	}
	if _, err := plan.Apply(idx); err != nil {
		t.Fatal(err)
	}
	back, _ := idx.Get("news")
	if back.Note != original.Note || back.SourceType != original.SourceType {
		t.Errorf("the existing record was changed: %+v", back)
	}
}

// The earliest machine commit is the one that produced the bytes. A later
// commit carrying them forward did not.
func TestTheEarliestMachineCommitIsTheEvidence(t *testing.T) {
	plan := provenance.BuildPlan(
		map[string]string{"news": hNews},
		[]provenance.Appearance{
			appearance("news", hNews, "later0000000", "mcp: republish", "bot", 900),
			appearance("news", hNews, "first0000000", "assist: write it", "dana", 100),
		},
		provenance.NewIndex(), 500)

	if len(plan.Inferred) != 1 {
		t.Fatalf("got %d inferred", len(plan.Inferred))
	}
	if ev := plan.Inferred[0].Evidence; !strings.Contains(ev, "first0000000") {
		t.Errorf("the evidence cites %q; the earliest machine commit is what "+
			"produced the bytes", ev)
	}
}

// Every page in the current tree lands in exactly one bucket, and the total is
// reported. A plan that examined nothing produces no proposals and looks
// exactly like a plan that found nothing to do.
func TestEveryPageIsAccountedForExactlyOnce(t *testing.T) {
	current := map[string]string{"about": hAbout, "index": hIndex, "news": hNews}
	idx := provenance.NewIndex()
	if err := idx.Set("index", provenance.Record{
		ContentHash: hIndex, SourceType: provenance.HumanEdits,
		Author: "dana", At: 1,
	}); err != nil {
		t.Fatal(err)
	}

	plan := provenance.BuildPlan(current, []provenance.Appearance{
		appearance("about", hAbout, "c1", "add about", "dana", 100),
		appearance("index", hIndex, "c2", "add index", "dana", 100),
		appearance("news", hNews, "c3", "assist: write it", "dana", 100),
	}, idx, 500)

	if plan.Total() != len(current) {
		t.Fatalf("plan accounts for %d pages, the tree has %d",
			plan.Total(), len(current))
	}
	if len(plan.Recorded) != 1 || len(plan.Inferred) != 1 ||
		len(plan.Undecidable) != 1 {
		t.Errorf("recorded %d, inferred %d, undecidable %d; want one each",
			len(plan.Recorded), len(plan.Inferred), len(plan.Undecidable))
	}
}

// A prefix appearing mid-message is not a machine write. "we should assist: "
// in prose would otherwise mark a page a person wrote.
func TestAPrefixOnlyCountsAtTheStart(t *testing.T) {
	plan := provenance.BuildPlan(
		map[string]string{"about": hAbout},
		[]provenance.Appearance{
			appearance("about", hAbout, "c1",
				"note that we should assist: users better", "dana", 100),
		},
		provenance.NewIndex(), 500)

	if len(plan.Inferred) != 0 {
		t.Errorf("a message merely containing a prefix was treated as a " +
			"machine write")
	}
}

// Applying twice changes nothing the second time.
func TestApplyingAPlanTwiceIsStable(t *testing.T) {
	current := map[string]string{"news": hNews}
	history := []provenance.Appearance{
		appearance("news", hNews, "c1", "assist: write it", "dana", 100),
	}
	idx := provenance.NewIndex()

	n, err := provenance.BuildPlan(current, history, idx, 500).Apply(idx)
	if err != nil || n != 1 {
		t.Fatalf("first apply wrote %d (err %v)", n, err)
	}
	second := provenance.BuildPlan(current, history, idx, 600)
	if len(second.Inferred) != 0 || len(second.Recorded) != 1 {
		t.Errorf("a second pass wants to write again: inferred %d, recorded %d",
			len(second.Inferred), len(second.Recorded))
	}
}
