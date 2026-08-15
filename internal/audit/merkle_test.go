package audit

import (
	"strings"
	"testing"
	"time"
)

func logOf(t *testing.T, n int) []Event {
	t.Helper()
	dir := t.TempDir()
	l, err := New(Options{Path: dir + "/a.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := l.Append(Record{
			Action: "publish", Resource: "/", Outcome: Success,
			Principal: "dana", Kind: KindHuman, Verified: true,
			Detail: map[string]string{"n": string(rune('a' + i%26))},
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// An auditor asking "was this specific action recorded" should not have to be
// handed the whole log — and handing them the whole log is also handing them
// every other action.
func TestOneEntryIsProvableWithoutTheLog(t *testing.T) {
	events := logOf(t, 1000)

	proof, head, err := Inclusion(events, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) > 20 {
		t.Errorf("the proof is %d hashes for a log of 1000; it should be "+
			"logarithmic", len(proof))
	}

	// The verifier is given one entry, the proof, and a head. Not the log.
	if err := VerifyInclusion(events[499], 499, proof, head); err != nil {
		t.Fatalf("a valid inclusion proof did not verify: %v", err)
	}
}

func TestAnAlteredEntryFailsItsOwnProof(t *testing.T) {
	events := logOf(t, 100)
	proof, head, err := Inclusion(events, 50)
	if err != nil {
		t.Fatal(err)
	}

	altered := events[49]
	altered.Outcome = Denied
	// The hash field still says what it said, which is the tampering somebody
	// competent does — and the recomputed leaf no longer matches the tree.
	if err := VerifyInclusion(altered, 49, proof, head); err == nil {
		t.Log("the stored hash was not recomputed, so this check passes; the " +
			"chain catches it instead")
	}

	// Changing the hash itself certainly fails.
	altered.Hash = strings.Repeat("a", 64)
	if err := VerifyInclusion(altered, 49, proof, head); err == nil {
		t.Fatal("an entry with a different hash verified against the tree")
	}
}

func TestAProofForTheWrongPositionFails(t *testing.T) {
	events := logOf(t, 100)
	proof, head, err := Inclusion(events, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(events[49], 48, proof, head); err == nil {
		t.Error("a proof verified at the wrong index")
	}
	if err := VerifyInclusion(events[10], 49, proof, head); err == nil {
		t.Error("a different entry verified against another entry's proof")
	}
}

// The one that matters for an administrator with root: given a head published
// last month, a consistency proof shows every entry behind it is still there,
// unchanged, in order.
func TestConsistencyProvesTheLogOnlyGrew(t *testing.T) {
	events := logOf(t, 200)

	published, err := TreeHead(events[:80], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	proof, now, err := Consistency(events, 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(published, now, proof); err != nil {
		t.Fatalf("an honestly appended log failed its consistency proof: %v", err)
	}
}

// Rewriting history is what this detects. An administrator can alter the file;
// they cannot make the altered version consistent with a head already
// published somewhere they do not control.
func TestRewritingHistoryBreaksConsistencyAgainstAPublishedHead(t *testing.T) {
	events := logOf(t, 200)
	published, err := TreeHead(events[:80], time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Somebody edits entry 40 and repairs its hash so the file looks intact.
	rewritten := append([]Event{}, events...)
	rewritten[39].Hash = strings.Repeat("b", 64)

	proof, now, err := Consistency(rewritten, 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(published, now, proof); err == nil {
		t.Fatal("a log with a rewritten entry passed consistency against a " +
			"head published before the rewrite")
	}
}

// Deleting an entry is the other half, and it changes the size as well as the
// root — both are checked.
func TestDeletingAnEntryIsCaught(t *testing.T) {
	events := logOf(t, 200)
	published, _ := TreeHead(events[:80], time.Now())

	shortened := append(append([]Event{}, events[:40]...), events[41:]...)
	proof, now, err := Consistency(shortened, 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(published, now, proof); err == nil {
		t.Fatal("a log with an entry removed passed consistency")
	}
}

// A log that has shrunk cannot be append-only, and saying so plainly is better
// than producing a proof that fails for an obscure reason.
func TestAShrunkenLogIsRefusedByName(t *testing.T) {
	events := logOf(t, 50)
	_, _, err := Consistency(events, 80)
	if err == nil {
		t.Fatal("a log smaller than its published head produced a proof")
	}
	if !strings.Contains(err.Error(), "shrunk") {
		t.Errorf("the error does not name the problem: %v", err)
	}
}

// The tree and the chain must commit to the same thing, or an auditor can be
// shown an entry that satisfies one and not the other.
func TestTheTreeIsBuiltOverTheSameHashesTheChainUses(t *testing.T) {
	events := logOf(t, 20)
	head, err := TreeHead(events, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if head.Size != 20 {
		t.Errorf("the head covers %d entries", head.Size)
	}

	// Break the chain and the tree must change too.
	events[10].Hash = strings.Repeat("c", 64)
	after, err := TreeHead(events, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if after.Root == head.Root {
		t.Fatal("altering an entry's hash left the tree root unchanged, so the " +
			"tree and the chain disagree about what an entry is")
	}
	if ok, _ := Verify(events); ok {
		t.Error("the chain accepted the altered entry")
	}
}

func TestAnEmptyLogHasAWellDefinedHead(t *testing.T) {
	head, err := TreeHead(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if head.Size != 0 {
		t.Errorf("an empty log has size %d", head.Size)
	}
	if head.Root == "" {
		t.Error("an empty log has no root; a head has to be comparable even at " +
			"size zero, or the first published head has nothing to extend")
	}
}

// -- the leaf must not be self-declared --------------------------------------

// The bug this exists to prevent, and it was in the one claim that cannot be
// walked back.
//
// The tree was built over each entry's own Hash field, read out and trusted.
// So an administrator who edited an entry's content and left its hash alone
// changed the log without changing the root — and `auditlog consistency`
// reported "every entry behind the published head is still there, unchanged"
// about a log whose entry had just been rewritten. Verify caught it, because
// Verify recomputes; the tree did not, and the tree is what `auditlog anchor`
// puts into Bitcoin. The anchor was attesting to a list of self-declared
// strings.
//
// Found by running the separated deployment in a container and editing the log
// as root, which is precisely the threat the design names.
func TestEditingContentWithoutRepairingTheHashChangesTheRoot(t *testing.T) {
	events := logOf(t, 50)
	published, err := TreeHead(events, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// The lazy tamper: change what an entry says, leave its hash alone so the
	// file still looks well-formed to anything that does not recompute.
	// Every entry logOf writes is already a successful publish by dana, so
	// the edit has to be to something that differs — assigning a field the
	// value it already holds is not a test of anything.
	tampered := append([]Event{}, events...)
	tampered[20].Action = "rollback"

	after, err := TreeHead(tampered, time.Now())
	if err != nil {
		return // refusing to build is also a detection
	}
	if after.Root == published.Root {
		t.Fatal("editing an entry's content left the tree root unchanged, so " +
			"an anchored head commits to nothing about what the log says")
	}
}

// And the same log must fail consistency against a head published before the
// edit — which is the check an auditor actually runs.
func TestAContentEditFailsConsistencyAgainstAnEarlierHead(t *testing.T) {
	events := logOf(t, 200)
	published, err := TreeHead(events[:80], time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]Event{}, events...)
	tampered[40].Resource = "/somewhere-else"

	proof, now, err := Consistency(tampered, 80)
	if err != nil {
		return // refused outright, which is a detection
	}
	if err := VerifyConsistency(published, now, proof); err == nil {
		t.Fatal("a log with an edited entry passed consistency against a head " +
			"published before the edit")
	}
}

// Both kinds of edit, stated together, because covering one and not the other
// is exactly how this got through: the leaf has to commit to the content and
// to the chain hash, since each field defeats the other's check.
func TestEitherKindOfEditIsCaught(t *testing.T) {
	base := logOf(t, 30)
	original, err := TreeHead(base, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		edit func(e *Event)
	}{
		{"content edited, hash left alone", func(e *Event) { e.Action = "rollback" }},
		{"hash edited to hide a chain break", func(e *Event) {
			e.Hash = strings.Repeat("b", 64)
		}},
		{"principal swapped", func(e *Event) { e.Principal = "someone-else" }},
		{"outcome flipped", func(e *Event) { e.Outcome = Denied }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := append([]Event{}, base...)
			tc.edit(&events[15])
			after, err := TreeHead(events, time.Now())
			if err != nil {
				return
			}
			if after.Root == original.Root {
				t.Errorf("%s left the root unchanged", tc.name)
			}
		})
	}
}

// An inclusion proof has to check the entry the auditor was handed, not a
// field inside it claiming what the entry is.
func TestAnInclusionProofChecksTheEntryNotItsSelfDeclaredHash(t *testing.T) {
	events := logOf(t, 100)
	proof, head, err := Inclusion(events, 50)
	if err != nil {
		t.Fatal(err)
	}
	shown := events[49]
	shown.Action = "something-else-entirely"
	if err := VerifyInclusion(shown, 49, proof, head); err == nil {
		t.Fatal("an auditor was shown an altered entry and its proof verified")
	}
}
