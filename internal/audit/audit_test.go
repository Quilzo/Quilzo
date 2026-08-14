package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An audit log fails silently and is believed anyway. So these lean on the two
// ways that happens: a record with a hole in it that gets read as "nothing
// happened", and a tampered log that still verifies.

func newLog(t *testing.T, key []byte) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(Options{Path: path, Key: key, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return l, path
}

func ok(t *testing.T, l *Log, r Record) *Event {
	t.Helper()
	e, err := l.Append(r)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// AU-3 names six things a record must establish. A record missing one is
// refused rather than written, because a log with holes reads as silence.
func TestEveryAU3FieldIsRequired(t *testing.T) {
	l, _ := newLog(t, nil)
	full := Record{
		Action: "publish", Resource: "/blog", Outcome: Success,
		Principal: "sam", Kind: KindHuman,
	}
	if _, err := l.Append(full); err != nil {
		t.Fatalf("a complete record should be accepted: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Record)
		want   string
	}{
		{"no action", func(r *Record) { r.Action = "" }, "what happened"},
		{"no resource", func(r *Record) { r.Resource = "" }, "where"},
		{"no principal", func(r *Record) { r.Principal = "" }, "who"},
		{"no outcome", func(r *Record) { r.Outcome = "" }, "outcome must be"},
		{"no kind", func(r *Record) { r.Kind = "" }, "human, service or ai"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := full
			c.mutate(&r)
			_, err := l.Append(r)
			if err == nil {
				t.Fatal("an incomplete record was accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error should name what is missing, got %q", err)
			}
		})
	}
}

func TestTheThreeKindsOfActorAreDistinguished(t *testing.T) {
	l, _ := newLog(t, nil)
	base := Record{Action: "edit", Resource: "/p", Outcome: Success}

	for _, k := range []Kind{KindHuman, KindService} {
		r := base
		r.Principal, r.Kind = "someone", k
		if _, err := l.Append(r); err != nil {
			t.Errorf("%s should be loggable: %v", k, err)
		}
	}

	// A model must name itself. "An AI did it" without saying which is not a
	// record anybody can act on later.
	r := base
	r.Principal, r.Kind = "assistant", KindAI
	if _, err := l.Append(r); err == nil {
		t.Error("an AI principal with no model should be refused")
	}
	r.Model = "gpt-oss:20b"
	e := ok(t, l, r)
	if e.Kind != KindAI || e.Model != "gpt-oss:20b" {
		t.Errorf("the model should be recorded: %+v", e)
	}
}

func TestDeniedIsNotFailure(t *testing.T) {
	l, path := newLog(t, nil)
	ok(t, l, Record{Action: "publish", Resource: "/", Outcome: Denied,
		Principal: "sam", Kind: KindHuman})

	events, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if events[0].Outcome != Denied {
		t.Error("a refusal should be recorded as denied, not failure")
	}
	// Being refused and breaking are different events, and an auditor chasing
	// attempted access needs to filter for one without the other.
	if Denied == Failure {
		t.Error("denied and failure must be distinct")
	}
}

// -- AU-9: the log must resist its own administrator ------------------------

func TestAnAlteredEntryIsDetected(t *testing.T) {
	l, path := newLog(t, nil)
	for _, a := range []string{"login", "edit", "publish"} {
		ok(t, l, Record{Action: a, Resource: "/", Outcome: Success,
			Principal: "sam", Kind: KindHuman})
	}

	events, _ := Read(path)
	if good, _ := Verify(events); !good {
		t.Fatal("an untouched log should verify")
	}

	// Someone edits the middle entry to change what it says.
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var mid Event
	_ = json.Unmarshal([]byte(lines[1]), &mid)
	mid.Action = "nothing-happened"
	edited, _ := json.Marshal(mid)
	lines[1] = string(edited)
	_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	events, _ = Read(path)
	good, problems := Verify(events)
	if good {
		t.Fatal("an altered entry passed verification")
	}
	if !strings.Contains(problems[0].Reason, "altered") {
		t.Errorf("the problem should say it was altered, got %q", problems[0].Reason)
	}
}

func TestADeletedEntryIsDetected(t *testing.T) {
	l, path := newLog(t, nil)
	for _, a := range []string{"one", "two", "three"} {
		ok(t, l, Record{Action: a, Resource: "/", Outcome: Success,
			Principal: "sam", Kind: KindHuman})
	}

	// Removing an entry is the tamper an append-only file most invites: just
	// delete the line you would rather nobody read.
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	_ = os.WriteFile(path, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)

	events, _ := Read(path)
	good, problems := Verify(events)
	if good {
		t.Fatal("a deleted entry passed verification")
	}
	joined := ""
	for _, p := range problems {
		joined += p.Reason + " "
	}
	if !strings.Contains(joined, "deleted") && !strings.Contains(joined, "removed") {
		t.Errorf("the problem should point at a deletion, got %q", joined)
	}
}

func TestAppendingResumesTheExistingChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l1, _ := New(Options{Path: path, Source: "test"})
	ok(t, l1, Record{Action: "one", Resource: "/", Outcome: Success,
		Principal: "sam", Kind: KindHuman})

	// A restart must continue the chain, not begin a second one.
	l2, err := New(Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ok(t, l2, Record{Action: "two", Resource: "/", Outcome: Success,
		Principal: "sam", Kind: KindHuman})

	events, _ := Read(path)
	if len(events) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(events))
	}
	if good, problems := Verify(events); !good {
		t.Errorf("the chain broke across a restart: %v", problems)
	}
	if events[1].Seq != 2 {
		t.Errorf("sequence should continue, got %d", events[1].Seq)
	}
}

// -- identifiers ------------------------------------------------------------

func TestIdentifiersArePseudonymisedNotStored(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	l, path := newLog(t, key)
	ok(t, l, Record{Action: "publish", Resource: "/", Outcome: Success,
		Principal: "sam@example.com", Kind: KindHuman})

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "sam@example.com") {
		t.Fatal("the identifier is in the log in the clear")
	}

	events, _ := Read(path)
	if !strings.HasPrefix(events[0].Principal, "p_") {
		t.Errorf("expected a pseudonym, got %q", events[0].Principal)
	}
	// Stable, or behaviour cannot be followed across entries.
	ok(t, l, Record{Action: "edit", Resource: "/", Outcome: Success,
		Principal: "sam@example.com", Kind: KindHuman})
	events, _ = Read(path)
	if events[0].Principal != events[1].Principal {
		t.Error("the same person should get the same pseudonym")
	}
	// And re-identifiable by someone holding the key.
	if !l.Matches(events[0].Principal, "sam@example.com") {
		t.Error("the key holder should be able to confirm an identity")
	}
	if l.Matches(events[0].Principal, "someone-else@example.com") {
		t.Error("a different identifier must not match")
	}
}

// The reason this uses HMAC rather than a bare hash: a plain SHA-256 of a
// low-entropy identifier is recovered by guessing, so a log of hashes is a log
// of identifiers with extra steps.
func TestPseudonymsAreNotGuessableWithoutTheKey(t *testing.T) {
	key, _ := NewKey()
	a, _ := New(Options{Path: filepath.Join(t.TempDir(), "a"), Key: key, Source: "t"})
	b, _ := New(Options{Path: filepath.Join(t.TempDir(), "b"), Key: []byte("different"), Source: "t"})

	if a.pseudonym("sam") == b.pseudonym("sam") {
		t.Error("the same identifier under different keys must not collide")
	}
	// Nothing derived from the identifier alone appears in the pseudonym.
	if strings.Contains(a.pseudonym("sam"), "sam") {
		t.Error("the pseudonym leaks the identifier")
	}
}

func TestWithoutAKeyTheModeIsVisible(t *testing.T) {
	l, _ := newLog(t, nil)
	if l.Pseudonymous() {
		t.Error("with no key, the log should report that it is not pseudonymous")
	}
	keyed, _ := newLog(t, []byte("k"))
	if !keyed.Pseudonymous() {
		t.Error("with a key, it should report that it is")
	}
}

// Redaction is for values that must be recorded but not read. A credential is
// not one of those.
func TestSecretsAndContentAreRefusedOutright(t *testing.T) {
	l, _ := newLog(t, nil)
	for _, key := range []string{"token", "api_key", "password", "body", "content", "Secret"} {
		_, err := l.Append(Record{
			Action: "x", Resource: "/", Outcome: Success,
			Principal: "sam", Kind: KindHuman,
			Detail: map[string]string{key: "whatever"},
		})
		if err == nil {
			t.Errorf("detail key %q should be refused", key)
		}
	}
	// Ordinary detail still works.
	if _, err := l.Append(Record{
		Action: "publish", Resource: "/", Outcome: Success,
		Principal: "sam", Kind: KindHuman,
		Detail: map[string]string{"changes": "3", "rule": "one-way-doors"},
	}); err != nil {
		t.Errorf("harmless detail should be allowed: %v", err)
	}
}

func TestAMalformedLineIsReportedNotSkipped(t *testing.T) {
	l, path := newLog(t, nil)
	ok(t, l, Record{Action: "one", Resource: "/", Outcome: Success,
		Principal: "sam", Kind: KindHuman})

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("{not json\n")
	_ = f.Close()

	// Skipping quietly is how a tampered log passes review.
	if _, err := Read(path); err == nil {
		t.Error("an unreadable entry should be an error, not silently dropped")
	}
}

func TestSourceIsRequired(t *testing.T) {
	if _, err := New(Options{Path: filepath.Join(t.TempDir(), "a")}); err == nil {
		t.Error("AU-3 requires a source on every record, so a log needs one")
	}
}
