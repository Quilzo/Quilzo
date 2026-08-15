package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/audit"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func log(t *testing.T, key []byte, records ...audit.Record) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	l, err := audit.New(audit.Options{
		Path: dir + "/audit.jsonl", Source: "test-host", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		records = []audit.Record{
			{Action: "publish", Resource: "/", Outcome: audit.Success,
				Principal: "dana", Kind: audit.KindHuman, Verified: true},
			{Action: "token.issue", Resource: "/", Outcome: audit.Success,
				Principal: "dana", Kind: audit.KindHuman, Verified: true},
			{Action: "publish", Resource: "/legal", Outcome: audit.Denied,
				Principal: "kit", Kind: audit.KindHuman, Verified: false},
			{Action: "mcp.write_page", Resource: "/news", Outcome: audit.Success,
				Principal: "assistant", Kind: audit.KindAI, Model: "claude",
				Verified: false},
		}
	}
	for _, r := range records {
		if _, err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// -- the evidence surviving the export ---------------------------------------

// A SIEM re-serialises what it ingests, which normally destroys whatever
// integrity the source had. From then on the log is trusted because it is in
// the SIEM rather than because anything checks out.
func TestAnExportCanBeVerifiedWithoutTheOriginal(t *testing.T) {
	events := log(t, nil)
	res, err := Export(JSONL, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}

	// Reconstruct what a receiving system would hold, from the export alone.
	var received []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(res.Body), "\n") {
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		received = append(received, e)
	}
	if err := VerifyEnvelope(received, res.Chain); err != nil {
		t.Fatalf("an untouched export does not verify: %v", err)
	}
}

func TestAlteringAnExportedEventIsDetected(t *testing.T) {
	events := log(t, nil)
	res, err := Export(JSONL, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	altered := append([]audit.Event{}, events...)
	altered[2].Outcome = audit.Success // turn a denial into a success

	err = VerifyEnvelope(altered, res.Chain)
	if err == nil {
		t.Fatal("a denial rewritten as a success passed verification")
	}
	if !strings.Contains(err.Error(), "does not verify") &&
		!strings.Contains(err.Error(), "altered") {
		t.Errorf("detected, but the message does not say what happened: %v", err)
	}
}

// Dropping the inconvenient record is the most likely tampering, and a digest
// over the whole set would catch it without saying which one went.
func TestRemovingAnEventIsDetected(t *testing.T) {
	events := log(t, nil)
	res, err := Export(JSONL, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	shortened := append(append([]audit.Event{}, events[:2]...), events[3:]...)

	if err := VerifyEnvelope(shortened, res.Chain); err == nil {
		t.Fatal("an export with an event removed passed verification")
	}
}

// Exporting a broken chain launders it: from then on the receiving system
// trusts the events because they arrived, not because they check out.
func TestABrokenChainIsNotExportedAtAll(t *testing.T) {
	events := log(t, nil)
	events[1].Action = "something else"

	for _, f := range Formats() {
		if _, err := Export(f, events, Options{}, now); err == nil {
			t.Errorf("%s exported a chain that does not verify", f)
		}
	}
	_, err := Export(JSONL, events, Options{}, now)
	if !strings.Contains(err.Error(), "launder") {
		t.Errorf("the refusal does not explain the consequence: %v", err)
	}
}

// -- privacy -----------------------------------------------------------------

// Pseudonymisation is worth nothing if the export undoes it, and an export is
// exactly where it gets undone — the receiving system asks for usernames and
// somebody adds a flag.
func TestAPseudonymousLogExportsPseudonymously(t *testing.T) {
	key, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	events := log(t, key)

	for _, f := range Formats() {
		res, err := Export(f, events, Options{}, now)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(res.Body, "dana") || strings.Contains(res.Body, "kit") {
			t.Errorf("%s: a real identifier reached the export", f)
		}
		if !res.Redacted {
			t.Errorf("%s: the export does not report itself as redacted", f)
		}
		if !res.Chain.Pseudonymous {
			t.Errorf("%s: the envelope does not tell the receiving system it is "+
				"holding pseudonymous data", f)
		}
	}
}

// Reveal cannot recover what was never stored. A caller passing it on a
// pseudonymous log should not come away believing they have names.
func TestRevealCannotUndoPseudonymisation(t *testing.T) {
	key, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	events := log(t, key)

	res, err := Export(JSONL, events, Options{Reveal: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Body, "dana") {
		t.Error("Reveal produced a name that the log never held; the HMAC is " +
			"one-way and nothing here can invert it")
	}
}

// -- OCSF --------------------------------------------------------------------

func TestOCSFRecordsCarryTheRequiredClassAndCategory(t *testing.T) {
	events := log(t, nil)
	res, err := Export(OCSF, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(res.Body), "\n")
	if len(lines) != len(events) {
		t.Fatalf("%d lines from %d events", len(lines), len(events))
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not JSON: %v", i, err)
		}
		for _, required := range []string{
			"class_uid", "category_uid", "activity_id", "type_uid", "time",
			"severity_id", "status_id", "metadata", "actor",
		} {
			if _, ok := rec[required]; !ok {
				t.Errorf("line %d has no %s, so a SIEM will file it wrongly",
					i, required)
			}
		}
	}
}

// A token issue is authentication; a page write is API activity. Filing them
// under one class makes the authentication dashboard useless.
func TestOCSFClassesDistinguishAuthenticationFromContentChanges(t *testing.T) {
	events := log(t, nil)
	res, _ := Export(OCSF, events, Options{}, now)

	classes := map[string]float64{}
	for _, line := range strings.Split(strings.TrimSpace(res.Body), "\n") {
		var rec map[string]any
		_ = json.Unmarshal([]byte(line), &rec)
		classes[rec["activity_name"].(string)] = rec["class_uid"].(float64)
	}
	if classes["token.issue"] != classAuthentication {
		t.Errorf("token.issue is class %v, not authentication", classes["token.issue"])
	}
	if classes["publish"] != classAPIActivity {
		t.Errorf("publish is class %v, not API activity", classes["publish"])
	}
}

// OCSF has no field for whether an identity was proved or merely asserted,
// which is itself telling. It goes in unmapped rather than being dropped: a log
// that cannot tell a proved identity from a claimed one is cryptographically
// intact and substantively false.
func TestVerificationStateSurvivesIntoOCSF(t *testing.T) {
	events := log(t, nil)
	res, _ := Export(OCSF, events, Options{}, now)

	var sawVerified, sawUnverified bool
	for _, line := range strings.Split(strings.TrimSpace(res.Body), "\n") {
		var rec map[string]any
		_ = json.Unmarshal([]byte(line), &rec)
		unmapped, ok := rec["unmapped"].(map[string]any)
		if !ok {
			t.Fatal("no unmapped block")
		}
		v, present := unmapped["identity_verified"]
		if !present {
			t.Fatal("identity_verified was dropped on the way out")
		}
		if v == true {
			sawVerified = true
		} else {
			sawUnverified = true
		}
	}
	if !sawVerified || !sawUnverified {
		t.Error("both states should appear; the distinction was flattened")
	}
}

// A model acting is not a service acting, and collapsing them loses exactly
// what the log exists to record.
func TestAnAIActorIsNotReportedAsAService(t *testing.T) {
	events := log(t, nil)
	res, _ := Export(OCSF, events, Options{}, now)

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(res.Body), "\n") {
		var rec map[string]any
		_ = json.Unmarshal([]byte(line), &rec)
		actor := rec["actor"].(map[string]any)["user"].(map[string]any)
		if actor["type"] == "AI" {
			found = true
			if um, ok := rec["unmapped"].(map[string]any); ok {
				if um["model"] != "claude" {
					t.Errorf("the model was lost: %v", um["model"])
				}
			}
		}
	}
	if !found {
		t.Error("the AI actor was reported as something else")
	}
}

// -- CEF ---------------------------------------------------------------------

// An unescaped = inside a value ends it and starts a new key, so a principal
// called `x= suser=admin` parses as a different user. CEF's format makes this
// easy, which is why it needs its own test.
func TestCEFEscapesLogInjectionInValues(t *testing.T) {
	events := log(t, nil, audit.Record{
		Action: "publish", Resource: "/", Outcome: audit.Success,
		Principal: "x= suser=admin cs1=spoofed", Kind: audit.KindHuman,
		Verified: false,
	})
	res, err := Export(CEF, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	// The injected pairs must appear escaped, never as separate keys.
	if strings.Contains(res.Body, " suser=admin") {
		t.Errorf("a second suser was injected: %s", res.Body)
	}
	if !strings.Contains(res.Body, `\=`) {
		t.Errorf("the equals signs were not escaped: %s", res.Body)
	}
}

// A pipe in a header field ends it, so a crafted action would shift every
// subsequent field one place left and change the reported severity.
func TestCEFEscapesPipesInHeaders(t *testing.T) {
	events := log(t, nil, audit.Record{
		Action: "publish|0|evil|1|pwn", Resource: "/", Outcome: audit.Success,
		Principal: "dana", Kind: audit.KindHuman, Verified: true,
	})
	res, err := Export(CEF, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	header := strings.SplitN(res.Body, "|", 8)
	if len(header) < 8 {
		t.Fatalf("the header has %d fields, not 7 plus extension: %q",
			len(header)-1, res.Body)
	}
	if !strings.Contains(res.Body, `\|`) {
		t.Error("the pipes were not escaped, so the header fields shifted")
	}
}

// A newline in a header splits one event into two, and the second half is
// parsed as a fresh record with attacker-chosen fields.
func TestCEFRefusesToSplitAnEventInTwo(t *testing.T) {
	events := log(t, nil, audit.Record{
		Action: "publish\nCEF:0|evil|evil|1|x|x|10|", Resource: "/",
		Outcome: audit.Success, Principal: "dana", Kind: audit.KindHuman,
		Verified: true,
	})
	res, err := Export(CEF, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(res.Body), "\n")
	if len(lines) != 1 {
		t.Errorf("one event produced %d lines: %q", len(lines), res.Body)
	}
}

// A denial is the record somebody looks for after an incident. Burying it among
// successful reads is how it stops being findable.
func TestDenialsAreRaisedAboveInformational(t *testing.T) {
	events := log(t, nil)
	res, _ := Export(CEF, events, Options{}, now)
	var sawHigh bool
	for _, line := range strings.Split(strings.TrimSpace(res.Body), "\n") {
		if strings.Contains(line, "outcome=denied") {
			parts := strings.Split(line, "|")
			if parts[6] == "6" {
				sawHigh = true
			} else {
				t.Errorf("a denial has severity %s", parts[6])
			}
		}
	}
	if !sawHigh {
		t.Error("no denial appeared in the export")
	}
}

// -- shape -------------------------------------------------------------------

func TestSequenceRangesBoundTheExport(t *testing.T) {
	events := log(t, nil)
	res, err := Export(JSONL, events, Options{Since: 2, Until: 3}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 {
		t.Errorf("exported %d events from a range of 2", res.Count)
	}
	if res.Chain.FirstSeq != 2 || res.Chain.LastSeq != 3 {
		t.Errorf("the envelope says %d-%d", res.Chain.FirstSeq, res.Chain.LastSeq)
	}
}

func TestAnEmptyRangeIsAnErrorNotAnEmptyFile(t *testing.T) {
	events := log(t, nil)
	if _, err := Export(JSONL, events, Options{Since: 900, Until: 999}, now); err == nil {
		t.Error("an empty export was produced silently")
	}
}

// LEEF is deliberately absent: QRadar-specific, and QRadar reads CEF.
func TestOnlyTheFormatsWorthMaintainingAreOffered(t *testing.T) {
	if len(Formats()) != 3 {
		t.Errorf("%d formats", len(Formats()))
	}
	for _, f := range Formats() {
		if _, err := Export(f, log(t, nil), Options{}, now); err != nil {
			t.Errorf("%s is offered but does not work: %v", f, err)
		}
	}
	if _, err := Export("leef", log(t, nil), Options{}, now); err == nil {
		t.Error("an unsupported format silently produced output")
	}
}

// A partial export is the normal case — last week's events, not all of them.
// The first version verified only the selected range, which verifies nothing:
// each event links to the one before it, so a slice cannot be checked against
// events that were filtered out, and an attacker choosing the range would
// choose one that passes.
func TestAPartialExportIsVerifiableAndAnchored(t *testing.T) {
	events := log(t, nil)
	res, err := Export(JSONL, events, Options{Since: 2, Until: 3}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Chain.AnchorPrev != events[0].Hash {
		t.Errorf("the anchor is %q; it should name the event before the range",
			res.Chain.AnchorPrev)
	}
	if err := VerifyEnvelope(events[1:3], res.Chain); err != nil {
		t.Fatalf("a valid partial export does not verify: %v", err)
	}

	// A range that claims to start elsewhere must be caught.
	wrong := res.Chain
	wrong.AnchorPrev = "0000000000000000"
	if err := VerifyEnvelope(events[1:3], wrong); err == nil {
		t.Error("an export claiming a different starting point verified")
	}
}

// The tampering somebody competent would do: edit an event and update its hash
// field so it is internally consistent. Comparing against the envelope catches
// it, and recomputing the content hash catches it again.
func TestARewrittenEventWithAMatchingHashIsStillCaught(t *testing.T) {
	events := log(t, nil)
	res, err := Export(JSONL, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]audit.Event{}, events...)
	tampered[2].Outcome = audit.Success
	// Give it a hash consistent with nothing, to stand in for an attacker who
	// recomputed it — the envelope still holds the original.
	tampered[2].Hash = strings.Repeat("a", 64)

	if err := VerifyEnvelope(tampered, res.Chain); err == nil {
		t.Fatal("an event edited and re-hashed passed verification")
	}
}

// Exporting is itself an event worth recording, and it must not be possible to
// export in a way that hides that it happened.
func TestTheEnvelopeSaysWhetherItHoldsPersonalData(t *testing.T) {
	plain := log(t, nil)
	res, err := Export(OCSF, plain, Options{Reveal: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Chain.Pseudonymous {
		t.Error("a revealed export claims to be pseudonymous")
	}
	if res.Chain.ExportedAt == "" {
		t.Error("the envelope has no export time")
	}

	key, _ := audit.NewKey()
	res, err = Export(OCSF, log(t, key), Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Chain.Pseudonymous {
		t.Error("a pseudonymous export does not say so, so the receiving " +
			"system has to guess whether it is holding personal data")
	}
}
