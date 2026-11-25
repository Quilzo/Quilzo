// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/register/side"
	"github.com/quilzo/quilzo/internal/store"
)

// The approvals' own map of people, kept in approvals/people.json before
// the subject map was the one map, is moved into it when the register is
// opened: each name keeps the pseudonym the approvals already name it by,
// the file is deleted, and the names the requests and batches waiting
// beside the store kept go with it. Opened again, there is nothing to move.
// A person erased since is not brought back.
func TestTheApprovalsMapOfPeopleMovesIntoTheSubjectMap(t *testing.T) {
	root := t.TempDir()
	const dana, erased = register.ID("d0000000000000000000000000000001"), register.ID("e0000000000000000000000000000002")
	write := func(name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, "approvals"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "approvals", name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("people.json", `{"people":{"dana@example.com":"`+string(dana)+`","gone@example.com":"`+string(erased)+`"}}`)
	write("requests.json", `{"requests":[{"record":"a0000000000000000000000000000001","object":"x","surface":"sha256:`+
		strings.Repeat("0", 64)+`","signers":[{"subject":"`+string(dana)+`","at":1,"evidence":"sha256:`+strings.Repeat("1", 64)+
		`","method":"passkey","name":"dana@example.com","holds":true}],"opened":1,"until":9999999999}]}`)
	write("batches.json", `{"batches":[{"root":"sha256:`+strings.Repeat("2", 64)+`","by":"dana@example.com","subject":"`+
		string(dana)+`","shown":1,"until":9999999999,"items":[],"viewing":-1}]}`)

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	// The person behind the second pseudonym was erased from the subject
	// map before the approvals' file was moved.
	sideStore := side.Open(filepath.Join(root, "side"), s)
	if _, err := sideStore.Adopt("gone@example.com", "person", string(erased)); err != nil {
		t.Fatal(err)
	}
	if err := sideStore.EraseSubject(string(erased), "request"); err != nil {
		t.Fatal(err)
	}
	r := register.Open(s)
	if _, err := os.Stat(PeoplePath(root)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the approvals' map is still beside the store once a register was opened on it: %v", err)
	}
	if err := r.Unmerged(); err != nil {
		t.Fatalf("the map did not move: %v", err)
	}
	m := &Approvals{Root: root, Register: r}
	if got, ok := m.Known("Dana@example.com"); !ok || got != dana {
		t.Fatalf("dana is %q (%v) in the subject map, and the approvals named her %s", got, ok, dana)
	}
	if got, err := m.people().Pseudonym("dana@example.com"); err != nil || got != dana {
		t.Errorf("asked again, dana is %q (%v)", got, err)
	}
	if _, ok := m.Known("gone@example.com"); ok {
		t.Error("a person erased under their pseudonym is named again from the approvals' old file")
	}
	for _, name := range []string{"requests.json", "batches.json"} {
		raw, err := os.ReadFile(filepath.Join(root, "approvals", name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "dana@example.com") {
			t.Errorf("%s still names dana: %s", name, raw)
		}
		if !strings.Contains(string(raw), string(dana)) {
			t.Errorf("%s lost what waits: %s", name, raw)
		}
	}
	if err := MigratePeople(r); err != nil {
		t.Errorf("moving a map that was moved already: %v", err)
	}
}

// The evidence an approval at the console leaves says that it was the
// console and whether the program proved who was at it, and nothing that
// names them: no name, no token's name. It is kept for good, beside the
// record, and the name of a token is often its person's. Evidence kept
// before it stopped naming the token still reads, and checks, without it.
func TestTheConsolesEvidenceNamesNobody(t *testing.T) {
	b := newBench(t, holds("dana@example.com", auth.ActAcceptRisk))
	id := b.propose("lee", b.risk("R-1", "lee", 2))
	a, err := b.m.Ask(id)
	if err != nil {
		t.Fatal(err)
	}
	console := b.person("dana@example.com")
	console.Console, console.Methods = true, nil
	out, err := b.m.Sign(console, id, Proof{Console: &ConsoleProof{Typed: a.Hash, Verified: true}})
	if err != nil || !out.Done {
		t.Fatalf("the console's approval: %+v %v", out, err)
	}
	path, _ := evidencePath(b.root, out.Evidence)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, named := range []string{"dana", "credential", "token"} {
		if strings.Contains(strings.ToLower(string(raw)), named) {
			t.Errorf("the console's evidence holds %q: %s", named, raw)
		}
	}
	ev, err := LoadEvidence(b.root, out.Evidence)
	if err != nil || ev.Console == nil || !ev.Console.Verified || ev.Check() != nil {
		t.Errorf("the console's evidence reads as %+v (%v)", ev.Console, err)
	}

	// Evidence written the way it was before, naming the token.
	old := []byte(`{"method":"console","purpose":"approve","subject":"` + string(b.subject("dana@example.com")) +
		`","for":"` + string(a.Hash) + `","at":1,"console":{"typed":"` + string(a.Hash) + `","credential":"dana-laptop"}}`)
	sum := sha256.Sum256(old)
	d := register.Digest("sha256:" + hex.EncodeToString(sum[:]))
	p, _ := evidencePath(b.root, d)
	if err := os.WriteFile(p, old, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := LoadEvidence(b.root, d)
	if err != nil || legacy.Check() != nil {
		t.Fatalf("evidence kept before the console stopped naming its token does not read: %v", err)
	}
	if again, _ := json.Marshal(legacy); strings.Contains(string(again), "dana-laptop") {
		t.Errorf("evidence read back still names the token: %s", again)
	}
}
