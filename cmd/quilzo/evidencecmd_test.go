// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func evidenceFixturePath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "internal", "evidence", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A file brought in on the command line: a preview writes nothing, the
// import seals it and writes what it yields, a second import writes
// nothing, and the file is listed, shown and checked. Somebody who may read
// the site and not the register is refused the import, exit 3.
func TestIngestOnTheCommandLine(t *testing.T) {
	root, token := accessStore(t)
	file := evidenceFixturePath(t, "ocsf/prowler-1.2.0.json")

	o, e, code := cliRun(t, root, token, "--json", "ingest", "ocsf", file, "--preview")
	var preview struct{ Preview bool }
	if code != 0 || json.Unmarshal([]byte(o), &preview) != nil || !preview.Preview {
		t.Fatalf("the preview exited %d: %s %s", code, e, firstLines(o, 5))
	}
	o, _, _ = cliRun(t, root, token, "--json", "evidence", "list")
	var listed struct{ Total int }
	if json.Unmarshal([]byte(o), &listed) != nil || listed.Total != 0 {
		t.Fatalf("the preview wrote something: %s", firstLines(o, 5))
	}

	o, e, code = cliRun(t, root, token, "--json", "ingest", "ocsf", file)
	if code != 0 {
		t.Fatalf("the import exited %d: %s", code, e)
	}
	var res struct {
		Batch struct {
			Digest string `json:"digest"`
			Grade  string `json:"grade"`
			RawID  string `json:"raw_id"`
		} `json:"batch"`
		Receipt struct {
			Commit string `json:"commit"`
		} `json:"receipt"`
		Proposed *struct{ Ref string } `json:"proposed"`
	}
	if err := json.Unmarshal([]byte(o), &res); err != nil || res.Receipt.Commit == "" || res.Batch.Grade != "uploaded" ||
		res.Proposed == nil || res.Proposed.Ref != "register-proposals" {
		t.Fatalf("the import answered %s, %v", firstLines(o, 10), err)
	}
	o, _, code = cliRun(t, root, token, "--json", "ingest", "ocsf", file)
	var again struct {
		Receipt struct{ Commit string }
	}
	if code != 0 || json.Unmarshal([]byte(o), &again) != nil || again.Receipt.Commit != "" {
		t.Errorf("a second import of the same file wrote: %s", firstLines(o, 5))
	}

	for _, line := range [][]string{{"evidence", "list"}, {"evidence", "show", res.Batch.Digest}, {"evidence", "show", res.Batch.RawID},
		{"evidence", "verify"}, {"evidence", "verify", res.Batch.Digest}} {
		o, e, code := cliRun(t, root, token, append([]string{"--json"}, line...)...)
		if code != 0 || !json.Valid([]byte(o)) {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, e)
		}
	}
	var verified struct{ Files, Problems int }
	if o, _, _ := cliRun(t, root, token, "--json", "evidence", "verify"); json.Unmarshal([]byte(o), &verified) != nil ||
		verified.Files != 1 || verified.Problems != 0 {
		t.Errorf("the file does not check: %s", firstLines(o, 10))
	}
	if _, _, code := cliRun(t, root, token, "evidence", "show", "sha256:"+strings.Repeat("ab", 32)); code != 4 {
		t.Errorf("a file that is not there exited %d, not 4", code)
	}

	if _, e, code := cliRun(t, root, token, "auth", "grant", "rita", "reader"); code != 0 {
		t.Fatal(e)
	}
	o, _, _ = cliRun(t, root, token, "token", "issue", "rita", "--principal", "rita", "--role", "reader", "--json")
	var tok struct{ Token string }
	json.Unmarshal([]byte(o), &tok)
	if _, e, code := cliRun(t, root, tok.Token, "ingest", "ocsf", file); code != 3 {
		t.Errorf("a reader of the site's import exited %d, not 3: %s", code, e)
	}
}

// A table is read only through a column map a person confirmed: without
// one the import is refused and says how to make one; a drafted map,
// confirmed, reads it.
func TestTableIngestThroughAConfirmedMap(t *testing.T) {
	root, token := accessStore(t)
	dir := t.TempDir()
	csv := filepath.Join(dir, "laptops.csv")
	if err := os.WriteFile(csv, []byte("Serial,Hostname,Encrypted\nC02X1,mac-01,true\nC02X2,mac-02,false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, e, code := cliRun(t, root, token, "ingest", "csv", csv); code != 2 || !strings.Contains(e, "draft-map") {
		t.Fatalf("a table with no map exited %d: %s", code, e)
	}
	o, e, code := cliRun(t, root, token, "--json", "evidence", "draft-map", "csv", csv, "--kind", "Observation", "--name", "laptops")
	if code != 0 {
		t.Fatalf("draft-map exited %d: %s", code, e)
	}
	draft := filepath.Join(dir, "map.json")
	if err := os.WriteFile(draft, []byte(o), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, e, code := cliRun(t, root, token, "evidence", "confirm-map", draft); code != 0 {
		t.Fatalf("confirm-map exited %d: %s", code, e)
	}
	if o, _, _ := cliRun(t, root, token, "--json", "evidence", "maps"); !strings.Contains(o, `"laptops"`) {
		t.Errorf("the confirmed map is not listed: %s", firstLines(o, 5))
	}
	o, e, code = cliRun(t, root, token, "--json", "ingest", "csv", csv, "--map", "laptops")
	if code != 0 || !strings.Contains(o, `"disk.encrypted"`) && !strings.Contains(o, `"encrypted"`) {
		t.Fatalf("the table through its map exited %d: %s %s", code, e, firstLines(o, 5))
	}
}

// A DSSE envelope is read once its signer's key is pinned, and graded
// signed; before that it is refused, exit 3.
func TestSignedIngestNeedsAPinnedKey(t *testing.T) {
	root, token := accessStore(t)
	dir := t.TempDir()
	seed := sha256.Sum256([]byte("a key for the command line's test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	der, _ := x509.MarshalPKIXPublicKey(priv.Public())
	keyFile := filepath.Join(dir, "key.pem")
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)

	bom, err := os.ReadFile(evidenceFixturePath(t, "cyclonedx/bom-1.5.json"))
	if err != nil {
		t.Fatal(err)
	}
	typ := "application/vnd.cyclonedx+json"
	pae := []byte("DSSEv1 " + itoa(len(typ)) + " " + typ + " " + itoa(len(bom)) + " ")
	pae = append(pae, bom...)
	env, _ := json.Marshal(map[string]any{"payloadType": typ, "payload": base64.StdEncoding.EncodeToString(bom),
		"signatures": []any{map[string]any{"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pae))}}})
	envFile := filepath.Join(dir, "bom.dsse.json")
	os.WriteFile(envFile, env, 0o600)

	if _, e, code := cliRun(t, root, token, "ingest", "dsse", envFile); code != 3 || !strings.Contains(e, "pinned") {
		t.Fatalf("an envelope no pinned key verifies exited %d: %s", code, e)
	}
	if o, e, code := cliRun(t, root, token, "evidence", "pin", "build", keyFile, "--title", "the build service"); code != 0 ||
		!strings.Contains(o, "sha256:") {
		t.Fatalf("pinning exited %d: %s", code, e)
	}
	o, e, code := cliRun(t, root, token, "--json", "ingest", "dsse", envFile)
	var signed struct {
		Batch struct {
			Grade string
			Raw   struct{ Signer string }
		}
	}
	if code != 0 || json.Unmarshal([]byte(o), &signed) != nil || signed.Batch.Grade != "signed" || signed.Batch.Raw.Signer != "build" {
		t.Fatalf("a pinned envelope exited %d: %s %s", code, e, firstLines(o, 5))
	}
}
