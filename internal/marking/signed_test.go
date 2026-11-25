// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package marking_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/marking"
)

func headSigner(t *testing.T, seed byte) *audit.HeadSigner {
	t.Helper()
	s, err := audit.NewHeadSigner(bytes.Repeat([]byte{seed}, audit.SeedSize), bytes.Repeat([]byte{seed + 1}, audit.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A transfer signed by the pinned key verifies; one with no signature, or
// signed by any other key, does not, however intact its files are.
func TestASignedTransferVerifiesOnlyWithThePinnedKey(t *testing.T) {
	dir := exported(t)
	record(t, dir)
	internal := headSigner(t, 1)

	if _, _, err := marking.VerifySignedTransfer(dir, internal.Verifier()); err == nil ||
		!strings.Contains(err.Error(), "not signed") {
		t.Fatalf("an unsigned transfer was taken: %v", err)
	}
	if err := marking.SignTransfer(dir, internal); err != nil {
		t.Fatal(err)
	}
	got, problems, err := marking.VerifySignedTransfer(dir, internal.Verifier())
	if err != nil || len(problems) != 0 {
		t.Fatalf("a transfer signed by the pinned key did not verify: %v %v", err, problems)
	}
	if got.Approved != "Ops Lead" {
		t.Errorf("the verified manifest is not the one recorded: %+v", got)
	}
	if _, _, err := marking.VerifySignedTransfer(dir, headSigner(t, 9).Verifier()); err == nil {
		t.Error("a transfer verified with a key that did not sign it")
	}
}

// The signature covers the manifest, so changing who approved the transfer
// after it was signed is caught, and the manifest covers the files, so is
// changing a file.
func TestASignedTransferNoticesAChangedManifestOrFile(t *testing.T) {
	dir := exported(t)
	record(t, dir)
	key := headSigner(t, 1)
	if err := marking.SignTransfer(dir, key); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, marking.TransferName)
	body, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, bytes.Replace(body, []byte("Ops Lead"), []byte("Somebody Else"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := marking.VerifySignedTransfer(dir, key.Verifier()); err == nil {
		t.Error("a manifest changed after it was signed verified")
	}
	if err := os.WriteFile(manifest, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pages", "about.json"), []byte(`{"title":"Changed"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, problems, err := marking.VerifySignedTransfer(dir, key.Verifier()); err != nil || len(problems) == 0 {
		t.Errorf("a file changed after signing was not reported: %v %v", err, problems)
	}
}

// The signature file is not content: it is neither hashed into the
// manifest nor reported as a file that joined the transfer.
func TestTheSignatureIsNotPartOfTheTransfer(t *testing.T) {
	dir := exported(t)
	record(t, dir)
	if err := marking.SignTransfer(dir, headSigner(t, 1)); err != nil {
		t.Fatal(err)
	}
	_, problems, err := marking.VerifyTransfer(dir)
	if err != nil || len(problems) != 0 {
		t.Errorf("the signature was taken for content: %v %v", err, problems)
	}
}
