// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package marking

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/audit"
)

// A transfer signed by the network it left.
//
// The manifest says what was sent, who approved it and who carried it, and
// its digests say whether what arrived is what left. What it cannot say on
// its own is that it left the network it claims to: anybody who can write a
// directory can write a manifest naming anybody. For a crossing a person
// carries, the receiving authority checks the carrier. For one no person
// carries -- an internal instance sending its published projections out to
// a public one -- the receiving side has no carrier to ask, and takes the
// transfer only if it is signed by the one key it was told to trust.
//
// The signature is over the manifest's bytes, and the manifest's digests
// are over the files, so one signature covers everything that crossed. It
// is a statement by the store's head keys under its own context, so it can
// never be presented as a signed audit head, nor a head as a transfer.

// TransferSigName is the signature beside the manifest. It is not content:
// neither hashed into the manifest nor counted as a file that arrived.
const TransferSigName = "transfer.sig"

// TransferContext is what a transfer is signed under.
const TransferContext = "quilzo/transfer/v1"

// Signer is what signs a transfer: the store's head keys.
type Signer interface {
	SignStatement(context string, msg []byte) (audit.Statement, error)
}

// SignTransfer signs the manifest RecordTransfer wrote into dir, and writes
// the signature beside it.
func SignTransfer(dir string, by Signer) error {
	body, err := os.ReadFile(filepath.Join(dir, TransferName))
	if err != nil {
		return fmt.Errorf("%s carries no transfer manifest to sign: %w", dir, err)
	}
	st, err := by.SignStatement(TransferContext, body)
	if err != nil {
		return fmt.Errorf("the transfer could not be signed: %w", err)
	}
	out, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, TransferSigName), append(out, '\n'), 0o644)
}

// ErrUnsigned is a transfer that carries no signature.
var ErrUnsigned = errors.New("the transfer is not signed, so it cannot be shown to have left the network it names")

// VerifySignedTransfer checks a transfer's signature against the pinned
// key, and then its files against its manifest, as VerifyTransfer does.
// A signature that does not verify is an error, not a problem in the list:
// nothing in a transfer from an unknown sender is worth reporting on.
func VerifySignedTransfer(dir string, pinned *audit.HeadVerifier) (*Transfer, []string, error) {
	sig, err := os.ReadFile(filepath.Join(dir, TransferSigName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrUnsigned
	}
	if err != nil {
		return nil, nil, err
	}
	var st audit.Statement
	if err := json.Unmarshal(sig, &st); err != nil {
		return nil, nil, fmt.Errorf("the transfer's signature does not parse: %w", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, TransferName))
	if err != nil {
		return nil, nil, fmt.Errorf("%s carries no transfer manifest: %w", dir, err)
	}
	if err := pinned.VerifyStatement(TransferContext, body, st); err != nil {
		return nil, nil, fmt.Errorf("the transfer is not signed by the pinned key: %w", err)
	}
	return VerifyTransfer(dir)
}
