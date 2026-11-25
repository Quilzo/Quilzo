// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"

	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
)

// verifyRS256 checks a JWT's signature as GitHub would.
func verifyRS256(pub *rsa.PublicKey, signing, sig string) error {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(signing))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], raw)
}

func evidenceInput(format, body, source string, m *register.ColumnMap) evidence.Input {
	return evidence.Input{Format: evidence.Format(format), Body: []byte(body), Source: source, Map: m}
}
