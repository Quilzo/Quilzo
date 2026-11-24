// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// A record's identifier is derived from what the record is.
//
// The generic record store mints a random identifier for each write, which
// is right for rows a person types and wrong for evidence. An import that
// runs every hour has to find the record it wrote the hour before, without
// keeping a table of what it wrote; two connectors that report the same
// account have to agree about which record is that account; and a bundle
// handed to an auditor has to name the same record next year. So the
// identifier is the first 32 hexadecimal characters of SHA-256 over the
// source and the natural key, and anybody holding those two can compute it.
//
// The kind's collection is hashed with them, so a control and a risk that
// happen to share a reference are two identifiers, and an identifier names
// one record across the whole register.
//
// The bytes hashed are fixed for good: the domain line below, then the
// collection, the source and the natural key, each preceded by its length as
// four big-endian bytes. A test holds a known identifier, because changing
// any of this would rename every record ever written.

// idDomain separates this hash from every other use of SHA-256 in the
// program.
const idDomain = "quilzo register id v1\n"

// DeriveID is the identifier of the record of a kind that a source knows by
// a natural key.
func DeriveID(kind Kind, source, natural string) (ID, error) {
	spec, err := specFor(kind)
	if err != nil {
		return "", err
	}
	if source == "" || natural == "" {
		return "", fmt.Errorf("%w: %s: it has no source or no natural key to be identified by",
			ErrInvalid, kind)
	}
	h := sha256.New()
	h.Write([]byte(idDomain))
	var n [4]byte
	for _, part := range []string{spec.Collection, source, natural} {
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	return ID(hex.EncodeToString(h.Sum(nil))[:32]), nil
}

// IDOf is the identifier a record has, before or after it is written.
func IDOf(rec Record) (ID, error) {
	if m, ok := rec.(interface{ minted() ID }); ok {
		id := m.minted()
		if !id.Valid() {
			return "", fmt.Errorf("%w: %s: its identifier is not 32 hexadecimal characters", ErrInvalid, rec.Kind())
		}
		return id, nil
	}
	source, natural := rec.Key()
	return DeriveID(rec.Kind(), source, natural)
}
