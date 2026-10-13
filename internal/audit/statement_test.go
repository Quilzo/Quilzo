// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestAStatementVerifiesOnlyUnderItsOwnContext(t *testing.T) {
	ed, ml, err := GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewHeadSigner(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.SignStatement("quilzo/feature-package/v1", []byte("digest"))
	if err != nil {
		t.Fatal(err)
	}
	v := s.Verifier()
	if err := v.VerifyStatement("quilzo/feature-package/v1", []byte("digest"), st); err != nil {
		t.Fatalf("a good statement was refused: %v", err)
	}
	if v.VerifyStatement("quilzo/other/v1", []byte("digest"), st) == nil {
		t.Error("a statement verified under another context")
	}
	if v.VerifyStatement("quilzo/feature-package/v1", []byte("digesT"), st) == nil {
		t.Error("a statement verified over other bytes")
	}
	half := st
	half.MLDSA = ""
	if s.PostQuantum() && v.VerifyStatement("quilzo/feature-package/v1", []byte("digest"), half) == nil {
		t.Error("a statement stripped of its ML-DSA half verified")
	}
	if _, err := s.SignStatement(signatureContext, []byte("x")); err == nil {
		t.Error("a statement was signed under the head's own context")
	}
	other, _, _ := GenerateHeadSeeds()
	s2, err := NewHeadSigner(other, ml)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Verifier().VerifyStatement("quilzo/feature-package/v1", []byte("digest"), st) == nil {
		t.Error("another key verified the statement")
	}
}
