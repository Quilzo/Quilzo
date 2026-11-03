// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/compliance"
	"github.com/quilzo/quilzo/internal/out"
)

// The summary is what a procurement questionnaire is answered from, and it
// said "quantum-broken, generated here: none", in green, as a literal. The
// inventory it summarises lists RSA, ECDSA, Ed25519 and TLS as broken and
// generated here, and --json, which hands over the inventory's own list, was
// right all along. The line under it, "verified only", counted every concern,
// the generated ones with them. Both lines are counted from the inventory.
func TestTheSummaryCountsTheQuantumBrokenAlgorithmsItGenerates(t *testing.T) {
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	if err := complianceSummary(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	generated, verified := 0, 0
	for _, a := range compliance.Concerns() {
		switch a.Use {
		case compliance.Generated:
			generated++
		case compliance.Verified:
			verified++
		}
	}
	if generated == 0 {
		t.Fatal("the inventory lists nothing quantum-broken as generated here; " +
			"this test needs one to tell a count from a literal")
	}

	said := func(label string) string {
		for _, line := range strings.Split(buf.String(), "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), label); ok {
				return strings.TrimSpace(rest)
			}
		}
		t.Fatalf("the summary has no %q line:\n%s", label, buf.String())
		return ""
	}
	if got := said("quantum-broken, generated here"); got != fmt.Sprint(generated) {
		t.Errorf("generated here: the summary says %q and the inventory lists %d", got, generated)
	}
	if got := said("quantum-broken, verified only"); got != fmt.Sprint(verified) {
		t.Errorf("verified only: the summary says %q and the inventory lists %d", got, verified)
	}
}
