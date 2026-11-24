// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// The scale probe: a register of the size one organisation's is meant to
// reach, made the same way every time.
//
// The design target for one instance is ten thousand assets and identities
// as observations, a thousand controls, and about a hundred and fifty
// thousand test runs and pieces of evidence. Whether the index holds that in
// the memory it was promised, and answers the question asked of it most in
// the time it was promised, is a thing to measure and not to assume, so the
// probe makes that register and a test and two benchmarks measure it
// (scale_test.go). The same records are what a demonstration can load.
//
// Every value comes from a counter and a hash, so two runs make the same
// records, byte for byte, and a measurement taken today can be taken again.

// Probe says how large a synthetic register to make.
type Probe struct {
	// Observations is how many facts, each about a subject of its own.
	Observations int
	// Controls is how many controls, each with one test.
	Controls int
	// Rows is how many test runs and pieces of evidence, together: half of
	// each, a piece of evidence for each run.
	Rows int
}

// FullProbe is the size the register is designed to.
var FullProbe = Probe{Observations: 10_000, Controls: 1_000, Rows: 150_000}

// probeDigest is a digest made from a word and a number.
func probeDigest(word string, n int) Digest {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	sum := sha256.Sum256(append([]byte("quilzo probe "+word+" "), b[:]...))
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

// probeID is an identifier made the same way: not a real pseudonym, which
// is random, but one a second run makes again.
func probeID(word string, n int) ID { return ID(probeDigest(word, n)[7:39]) }

// Records makes the register, in the order it would be written: the source
// and the people, then what is known, then the programme, then the runs and
// their evidence. One in seven runs fails, and one control in ten has never
// been run, so every state coverage can count is there to be counted.
func (p Probe) Records() ([]Record, error) {
	owner := probeID("owner", 0)
	approver := probeID("approver", 0)
	approval := &Approval{Atom: "approve-test", Rule: "author-is-not-approver", Needed: 1, Of: 2,
		Surface: probeDigest("surface", 0), Raised: owner,
		Signers: []Signer{{Subject: approver, At: 1_780_000_000, Assertion: probeDigest("assertion", 0)}}}

	source := Source{Name: "probe", Type: "import", Fresh: 86_400, Grade: GradeImported}
	sourceID, err := IDOf(source)
	if err != nil {
		return nil, err
	}
	population := Population{Name: "probe-accounts", Source: sourceID, Query: probeDigest("query", 0),
		Fresh: 86_400, Independent: true, Size: int64(p.Observations), Members: probeDigest("members", 0)}
	populationID, err := IDOf(population)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, 4+p.Observations+2*p.Controls+p.Rows)
	out = append(out, source, Subject{Pseudonym: owner, Type: "person"},
		Subject{Pseudonym: approver, Type: "person"}, population)

	for i := 0; i < p.Observations; i++ {
		out = append(out, Observation{Source: sourceID, About: probeID("account", i), Fact: "mfa.registered",
			Value: BoolValue(i%9 != 0), Grade: GradeImported, Raw: probeDigest("raw", i/500)})
	}

	domains := Domain("").Values()
	tests := make([]ID, p.Controls)
	controls := make([]ID, p.Controls)
	for i := 0; i < p.Controls; i++ {
		c := Control{Ref: fmt.Sprintf("C-%04d", i+1), Title: fmt.Sprintf("Probe control %d", i+1),
			Domain: Domain(domains[i%len(domains)]), Owner: owner}
		if controls[i], err = IDOf(c); err != nil {
			return nil, err
		}
		t := ControlTest{Control: controls[i], Name: "weekly", Population: populationID,
			Query: probeDigest("test-query", i), Assertion: "all", Approval: approval}
		if tests[i], err = IDOf(t); err != nil {
			return nil, err
		}
		out = append(out, c, t)
	}

	// The runs go round the controls that are tested, a week apart, so each
	// tested control has the same number and its newest is the last made.
	tested := p.Controls - p.Controls/10
	if tested < 1 {
		tested = p.Controls
	}
	for i := 0; tested > 0 && i < p.Rows/2; i++ {
		c := i % tested
		round := i / tested
		ran := Time(1_700_000_000 + int64(round)*7*86_400 + int64(c))
		run := TestRun{Test: tests[c], Ran: ran, Outcome: Pass, Population: probeDigest("members", round),
			Size: int64(p.Observations), Snapshot: probeDigest("snapshot", i)}
		if (c+round*3)%7 == 0 && p.Observations > 0 {
			run.Outcome = Fail
			run.Failing = []ID{probeID("account", (c*31+round)%max(p.Observations, 1))}
		}
		runID, err := IDOf(run)
		if err != nil {
			return nil, err
		}
		out = append(out, run, Evidence{Control: controls[c], Run: runID, At: ran, Outcome: run.Outcome, Grade: GradeImported})
	}
	return out, nil
}
