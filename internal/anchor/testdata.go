package anchor

import _ "embed"

//go:embed testdata_proof.bin
var realProof []byte

// testdata returns a genuine calendar response, captured from
// alice.btc.calendar.opentimestamps.org.
//
// Kept because hand-built proofs test the parser against what the format
// permits, and this tests it against what a server actually sends — which is
// the thing that has to work and the thing that changes without warning.
func testdata() ([]byte, error) { return realProof, nil }
