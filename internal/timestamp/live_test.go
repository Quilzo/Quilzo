package timestamp

import (
	"os"
	"testing"
)

// Talks to a real authority. Skipped unless SCRIVET_LIVE_TSA is set, because a
// test that needs the network fails for reasons that have nothing to do with the
// code — but the encoding is only actually proved by a TSA accepting it. Round
// tripping my own encoder through my own decoder proves the pair agree, not that
// either is right.
func TestAgainstARealAuthority(t *testing.T) {
	if os.Getenv("SCRIVET_LIVE_TSA") == "" {
		t.Skip("set SCRIVET_LIVE_TSA=1 to talk to a real TSA")
	}
	s, err := Request(nil, DefaultTSA, "scrivet-live-test-root")
	if err != nil {
		t.Fatalf("a real TSA refused our request, so the encoding is wrong: %v", err)
	}
	if len(s.Token) < 100 {
		t.Errorf("token looks too small to be real: %d bytes", len(s.Token))
	}
	t.Logf("%s", Describe(s))
	if err := WriteToken(s, "/tmp/stamp.tsr"); err == nil {
		if err := WriteStampedData(s, "/tmp/stamp.data"); err == nil {
			t.Log("wrote /tmp/stamp.tsr and /tmp/stamp.data for openssl ts -verify")
		}
	}
}
