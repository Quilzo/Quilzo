package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// The context string, tested from inside because it is about the bytes that
// get signed rather than about the API.
//
// Without domain separation, a signature made for any other purpose with the
// same key is a valid audit head. Anything that will sign arbitrary bytes with
// this key — another protocol, a debug endpoint, a future feature — becomes an
// oracle for forging the log's own commitment.
func TestASignatureOverTheBareFieldsIsNotAHead(t *testing.T) {
	edSeed, mlSeed, err := GenerateHeadSeeds()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewHeadSigner(edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	h := Head{Size: 42, Root: "a1b2c3",
		At: time.Unix(1787000000, 0).UTC().Format(time.RFC3339)}

	sh, err := s.Sign(h)
	if err != nil {
		t.Fatal(err)
	}

	// What a general-purpose signing oracle over the head's own fields would
	// produce, with no context and no length prefixes.
	naked := ed25519.Sign(s.ed, []byte("42a1b2c3"+h.At))
	sh.Ed25519 = base64.StdEncoding.EncodeToString(naked)
	if err := s.Verifier().Verify(sh); err == nil {
		t.Fatal("a signature over the bare concatenated fields verified as a " +
			"head, so anything that signs arbitrary bytes with this key can " +
			"forge one")
	}
}

// The message actually carries the context, checked directly so that removing
// it is a test failure rather than a silent loss of the property above.
func TestTheSignedMessageCarriesItsContext(t *testing.T) {
	msg := headMessage(Head{Size: 1, Root: "aa", At: "now"})
	if !strings.HasPrefix(string(msg), signatureContext) {
		t.Errorf("the signed message does not begin with the context: %q",
			string(msg[:min(40, len(msg))]))
	}
	if !strings.Contains(signatureContext, "/v1") {
		t.Error("the context carries no version, so a change to what is " +
			"signed cannot be told apart from what it replaced")
	}
}
