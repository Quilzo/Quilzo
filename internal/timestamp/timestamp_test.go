package timestamp

import (
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A timestamp that proves the wrong thing is worse than none, because its output
// is believed without being re-derived. So these lean on the ways that happens:
// a refusal stored as a proof, a response to somebody else's request, and a
// token checked against data it does not commit to.

// tsaResponse builds a well-formed reply with the given status.
func tsaResponse(t *testing.T, status int, withToken bool) []byte {
	t.Helper()
	resp := struct {
		Status struct {
			Status int
		}
		Token asn1.RawValue `asn1:"optional"`
	}{}
	resp.Status.Status = status
	if withToken {
		// Any well-formed DER stands in for a CMS token here; this package
		// deliberately does not parse it.
		tok, err := asn1.Marshal("stand-in token")
		if err != nil {
			t.Fatal(err)
		}
		resp.Token = asn1.RawValue{FullBytes: tok}
	}
	b, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fakeTSA(t *testing.T, status int, withToken bool) (*httptest.Server, *[]byte) {
	t.Helper()
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		got = buf[:n]
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(tsaResponse(t, status, withToken))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestRequestStoresAToken(t *testing.T) {
	srv, _ := fakeTSA(t, 0, true)
	s, err := Request(srv.Client(), srv.URL, "abc123-publication-root")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Token) == 0 {
		t.Error("no token stored")
	}
	if s.Root != "abc123-publication-root" {
		t.Errorf("wrong root recorded: %q", s.Root)
	}
	if s.Hash == "" {
		t.Error("the submitted hash should be recorded so it can be re-derived")
	}
}

// The request has to carry a nonce, or a TSA — or anything in between — can
// replay an older token and the proof is of a moment nobody asked about.
func TestRequestCarriesANonceAndAsksForTheCertificate(t *testing.T) {
	srv, captured := fakeTSA(t, 0, true)
	if _, err := Request(srv.Client(), srv.URL, "root"); err != nil {
		t.Fatal(err)
	}

	var req timeStampReq
	if _, err := asn1.Unmarshal(*captured, &req); err != nil {
		t.Fatalf("the request we sent is not a valid TimeStampReq: %v", err)
	}
	if req.Version != 1 {
		t.Errorf("version should be 1, got %d", req.Version)
	}
	if req.Nonce == nil || req.Nonce.Cmp(big.NewInt(0)) == 0 {
		t.Error("no nonce; the response could be a replay of an older token")
	}
	if !req.CertReq {
		t.Error("certReq should be set, or verifying later needs a certificate " +
			"fetched from somewhere that may no longer exist")
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("unexpected hash algorithm: %v", req.MessageImprint.HashAlgorithm.Algorithm)
	}
	if len(req.MessageImprint.HashedMessage) != 32 {
		t.Errorf("expected a 32-byte SHA-256, got %d", len(req.MessageImprint.HashedMessage))
	}
}

// A refusal must never be stored as though it were a proof.
func TestARefusalIsNotStoredAsAProof(t *testing.T) {
	for _, status := range []int{2, 3, 5} { // rejection, waiting, revocation
		srv, _ := fakeTSA(t, status, false)
		if _, err := Request(srv.Client(), srv.URL, "root"); err == nil {
			t.Errorf("status %d was accepted as a stamp", status)
		}
	}
}

func TestAResponseWithNoTokenIsRefused(t *testing.T) {
	srv, _ := fakeTSA(t, 0, false)
	if _, err := Request(srv.Client(), srv.URL, "root"); err == nil {
		t.Error("a granted status with no token is not a proof")
	}
}

func TestGarbageFromTheAuthorityIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not asn.1 at all"))
	}))
	defer srv.Close()

	if _, err := Request(srv.Client(), srv.URL, "root"); err == nil {
		t.Error("an unparseable reply should not become a stamp")
	}
}

func TestAnEmptyRootIsRefused(t *testing.T) {
	if _, err := Request(nil, "", ""); err == nil {
		t.Error("there is nothing to stamp before anything is published")
	}
}

func TestLatestReturnsTheMostRecentForARoot(t *testing.T) {
	s := &Store{Stamps: []Stamp{
		{Root: "a", Authority: "first"},
		{Root: "b", Authority: "other"},
		{Root: "a", Authority: "second"},
	}}
	got, ok := s.Latest("a")
	if !ok || got.Authority != "second" {
		t.Errorf("expected the most recent stamp for a, got %+v", got)
	}
	if _, ok := s.Latest("nope"); ok {
		t.Error("an unstamped root should report as unstamped")
	}
}

// The description must not imply a durability the stamp has not got.
func TestDescribeSaysWhatIsMissing(t *testing.T) {
	unanchored := Describe(Stamp{Root: "r", Authority: "tsa", RequestedAt: "now"})
	if !strings.Contains(unanchored, "certificate remaining valid") {
		t.Error("an unanchored stamp should say its proof depends on the TSA's cert")
	}
	// Our own clock is not evidence, and saying so stops it being cited as if
	// it were.
	if !strings.Contains(unanchored, "not evidence") {
		t.Error("the local timestamp should be marked as not evidential")
	}

	anchored := Describe(Stamp{
		Root: "r", Authority: "tsa", RequestedAt: "now",
		Anchor: &Anchor{Method: "opentimestamps", Confirmed: false},
	})
	if !strings.Contains(anchored, "not yet confirmed") {
		t.Error("an unconfirmed anchor must not read as confirmed")
	}
}
