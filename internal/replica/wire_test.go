package replica_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/replica"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The whole thing, over a socket.
//
// The unit tests use a peer backed by a store directly, which proves the walk
// and the refusals but not the wire: a field renamed on one side of the JSON
// would pass every one of them and fail on the first real sync. This runs the
// actual API handler behind an actual HTTP server and pulls through the actual
// client, so the encoding is checked by using it.
//
// Production reaches a peer through internal/fetch, which refuses loopback
// after DNS resolution — correctly, and which is why the transport is a field.
// The address rules are tested where they live.

func servePeer(t *testing.T) (*httptest.Server, string, *store.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index":   map[string]any{"title": "Home", "body": "Welcome."},
		"pricing": map[string]any{"title": "Pricing", "body": "Ten pounds."},
	}, "peer content", "them"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "replica", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	token, _, err := ts.Issue("replica", "replica", auth.RoleReader, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer((&api.Server{
		Store: s, Policy: pol, Tokens: ts}).Handler())
	t.Cleanup(srv.Close)
	return srv, token, s
}

// loopbackTransport is what a test uses instead of internal/fetch, which would
// refuse this address and be right to.
func loopbackTransport(t *testing.T) replica.Transport {
	t.Helper()
	return func(ctx context.Context, raw, token string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		return resp.StatusCode, body, err
	}
}

func TestAFullPullOverHTTP(t *testing.T) {
	srv, token, remote := servePeer(t)
	local, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	src := &replica.HTTPSource{Base: srv.URL, Token: token, Get: loopbackTransport(t)}
	res, err := replica.Pull(context.Background(), local, src, "origin",
		site.RefLive, replica.Limits{})
	if err != nil {
		t.Fatalf("a pull over HTTP failed: %v", err)
	}
	if res.Head != remote.GetRef(site.RefLive) {
		t.Errorf("pulled %s, the peer is at %s", res.Head, remote.GetRef(site.RefLive))
	}

	// The content arrived and is readable, which is the only proof that counts.
	pages, err := site.PagesAt(local, res.Ref)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := pages["pricing"].(map[string]any)
	if body["body"] != "Ten pounds." {
		t.Errorf("the content did not survive the wire: %v", pages["pricing"])
	}

	// And a second pull moves almost nothing.
	second, err := replica.Pull(context.Background(), local, src, "origin",
		site.RefLive, replica.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Fetched != 0 {
		t.Errorf("the second pull fetched %d objects; everything was already "+
			"here and already correct", second.Fetched)
	}
}

// A wrong credential says so, rather than looking like a network problem.
func TestAPullWithABadCredentialSaysSo(t *testing.T) {
	srv, _, _ := servePeer(t)
	local, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := &replica.HTTPSource{
		Base: srv.URL, Token: "qz_wrong", Get: loopbackTransport(t)}

	_, err = replica.Pull(context.Background(), local, src, "origin",
		site.RefLive, replica.Limits{})
	if err == nil {
		t.Fatal("a pull with a bad credential succeeded")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("the failure does not point at the credential: %v", err)
	}
}

// A peer is an https origin, checked once rather than on the first object.
func TestAPeerMustBeAnHTTPSOrigin(t *testing.T) {
	for _, base := range []string{
		"http://peer.example.com",
		"https://peer.example.com/some/path",
		"https://",
		"not a url at all",
	} {
		if _, err := replica.NewHTTPSource(base, "qz_token"); err == nil {
			t.Errorf("%q was accepted as a peer", base)
		}
	}
	if _, err := replica.NewHTTPSource("https://peer.example.com", ""); err == nil {
		t.Error("a peer with no credential was accepted")
	}
	src, err := replica.NewHTTPSource("https://peer.example.com/", "qz_token")
	if err != nil {
		t.Fatalf("a good peer was refused: %v", err)
	}
	if src.Base != "https://peer.example.com" {
		t.Errorf("the base was normalised to %q", src.Base)
	}
}
