package replica

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/quilzo/quilzo/internal/fetch"
)

// Reaching a peer over HTTP.
//
// # Why the transport is injectable
//
// Production uses internal/fetch, which resolves the host and refuses loopback,
// link-local and the cloud metadata endpoint after resolution and before the
// socket connects. That is the SSRF defence this program already has, and a
// replica that opened its own sockets would be a second answer to a question
// that must have one.
//
// It also means a peer cannot be an address inside this network, which is
// correct and makes a test against a local server impossible — so the transport
// is a field. The default is fetch. A test supplies something that talks to a
// server on loopback, and the thing being tested is the wire format rather than
// the address rules, which have their own tests where they live.
//
// # The credential goes per call
//
// Not on the client. A token that lives on a client is one that follows a
// redirect to wherever the peer points next.

// Transport performs one authenticated GET.
type Transport func(ctx context.Context, url, token string) (status int, body []byte, err error)

// HTTPSource is a peer reached over its API.
type HTTPSource struct {
	// Base is the peer's origin, e.g. https://edge.example.com. No path.
	Base string
	// Token authenticates to it. A peer is a store somebody paired with
	// deliberately, and pairing means a credential.
	Token string
	// Get is how requests are made. Nil uses internal/fetch.
	Get Transport
}

// NewHTTPSource checks the base URL once, so a typo fails before a pull starts
// spending its budget rather than on the first object.
func NewHTTPSource(base, token string) (*HTTPSource, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return nil, fmt.Errorf("%q is not a URL: %w", base, err)
	}
	if u.Scheme != "https" {
		// Objects verify themselves, so plaintext could not corrupt content.
		// It would disclose the whole site to the path, and it would disclose
		// the credential, which is the part that does not verify itself.
		return nil, fmt.Errorf(
			"a peer has to be https; %q is not. Objects check out over any "+
				"transport, but the token authenticating to them does not",
			base)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%q names no host", base)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf(
			"a peer is an origin, not a path: %q. The API paths are fixed", base)
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf(
			"no credential for %s. A peer is a store somebody paired with, "+
				"and pairing means a credential", u.Host)
	}
	return &HTTPSource{Base: u.Scheme + "://" + u.Host, Token: token}, nil
}

func (h *HTTPSource) get(ctx context.Context, path string) ([]byte, error) {
	do := h.Get
	if do == nil {
		do = fetchTransport
	}
	status, body, err := do(ctx, h.Base+path, h.Token)
	if err != nil {
		return nil, err
	}
	switch status {
	case 200:
		return body, nil
	case 401, 403:
		return nil, fmt.Errorf(
			"%s refused the credential (%d). A peer that used to answer and "+
				"now does not is usually a revoked token rather than a "+
				"network problem", h.Base, status)
	case 404:
		return nil, fmt.Errorf("%s has no %s", h.Base, path)
	default:
		return nil, fmt.Errorf("%s answered %d for %s", h.Base, status, path)
	}
}

// Ref resolves a ref on the peer.
func (h *HTTPSource) Ref(ctx context.Context, name string) (string, error) {
	body, err := h.get(ctx, "/api/v1/replica/ref/"+url.PathEscape(name))
	if err != nil {
		return "", err
	}
	var resp struct {
		Commit string `json:"commit"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("%s answered with something that is not a ref: %w",
			h.Base, err)
	}
	return resp.Commit, nil
}

// Object fetches one object by id.
//
// The id in the response is ignored on purpose. It is the peer repeating back
// what it was asked, which proves nothing, and reading it would invite treating
// it as the object's name. The name is the hash of the payload, checked by
// PutRaw against the id this side asked for.
func (h *HTTPSource) Object(ctx context.Context, oid string) (string, []byte, error) {
	if !looksLikeID(oid) {
		return "", nil, fmt.Errorf("%q is not an object id", oid)
	}
	body, err := h.get(ctx, "/api/v1/replica/object/"+oid)
	if err != nil {
		return "", nil, err
	}
	var resp struct {
		Kind    string `json:"kind"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", nil, fmt.Errorf(
			"%s answered with something that is not an object: %w", h.Base, err)
	}
	payload, err := base64.StdEncoding.DecodeString(resp.Payload)
	if err != nil {
		return "", nil, fmt.Errorf("%s sent a payload that is not base64: %w",
			h.Base, err)
	}
	return resp.Kind, payload, nil
}

// fetchTransport is the production transport: internal/fetch, which is where
// the address rules live.
func fetchTransport(ctx context.Context, raw, token string) (int, []byte, error) {
	c := fetch.New()
	c.UserAgent = "quilzo/1 (+replication)"
	res, err := c.GetWithToken(ctx, raw, token)
	if err != nil {
		return 0, nil, err
	}
	if res.Truncated {
		// A truncated object would fail its hash anyway, but saying so here
		// gives the real reason rather than "the peer sent the wrong bytes".
		return 0, nil, fmt.Errorf(
			"%s sent more than this fetch accepts; the response was cut short",
			raw)
	}
	return res.Status, res.Body, nil
}
