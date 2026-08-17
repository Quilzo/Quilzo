package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/fetch"
)

// Discovery is the subset of the provider metadata this needs.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	// CodeChallengeMethods says whether PKCE is offered. A provider that does
	// not offer S256 is a provider this refuses, because the alternative is
	// plain — which is PKCE with the protection removed.
	CodeChallengeMethods []string `json:"code_challenge_methods_supported"`
}

// Provider is a configured identity provider with a cached key set.
type Provider struct {
	Discovery Discovery
	// Algorithms is the intersection of what the provider advertises with what
	// this package implements, computed once at discovery.
	Algorithms []Algorithm

	fetcher *fetch.Client
	// TTL bounds how long a fetched key set is trusted. Not per-login, because
	// that hands the provider a request on every sign-in and turns an outage
	// there into an outage here. Not forever, because keys rotate.
	TTL time.Duration

	mu       sync.RWMutex
	keys     map[string]crypto.PublicKey
	fetched  time.Time
	singular crypto.PublicKey // the only key, when there is exactly one
}

// DefaultTTL is how long a key set is cached.
const DefaultTTL = time.Hour

// Discover reads a provider's metadata.
//
// The URL goes through the SSRF-hardened fetcher, which matters more here than
// almost anywhere: an issuer URL is configuration, configuration is sometimes
// set by whoever runs the tenant, and "fetch this URL from inside the network"
// is the whole of server-side request forgery. The fetcher validates the
// address at connect time rather than before it.
func Discover(ctx context.Context, issuer string, client *fetch.Client) (*Provider, error) {
	if client == nil {
		client = fetch.New()
	}
	base := strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	res, err := client.Get(ctx, base+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("cannot read the provider metadata: %w", err)
	}

	var d Discovery
	if err := json.Unmarshal(res.Body, &d); err != nil {
		return nil, fmt.Errorf("the metadata is not JSON: %w", err)
	}

	// The issuer in the document must match the one asked for. Without this a
	// provider could claim to be somebody else and every issuer check
	// downstream would compare against the wrong value.
	if d.Issuer != base && d.Issuer != base+"/" {
		// A templated issuer is the multi-tenant case rather than an attack,
		// and it is worth saying so: Microsoft's /common and /organizations
		// endpoints publish a placeholder because the real issuer differs per
		// tenant. Refusing is still right — the issuer check would otherwise
		// compare against a placeholder — but an operator hitting this needs to
		// know the fix is a tenant-specific URL, not that their provider is
		// broken.
		if strings.Contains(d.Issuer, "{") {
			return nil, fmt.Errorf(
				"%s publishes a templated issuer (%q), because it is a "+
					"multi-tenant endpoint and the real issuer differs per "+
					"tenant.\n  Configure the tenant-specific URL instead, which "+
					"publishes a concrete issuer:\n    %s",
				base, d.Issuer,
				strings.Replace(base, "/common", "/<your-tenant-id>", 1))
		}
		return nil, fmt.Errorf(
			"the metadata at %s says the issuer is %q. Trusting it would mean "+
				"every issuer check afterwards compares against a value the "+
				"provider chose", base, d.Issuer)
	}
	// Named individually. "Missing an endpoint" sends somebody to read a JSON
	// document; naming the endpoint tells them what kind of provider they have
	// pointed at — a workload identity issuer has a jwks_uri and no
	// authorization endpoint, because nobody signs in to it.
	var missing []string
	if d.AuthorizationEndpoint == "" {
		missing = append(missing, "authorization_endpoint")
	}
	if d.TokenEndpoint == "" {
		missing = append(missing, "token_endpoint")
	}
	if d.JWKSURI == "" {
		missing = append(missing, "jwks_uri")
	}
	if len(missing) > 0 {
		hint := ""
		if d.AuthorizationEndpoint == "" && d.JWKSURI != "" {
			hint = "\n  A provider with keys but no authorization endpoint issues " +
				"tokens to machines rather than signing people in — a workload " +
				"identity issuer. It cannot be used for sign-in."
		}
		return nil, fmt.Errorf("%s publishes no %s%s",
			base, strings.Join(missing, " and no "), hint)
	}
	// Every endpoint has to survive the same validation as the discovery URL,
	// or a hostile metadata document redirects the token exchange inward.
	for name, endpoint := range map[string]string{
		"authorization_endpoint": d.AuthorizationEndpoint,
		"token_endpoint":         d.TokenEndpoint,
		"jwks_uri":               d.JWKSURI,
	} {
		if _, err := fetch.ValidateURL(endpoint); err != nil {
			return nil, fmt.Errorf("the metadata's %s is not usable: %w", name, err)
		}
	}

	p := &Provider{Discovery: d, fetcher: client, TTL: DefaultTTL}
	for _, a := range d.SigningAlgs {
		if supported[Algorithm(a)] {
			p.Algorithms = append(p.Algorithms, Algorithm(a))
		}
	}
	if len(p.Algorithms) == 0 {
		return nil, fmt.Errorf(
			"%s signs with %v and this implements %v, so there is no algorithm "+
				"in common. Adding one is a deliberate decision, not a fallback",
			d.Issuer, d.SigningAlgs, Supported())
	}
	if !d.offersS256() {
		return nil, fmt.Errorf(
			"%s does not advertise the S256 code challenge method. PKCE with "+
				"the plain method is PKCE with the protection removed, so this "+
				"refuses rather than downgrading", d.Issuer)
	}
	return p, nil
}

func (d Discovery) offersS256() bool {
	// An absent list is treated as offering S256. The parameter is optional in
	// the spec and several established providers omit it while supporting it;
	// refusing them would make the check a compatibility problem rather than a
	// security one.
	if len(d.CodeChallengeMethods) == 0 {
		return true
	}
	for _, m := range d.CodeChallengeMethods {
		if m == "S256" {
			return true
		}
	}
	return false
}

// Key implements KeySource.
func (p *Provider) Key(kid string) (crypto.PublicKey, error) {
	p.mu.RLock()
	fresh := time.Since(p.fetched) < p.ttl()
	key, have := p.keys[kid]
	single := p.singular
	n := len(p.keys)
	p.mu.RUnlock()

	if fresh {
		if k, err := pick(kid, key, have, single, n); err == nil {
			return k, nil
		}
		// A kid that is not in a fresh key set is the rotation case: the
		// provider signed with a key published after the last fetch. One
		// refresh is worth trying; more would let an attacker with a stream of
		// unknown kids turn this into a request amplifier.
	}

	if err := p.refresh(context.Background()); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return pick(kid, p.keys[kid], p.keys[kid] != nil, p.singular, len(p.keys))
}

// pick chooses a key, refusing the ambiguous case.
//
// An empty kid is allowed only when the provider publishes exactly one key.
// Trying each key until one verifies would mean accepting a token signed by any
// of them, which is a different and much weaker claim than the one being made.
func pick(kid string, key crypto.PublicKey, have bool, single crypto.PublicKey,
	n int) (crypto.PublicKey, error) {

	if have && key != nil {
		return key, nil
	}
	if kid == "" {
		if n == 1 && single != nil {
			return single, nil
		}
		return nil, fmt.Errorf(
			"the token names no key id and the provider publishes %d keys. "+
				"Trying each until one verifies would accept a token signed by "+
				"any of them", n)
	}
	return nil, fmt.Errorf("the provider does not publish a key with id %q", kid)
}

func (p *Provider) ttl() time.Duration {
	if p.TTL <= 0 {
		return DefaultTTL
	}
	return p.TTL
}

// refresh fetches the key set.
func (p *Provider) refresh(ctx context.Context) error {
	res, err := p.fetcher.Get(ctx, p.Discovery.JWKSURI)
	if err != nil {
		return fmt.Errorf("cannot read the key set: %w", err)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(res.Body, &set); err != nil {
		return fmt.Errorf("the key set is not JSON: %w", err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("the key set is empty")
	}
	if len(set.Keys) > 32 {
		return fmt.Errorf("the key set has %d keys, which is not a key set",
			len(set.Keys))
	}

	keys := map[string]crypto.PublicKey{}
	var single crypto.PublicKey
	for _, k := range set.Keys {
		// A key published for encryption is not a key to verify signatures
		// with, and using one for the other is how key confusion starts.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.public()
		if err != nil {
			continue // an unsupported curve or type is skipped, not fatal
		}
		keys[k.Kid] = pub
		single = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("the key set has no usable signing keys")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys, p.fetched = keys, time.Now()
	if len(keys) == 1 {
		p.singular = single
	} else {
		p.singular = nil
	}
	return nil
}

// jwk is one key from a JSON Web Key Set.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		// A modulus under 2048 bits is refused. Accepting a small key means a
		// provider that misconfigures itself downgrades everyone silently.
		if len(n)*8 < 2048 {
			return nil, fmt.Errorf("an RSA key of %d bits is too small", len(n)*8)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve,
			X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		// A point that is not on the curve is not a key. Accepting one is the
		// invalid-curve attack, which leaks the private key of whoever is
		// tricked into using it.
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("the published point is not on %s", k.Crv)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// -- the authorization request -----------------------------------------------

// Request is one sign-in attempt in progress.
//
// The verifier and the nonce are bound together: the value sent on the
// authorization request has to be the value checked inside the ID token, and
// keeping them in one object is what stops one being regenerated without the
// other.
type Request struct {
	State        string
	Nonce        string
	CodeVerifier string
	// RedirectURI is echoed to the token endpoint, where the provider checks it
	// matches the one from the authorization request.
	RedirectURI string
	CreatedAt   time.Time
}

// MaxRequestAge bounds how long a sign-in may take.
//
// Ten minutes. A state parameter that stays valid indefinitely is a CSRF token
// with no expiry, and one left in a browser's history is a replay.
const MaxRequestAge = 10 * time.Minute

// NewRequest generates the per-sign-in secrets.
func NewRequest(redirectURI string) (*Request, error) {
	state, err := randomString()
	if err != nil {
		return nil, err
	}
	nonce, err := randomString()
	if err != nil {
		return nil, err
	}
	// The verifier is 43-128 characters of unreserved alphabet, per RFC 7636.
	verifier, err := randomString()
	if err != nil {
		return nil, err
	}
	return &Request{
		State: state, Nonce: nonce, CodeVerifier: verifier,
		RedirectURI: redirectURI, CreatedAt: time.Now(),
	}, nil
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("no randomness available: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge is the S256 code challenge for this request.
func (r *Request) Challenge() string {
	sum := sha256.Sum256([]byte(r.CodeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Expired reports whether this attempt has taken too long.
func (r *Request) Expired(now time.Time) bool {
	return now.Sub(r.CreatedAt) > MaxRequestAge
}

// AuthorizationURL is where the browser is sent.
func (p *Provider) AuthorizationURL(clientID string, r *Request, scopes []string) string {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", r.RedirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", r.State)
	q.Set("nonce", r.Nonce)
	q.Set("code_challenge", r.Challenge())
	// S256 always. The plain method sends the verifier itself, which is PKCE
	// with the part that does the work removed.
	q.Set("code_challenge_method", "S256")

	sep := "?"
	if strings.Contains(p.Discovery.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return p.Discovery.AuthorizationEndpoint + sep + q.Encode()
}

// -- the token exchange ------------------------------------------------------

// Tokens is what the token endpoint returns.
type Tokens struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	// RefreshToken is deliberately read and deliberately not used. Storing one
	// means holding a credential that outlives every session it mints, which is
	// the opposite of what the short-lived session design is for.
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// Exchange trades an authorization code for tokens.
//
// The code verifier goes here, on the back channel, and nowhere else. That is
// the whole of PKCE: an attacker who intercepted the code on the front channel
// cannot use it, because they never saw the verifier that the challenge in the
// authorization request committed to.
func (p *Provider) Exchange(ctx context.Context, clientID, clientSecret string,
	r *Request, code string) (*Tokens, error) {

	if code == "" {
		return nil, fmt.Errorf("no authorization code")
	}
	if r.Expired(time.Now()) {
		return nil, fmt.Errorf(
			"this sign-in took longer than %s. A state parameter with no expiry "+
				"is a CSRF token with no expiry", MaxRequestAge)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.RedirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", r.CodeVerifier)

	res, err := p.fetcher.PostForm(ctx, p.Discovery.TokenEndpoint, form,
		clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("the token exchange failed: %w", err)
	}

	var tok Tokens
	if err := json.Unmarshal(res.Body, &tok); err != nil {
		return nil, fmt.Errorf("the token response is not JSON: %w", err)
	}
	if tok.Error != "" {
		return nil, fmt.Errorf("the provider refused the exchange: %s (%s)",
			tok.Error, tok.ErrorDesc)
	}
	if tok.IDToken == "" {
		return nil, fmt.Errorf("the response carries no ID token, so nobody was " +
			"authenticated")
	}
	return &tok, nil
}

// Verifier returns a verifier for tokens from this provider.
func (p *Provider) Verifier(clientID string) *Verifier {
	return &Verifier{
		Issuer: p.Discovery.Issuer, ClientID: clientID,
		Algorithms: p.Algorithms, Keys: p, Skew: 2 * time.Minute,
	}
}

// KeyCount reports how many signing keys are cached, for diagnostics.
func (p *Provider) KeyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.keys)
}

// Warm fetches the key set now rather than on the first sign-in, so a
// misconfigured provider fails at startup instead of when somebody tries to log
// in.
func (p *Provider) Warm(ctx context.Context) error { return p.refresh(ctx) }
