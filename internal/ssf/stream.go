// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package ssf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/quilzo/quilzo/internal/fetch"
)

// Asking a transmitter for a stream.
//
// The receiver creates the stream: it tells the transmitter where to push,
// with what header, and which events it wants, using an OAuth access token
// the transmitter issued it (the interoperability profile: client
// credentials, scopes ssf.manage and ssf.read). Every URL it calls comes from
// the transmitter's metadata and passes the same address rules as any other
// fetch, so a hostile metadata document cannot point a credentialed request
// inward.

// HTTP is the one call this needs, which fetch.Client makes.
type HTTP interface {
	Do(ctx context.Context, method, raw string, body []byte, headers map[string]string) (*fetch.Result, error)
}

// PushMethod is RFC 8935 delivery.
const PushMethod = "urn:ietf:rfc:8935"

// Transmitter is a transmitter's published configuration.
type Transmitter struct {
	Issuer                string   `json:"issuer"`
	JWKSURI               string   `json:"jwks_uri"`
	DeliveryMethods       []string `json:"delivery_methods_supported"`
	ConfigurationEndpoint string   `json:"configuration_endpoint"`
	StatusEndpoint        string   `json:"status_endpoint"`
	VerificationEndpoint  string   `json:"verification_endpoint"`
	SpecVersion           string   `json:"spec_version"`
}

// WellKnown is where an issuer's configuration is published: the well-known
// segment goes between the host and the issuer's path.
func WellKnown(issuer string) (string, error) {
	u, err := fetch.ValidateURL(issuer)
	if err != nil {
		return "", err
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("an issuer has no query or fragment")
	}
	path := strings.TrimSuffix(u.Path, "/")
	return u.Scheme + "://" + u.Host + "/.well-known/ssf-configuration" + path, nil
}

// Discover reads and checks a transmitter's configuration.
func Discover(ctx context.Context, h HTTP, issuer string) (*Transmitter, error) {
	issuer = strings.TrimSpace(issuer)
	where, err := WellKnown(issuer)
	if err != nil {
		return nil, err
	}
	res, err := h.Do(ctx, "GET", where, nil, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", where, err)
	}
	if res.Status != 200 {
		return nil, fmt.Errorf("%s answered %d; this issuer publishes no shared signals configuration", where, res.Status)
	}
	var t Transmitter
	if err := json.Unmarshal(res.Body, &t); err != nil {
		return nil, fmt.Errorf("the configuration is not JSON: %w", err)
	}
	if t.Issuer != issuer && t.Issuer != strings.TrimSuffix(issuer, "/") {
		return nil, fmt.Errorf("the configuration at %s says the issuer is %q; trusting it would make every issuer check compare against a value it chose", where, t.Issuer)
	}
	if t.JWKSURI == "" {
		return nil, fmt.Errorf("%s publishes no keys (jwks_uri), so nothing it sends could be verified", t.Issuer)
	}
	for name, u := range map[string]string{"jwks_uri": t.JWKSURI, "configuration_endpoint": t.ConfigurationEndpoint,
		"status_endpoint": t.StatusEndpoint, "verification_endpoint": t.VerificationEndpoint} {
		if u == "" {
			continue
		}
		if _, err := fetch.ValidateURL(u); err != nil {
			return nil, fmt.Errorf("the configuration's %s is not usable: %w", name, err)
		}
	}
	if len(t.DeliveryMethods) > 0 && !contains(t.DeliveryMethods, PushMethod) {
		return nil, fmt.Errorf("%s does not push events (RFC 8935), which is how this receives them", t.Issuer)
	}
	return &t, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// TokenEndpoint finds an issuer's OAuth token endpoint: authorization server
// metadata (RFC 8414) first, OpenID discovery second.
func TokenEndpoint(ctx context.Context, h HTTP, issuer string) (string, error) {
	u, err := fetch.ValidateURL(issuer)
	if err != nil {
		return "", err
	}
	path := strings.TrimSuffix(u.Path, "/")
	for _, where := range []string{
		u.Scheme + "://" + u.Host + "/.well-known/oauth-authorization-server" + path,
		strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
	} {
		res, err := h.Do(ctx, "GET", where, nil, map[string]string{"Accept": "application/json"})
		if err != nil || res.Status != 200 {
			continue
		}
		var m struct {
			Issuer        string `json:"issuer"`
			TokenEndpoint string `json:"token_endpoint"`
		}
		if json.Unmarshal(res.Body, &m) != nil || m.TokenEndpoint == "" {
			continue
		}
		if m.Issuer != "" && strings.TrimSuffix(m.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
			continue
		}
		if _, err := fetch.ValidateURL(m.TokenEndpoint); err != nil {
			return "", fmt.Errorf("the token endpoint is not usable: %w", err)
		}
		return m.TokenEndpoint, nil
	}
	return "", fmt.Errorf("%s publishes no OAuth token endpoint; give it with --token-url", issuer)
}

// ClientCredentials asks for an access token with a client id and secret.
// The secret goes to the token endpoint and nowhere else, and never into an
// error message.
func ClientCredentials(ctx context.Context, h HTTP, tokenURL, clientID, secret string, scopes []string) (string, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {strings.Join(scopes, " ")}}
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(clientID) + ":" + url.QueryEscape(secret)))
	res, err := h.Do(ctx, "POST", tokenURL, []byte(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json",
		"Authorization": "Basic " + basic,
	})
	if err != nil {
		return "", fmt.Errorf("cannot reach the token endpoint: %w", err)
	}
	var m struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(res.Body, &m)
	if res.Status != 200 || m.AccessToken == "" {
		why := m.Error
		if m.Description != "" {
			why += ": " + oneLine(m.Description)
		}
		if why == "" {
			why = fmt.Sprintf("status %d", res.Status)
		}
		return "", fmt.Errorf("the token endpoint refused: %s", why)
	}
	if m.TokenType != "" && !strings.EqualFold(m.TokenType, "Bearer") {
		return "", fmt.Errorf("the token endpoint issued a %q token, not a bearer token", m.TokenType)
	}
	return m.AccessToken, nil
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Stream is a stream's configuration as the transmitter returns it.
type Stream struct {
	ID              string   `json:"stream_id"`
	Issuer          string   `json:"iss"`
	Audience        any      `json:"aud"`
	EventsDelivered []string `json:"events_delivered"`
	Delivery        struct {
		Method      string `json:"method"`
		EndpointURL string `json:"endpoint_url"`
	} `json:"delivery"`
}

// Audiences lists the stream's audience whether it came as one or many.
func (s Stream) Audiences() []string {
	switch a := s.Audience.(type) {
	case string:
		return []string{a}
	case []any:
		var out []string
		for _, v := range a {
			if x, ok := v.(string); ok {
				out = append(out, x)
			}
		}
		return out
	}
	return nil
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token, "Accept": "application/json",
		"Content-Type": "application/json"}
}

func answer(res *fetch.Result, what string, ok ...int) error {
	for _, s := range ok {
		if res.Status == s {
			return nil
		}
	}
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Message     string `json:"message"`
	}
	_ = json.Unmarshal(res.Body, &e)
	why := strings.TrimSpace(e.Error + " " + oneLine(e.Description+" "+e.Message))
	if why == "" {
		why = "no reason given"
	}
	return fmt.Errorf("%s: the transmitter answered %d (%s)", what, res.Status, why)
}

// CreateStream asks for a push stream to endpoint, with authHeader sent on
// every push so the endpoint can tell the transmitter from anybody else.
func (t *Transmitter) CreateStream(ctx context.Context, h HTTP, token, endpoint, authHeader, description string, events []string) (*Stream, error) {
	if t.ConfigurationEndpoint == "" {
		return nil, fmt.Errorf("%s publishes no configuration endpoint, so a stream has to be made in its own console", t.Issuer)
	}
	if _, err := fetch.ValidateURL(endpoint); err != nil {
		return nil, fmt.Errorf("the receiving address must be https and public: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"delivery": map[string]string{"method": PushMethod, "endpoint_url": endpoint,
			"authorization_header": authHeader},
		"events_requested": events,
		"description":      description,
	})
	res, err := h.Do(ctx, "POST", t.ConfigurationEndpoint, body, bearer(token))
	if err != nil {
		return nil, err
	}
	if err := answer(res, "creating the stream", 200, 201); err != nil {
		return nil, err
	}
	var s Stream
	if err := json.Unmarshal(res.Body, &s); err != nil || s.ID == "" {
		return nil, fmt.Errorf("the transmitter's answer has no stream id")
	}
	if s.Issuer != "" && s.Issuer != t.Issuer {
		return nil, fmt.Errorf("the stream says it is from %q, not %q", s.Issuer, t.Issuer)
	}
	return &s, nil
}

// RequestVerification asks the transmitter to send a verification event
// carrying state, which proves the stream reaches this receiver.
func (t *Transmitter) RequestVerification(ctx context.Context, h HTTP, token, streamID, state string) error {
	if t.VerificationEndpoint == "" {
		return fmt.Errorf("%s publishes no verification endpoint", t.Issuer)
	}
	body, _ := json.Marshal(map[string]string{"stream_id": streamID, "state": state})
	res, err := h.Do(ctx, "POST", t.VerificationEndpoint, body, bearer(token))
	if err != nil {
		return err
	}
	return answer(res, "asking for verification", 200, 202, 204)
}

// Status reads whether the transmitter is sending on a stream.
func (t *Transmitter) Status(ctx context.Context, h HTTP, token, streamID string) (string, string, error) {
	if t.StatusEndpoint == "" {
		return "", "", fmt.Errorf("%s publishes no status endpoint", t.Issuer)
	}
	res, err := h.Do(ctx, "GET", t.StatusEndpoint+"?stream_id="+url.QueryEscape(streamID), nil, bearer(token))
	if err != nil {
		return "", "", err
	}
	if err := answer(res, "reading the stream status", 200); err != nil {
		return "", "", err
	}
	var s struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(res.Body, &s); err != nil {
		return "", "", fmt.Errorf("the status is not JSON")
	}
	return s.Status, oneLine(s.Reason), nil
}

// DeleteStream asks the transmitter to stop and forget the stream.
func (t *Transmitter) DeleteStream(ctx context.Context, h HTTP, token, streamID string) error {
	if t.ConfigurationEndpoint == "" {
		return fmt.Errorf("%s publishes no configuration endpoint", t.Issuer)
	}
	res, err := h.Do(ctx, "DELETE", t.ConfigurationEndpoint+"?stream_id="+url.QueryEscape(streamID), nil, bearer(token))
	if err != nil {
		return err
	}
	return answer(res, "deleting the stream", 200, 202, 204, 404)
}
