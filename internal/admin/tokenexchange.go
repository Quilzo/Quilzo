// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dpop"
	"github.com/quilzo/quilzo/internal/federate"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Short-lived and bound credentials for programs.
//
// A program used to hold one long-lived bearer token, and a bearer token
// works for whoever holds it. Two things change that. A program exchanges
// what it holds for a token that lasts minutes (RFC 8693), and a CI job
// exchanges the identity token its platform signs for each run, so it holds
// no secret at all (internal/federate). And a token can be bound to a key,
// so it works only with a fresh proof made by that key (RFC 9449,
// internal/dpop): the agent interface, the model gateway and A2A check the
// proof; everything else refuses a bound token outright.

// Federation reaches the trusts that admit other issuers' jobs.
type Federation struct {
	Trusts func() ([]federate.Trust, error)
	Keys   federate.Keys
}

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	typeAccessToken    = "urn:ietf:params:oauth:token-type:access_token"
	typeIDToken        = "urn:ietf:params:oauth:token-type:id_token"
	typeJWT            = "urn:ietf:params:oauth:token-type:jwt"
)

// authzToken is the token in a request's Authorization header and the
// scheme it came under.
func authzToken(r *http.Request) (token, scheme string) {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(t), "Bearer"
	}
	if t, ok := strings.CutPrefix(h, "DPoP "); ok {
		return strings.TrimSpace(t), "DPoP"
	}
	return "", ""
}

// requestURL is the address a request was made to, as a proof names it.
func (s *Server) requestURL(r *http.Request) string { return s.ownOrigin(r) + r.URL.Path }

// proofOf checks the one DPoP proof a request carries, made for it and for
// the token presented, and returns the key's thumbprint.
func (s *Server) proofOf(r *http.Request, token string) (string, error) {
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return "", fmt.Errorf("%w: a request carries exactly one DPoP proof", dpop.ErrProof)
	}
	return dpop.Check(proofs[0], r.Method, s.requestURL(r), token, time.Now(), s.proofs)
}

// tokenChallenge answers a refused token with what this server accepts: a
// Bearer token, or a DPoP-bound one, and what was wrong.
func tokenChallenge(w http.ResponseWriter, extra string, err error) {
	bearer, proof := `Bearer realm="quilzo"`+extra, `DPoP algs="`+dpop.AlgorithmNames()+`"`
	switch {
	case errors.Is(err, dpop.ErrProof):
		proof += `, error="invalid_dpop_proof"`
	case errors.Is(err, auth.ErrKeyBound):
		proof += `, error="invalid_token"`
	case err != nil:
		bearer += `, error="invalid_token"`
	}
	w.Header().Add("WWW-Authenticate", bearer)
	w.Header().Add("WWW-Authenticate", proof)
}

type exchangeAnswer struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
}

// handleTokenExchange is RFC 8693 token exchange: a Quilzo token for a
// narrower one that lasts minutes, or a job's identity token for a token a
// trust says it may have. Bound to a key when the request carries a proof.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int, kind, why string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": kind, "error_description": why})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed, "invalid_request", "a token is exchanged with POST")
		return
	}
	if s.ReloadTokens != nil {
		s.ReloadTokens()
	}
	if s.Tokens == nil {
		fail(http.StatusServiceUnavailable, "server_error", "this build was started without a token store")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest, "invalid_request", "the body is a form")
		return
	}
	f := r.PostForm
	switch {
	case f.Get("grant_type") != grantTokenExchange:
		fail(http.StatusBadRequest, "unsupported_grant_type", "the grant type is "+grantTokenExchange)
		return
	case f.Get("subject_token") == "":
		fail(http.StatusBadRequest, "invalid_request", "subject_token is the token being exchanged")
		return
	case f.Get("requested_token_type") != "" && f.Get("requested_token_type") != typeAccessToken:
		fail(http.StatusBadRequest, "invalid_request", "an access token is what this issues")
		return
	case f.Get("actor_token") != "":
		fail(http.StatusBadRequest, "invalid_request", "acting for another is not exchanged here")
		return
	}
	sub := throttle.Subject{Source: sourceOf(r)}
	if s.Throttle != nil {
		if d := s.Throttle.Check(sub); !d.Allowed {
			fail(http.StatusTooManyRequests, "invalid_request", "too many failed attempts from this address. "+d.Why)
			return
		}
	}
	failed := func(kind string, err error) {
		if s.Throttle != nil {
			if d, alert := s.Throttle.Fail(sub); alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(sub.Source, d.Failures)
			}
		}
		code := http.StatusBadRequest
		if errors.Is(err, dpop.ErrProof) {
			kind = "invalid_dpop_proof"
		}
		fail(code, kind, err.Error())
	}

	thumb := ""
	if len(r.Header.Values("DPoP")) > 0 {
		var err error
		if thumb, err = s.proofOf(r, ""); err != nil {
			failed("invalid_dpop_proof", err)
			return
		}
	}
	role := auth.Role(strings.TrimSpace(f.Get("scope")))
	if role != "" && !role.Valid() {
		failed("invalid_scope", fmt.Errorf("the scope is a role: reader, author, publisher or admin"))
		return
	}
	resource := strings.TrimSpace(f.Get("resource"))
	now := time.Now()

	var secret string
	var tok auth.Token
	detail := map[string]string{"bound": fmt.Sprint(thumb != "")}
	switch f.Get("subject_token_type") {
	case typeAccessToken:
		var err error
		secret, tok, err = s.Tokens.ExchangeProved(f.Get("subject_token"), role, resource, 0, thumb, now)
		if err != nil {
			failed("invalid_grant", err)
			return
		}
		detail["how"] = "narrowed"
	case typeIDToken, typeJWT:
		if s.Federation == nil || s.Federation.Trusts == nil || s.Federation.Keys == nil {
			failed("invalid_grant", errors.New("this store trusts no other issuer"))
			return
		}
		trusts, err := s.Federation.Trusts()
		if err != nil {
			fail(http.StatusInternalServerError, "server_error", "the trusts could not be read")
			return
		}
		t, claims, err := federate.Admit(r.Context(), f.Get("subject_token"), trusts, s.Federation.Keys, now, s.admitted)
		if err != nil {
			failed("invalid_grant", err)
			return
		}
		if role == "" {
			role = t.Role
		}
		if !t.Role.AtLeast(role) {
			failed("invalid_scope", fmt.Errorf("the trust %s gives %s at most", t.Name, t.Role))
			return
		}
		if resource == "" {
			resource = t.Resource
		}
		if !auth.Covers(t.Resource, resource) {
			failed("invalid_target", fmt.Errorf("the trust %s reaches %s, not %s", t.Name, t.Resource, resource))
			return
		}
		run := fmt.Sprint(claims["run_id"])
		if run == "<nil>" {
			run = fmt.Sprint(claims["jti"])
		}
		secret, tok, err = s.Tokens.IssueFederated("trust:"+t.Name+" run "+clipText(run, 40), t.Principal, role, resource,
			auth.Scope{ReadOnly: t.ReadOnly}, t.Life(), thumb, now)
		if err != nil {
			failed("invalid_grant", err)
			return
		}
		detail["how"], detail["trust"] = "federated", t.Name
		for _, k := range []string{"repository", "ref", "environment", "project_path", "run_id"} {
			if v, ok := claims[k].(string); ok {
				detail[k] = clipText(v, 120)
			}
		}
	default:
		failed("invalid_request", errors.New("subject_token_type is a Quilzo access token, or an identity token (id_token or jwt) from an issuer a trust names"))
		return
	}
	if s.Throttle != nil {
		s.Throttle.Succeed(throttle.Subject{Principal: tok.Principal})
	}
	if err := s.save(); err != nil {
		fail(http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	detail["by"], detail["for"], detail["role"], detail["credential"] = tok.Principal, tok.Principal, string(tok.Role), tok.ID
	s.audit("credential.exchanged", tok.Resource, detail)
	kind := "Bearer"
	if tok.Key != "" {
		kind = "DPoP"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exchangeAnswer{AccessToken: secret, IssuedTokenType: typeAccessToken,
		TokenType: kind, ExpiresIn: tok.ExpiresAt - now.Unix()})
}
