// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package federate lets a program another issuer vouches for exchange that
// issuer's identity token for a short Quilzo token, with no secret kept
// anywhere.
//
// A CI job has always been given a long-lived token as a repository secret,
// which every workflow in the repository, and whoever can change one, can
// read and keep. GitHub Actions, GitLab CI and the clouds instead give each
// job a signed identity token naming the repository, the branch, the
// environment and the run, valid for minutes. A trust declared here says
// which issuer, which audience and which exact claims are acceptable, and
// what the job gets: a principal, a role on part of the store, and a life
// of at most an hour. Nothing is stored in the repository, and a token
// taken from a job's log is gone before anybody finds it.
//
// The checks are the ones an ID token gets (internal/oidc): an issuer named
// exactly, keys from its own discovery document, an agreed algorithm, the
// audience, the times. Then every claim the trust pins must match, and the
// token's identifier is used once.
package federate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oidc"
)

// Trust admits the jobs of one issuer whose claims match.
type Trust struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// Claims is what a token must say: claim to value, exactly, or to a
	// prefix when the value ends in *.
	Claims    map[string]string `json:"claims"`
	Principal string            `json:"principal"`
	Role      auth.Role         `json:"role"`
	Resource  string            `json:"resource"`
	ReadOnly  bool              `json:"read_only,omitempty"`
	// TTL is how long the token a job gets lasts, at most an hour.
	TTL       string    `json:"ttl"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
}

// GitHub and GitLab are the issuers people name most.
const (
	GitHub = "https://token.actions.githubusercontent.com"
	GitLab = "https://gitlab.com"
)

var reName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

// identifying are the claims that say which workload a token is for; a
// trust pins at least one, so it never admits every job an issuer signs.
var identifying = map[string]bool{"sub": true, "repository": true, "repository_id": true,
	"project_path": true, "project_id": true, "job_workflow_ref": true, "workflow_ref": true}

// Validate checks a trust on its own.
func (t Trust) Validate() error {
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if !reName.MatchString(t.Name) {
		bad("the name %q is not usable: lower-case letters, digits and hyphens", t.Name)
	}
	if !strings.HasPrefix(t.Issuer, "https://") || strings.ContainsAny(t.Issuer, " ?#") {
		bad("the issuer is an https address with no query, such as %s", GitHub)
	}
	if strings.TrimSpace(t.Audience) == "" {
		bad("an audience is needed: the value jobs ask their issuer to put in aud, such as this store's address")
	}
	pinned := false
	for k, v := range t.Claims {
		if strings.TrimSpace(v) == "" || strings.TrimSuffix(v, "*") == "" {
			bad("the claim %s needs a value, not just *", k)
		}
		if identifying[k] && !strings.HasSuffix(v, "*") {
			pinned = true
		}
	}
	if !pinned {
		bad("a trust pins at least one claim naming the workload exactly: sub, repository, repository_id, project_path, project_id or a workflow ref")
	}
	if strings.TrimSpace(t.Principal) == "" {
		bad("a principal is needed: who the job acts as")
	}
	if !t.Role.Valid() || t.Role == auth.RoleAdmin {
		bad("a job is a reader, author or publisher; never an administrator")
	}
	if d, err := time.ParseDuration(t.TTL); err != nil || d <= 0 || d > auth.MaxFederatedTTL {
		bad("the life of a job's token is a duration up to %s, such as 15m", auth.MaxFederatedTTL)
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("the trust is not usable:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// Life is the trust's token life.
func (t Trust) Life() time.Duration {
	d, _ := time.ParseDuration(t.TTL)
	return d
}

// Keys gives an issuer's signing keys and the algorithms agreed with it.
type Keys func(ctx context.Context, issuer string) (oidc.KeySource, []oidc.Algorithm, error)

// Replays remembers the identifiers of tokens already exchanged.
type Replays struct {
	mu   sync.Mutex
	seen map[string]int64
}

func (r *Replays) first(id string, exp int64, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]int64{}
	}
	for k, e := range r.seen {
		if now.Unix() > e+int64(skew/time.Second) {
			delete(r.seen, k)
		}
	}
	if _, ok := r.seen[id]; ok {
		return false
	}
	r.seen[id] = exp
	return true
}

const (
	skew = time.Minute
	// maxAge is how old a token may be when it is exchanged: a job asks
	// for one when it needs it.
	maxAge = time.Hour
)

// ErrNotAdmitted is a token no trust admits.
var ErrNotAdmitted = errors.New("no trust admits this token")

// Admit checks an identity token and finds the first trust it satisfies.
// The claims come back for the record.
func Admit(ctx context.Context, assertion string, trusts []Trust, keys Keys, now time.Time, seen *Replays) (*Trust, map[string]any, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || len(assertion) > 16<<10 {
		return nil, nil, fmt.Errorf("%w: it is not a signed JWT", ErrNotAdmitted)
	}
	// The issuer is read before the signature only to choose whose keys to
	// check it with; nothing else is believed until it verifies.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the payload is not base64url", ErrNotAdmitted)
	}
	var peek struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(raw, &peek) != nil || peek.Iss == "" {
		return nil, nil, fmt.Errorf("%w: it names no issuer", ErrNotAdmitted)
	}
	var mine []Trust
	for _, t := range trusts {
		if t.Issuer == peek.Iss {
			mine = append(mine, t)
		}
	}
	if len(mine) == 0 {
		return nil, nil, fmt.Errorf("%w: no trust names the issuer %s", ErrNotAdmitted, peek.Iss)
	}
	ks, algs, err := keys(ctx, peek.Iss)
	if err != nil {
		return nil, nil, fmt.Errorf("the keys of %s could not be read: %w", peek.Iss, err)
	}
	payload, err := oidc.VerifyJWS(assertion, algs, ks, peek.Iss, "an identity token",
		func(t string) bool { return t == "" || strings.EqualFold(t, "JWT") })
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNotAdmitted, err)
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, nil, fmt.Errorf("%w: the claims are not JSON", ErrNotAdmitted)
	}
	num := func(k string) int64 {
		f, _ := c[k].(float64)
		return int64(f)
	}
	exp, nbf, iat := num("exp"), num("nbf"), num("iat")
	switch {
	case c["iss"] != peek.Iss:
		return nil, nil, fmt.Errorf("%w: the issuer changed after the signature", ErrNotAdmitted)
	case exp == 0 || now.After(time.Unix(exp, 0).Add(skew)):
		return nil, nil, fmt.Errorf("%w: it has expired", ErrNotAdmitted)
	case nbf != 0 && now.Add(skew).Before(time.Unix(nbf, 0)):
		return nil, nil, fmt.Errorf("%w: it is not valid yet", ErrNotAdmitted)
	case iat == 0 || now.Sub(time.Unix(iat, 0)) > maxAge || time.Unix(iat, 0).After(now.Add(skew)):
		return nil, nil, fmt.Errorf("%w: it was issued more than %s ago, or in the future", ErrNotAdmitted, maxAge)
	}
	var audiences []string
	switch a := c["aud"].(type) {
	case string:
		audiences = []string{a}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				audiences = append(audiences, s)
			}
		}
	}
	var why []string
	for i := range mine {
		t := &mine[i]
		if !contains(audiences, t.Audience) {
			why = append(why, fmt.Sprintf("%s: the audience is %v, not %s", t.Name, audiences, t.Audience))
			continue
		}
		if miss := t.mismatch(c); miss != "" {
			why = append(why, fmt.Sprintf("%s: %s", t.Name, miss))
			continue
		}
		id, _ := c["jti"].(string)
		if id == "" {
			id = fmt.Sprintf("%s|%v|%d", peek.Iss, c["sub"], iat)
		}
		if seen != nil && !seen.first(peek.Iss+"|"+id, exp, now) {
			return nil, nil, fmt.Errorf("%w: this token was exchanged before", ErrNotAdmitted)
		}
		return t, c, nil
	}
	sort.Strings(why)
	return nil, nil, fmt.Errorf("%w: %s", ErrNotAdmitted, strings.Join(why, "; "))
}

// mismatch is the first pinned claim the token does not satisfy.
func (t Trust) mismatch(c map[string]any) string {
	keys := make([]string, 0, len(t.Claims))
	for k := range t.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		want := t.Claims[k]
		v, ok := c[k]
		if !ok {
			return k + " is missing"
		}
		got := fmt.Sprint(v)
		if f, isNum := v.(float64); isNum {
			got = fmt.Sprintf("%.0f", f)
		}
		if prefix, wild := strings.CutSuffix(want, "*"); wild {
			if !strings.HasPrefix(got, prefix) {
				return fmt.Sprintf("%s is %q, not %s", k, got, want)
			}
		} else if got != want {
			return fmt.Sprintf("%s is %q, not %q", k, got, want)
		}
	}
	return ""
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
