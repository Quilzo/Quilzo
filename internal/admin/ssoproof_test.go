// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/oidc"
)

// An ID token counts as two factors only when it says so, about a sign-in
// recent enough to be this one.
func TestAnIDTokenIsTwoFactorsOnlyWhenItSaysSo(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	recent := float64(now.Add(-10 * time.Minute).Unix())
	o := &OIDC{MFAACR: []string{"urn:okta:loa:2fa:any"}}
	for _, c := range []struct {
		name string
		raw  map[string]any
		mfa  bool
	}{
		{"amr naming mfa", map[string]any{"auth_time": recent, "amr": []any{"pwd", "mfa"}}, true},
		{"amr with a password alone", map[string]any{"auth_time": recent, "amr": []any{"pwd"}}, false},
		{"amr that is not a list", map[string]any{"auth_time": recent, "amr": "mfa"}, false},
		{"an acr the operator named", map[string]any{"auth_time": recent, "acr": "urn:okta:loa:2fa:any"}, true},
		{"an acr nobody named", map[string]any{"auth_time": recent, "acr": "urn:okta:loa:1fa:pwd"}, false},
		{"no auth_time", map[string]any{"amr": []any{"mfa"}}, false},
		{"a sign-in days ago", map[string]any{"auth_time": float64(now.Add(-72 * time.Hour).Unix()), "amr": []any{"mfa"}}, false},
		{"nothing said", map[string]any{"auth_time": recent}, false},
	} {
		p := o.proof(&oidc.Claims{Raw: c.raw}, 8*time.Hour, now)
		if p.MFA != c.mfa || p.Said == "" {
			t.Errorf("%s: %+v", c.name, p)
		}
		if want := map[bool]string{true: "sso", false: "sso-1fa"}[c.mfa]; p.method() != want {
			t.Errorf("%s: method %s", c.name, p.method())
		}
	}
	if (&OIDC{MFAACR: []string{""}}).proof(&oidc.Claims{Raw: map[string]any{"auth_time": recent}}, 8*time.Hour, now).MFA {
		t.Error("a missing acr matched an empty name")
	}
	if o.proof(&oidc.Claims{Raw: map[string]any{"amr": []any{"mfa"}}}, 0, now).MFA {
		t.Error("with no age asked for, a token that does not say when counted")
	}
}
