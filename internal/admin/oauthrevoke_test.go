// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"testing"
)

// An app that revokes its access token at /oauth/revoke is disconnected:
// the access token stops working at /mcp and the refresh token is refused.
//
// Only a refresh token was looked for. An access token was answered 200,
// which RFC 7009 asks of a token the server does not know, and nothing was
// revoked, so an app that signed out by revoking the token it used was
// told it had and kept both working. Another app presenting the token
// changes nothing.
func TestRevokingAnAccessTokenDisconnectsTheApp(t *testing.T) {
	r := newIfaceRig(t)
	out := r.connect(t)
	access, refresh := out["access_token"].(string), out["refresh_token"].(string)
	revoke := func(client string) {
		t.Helper()
		if w := r.do(t, "POST", "/oauth/revoke", "", url.Values{"token": {access}, "client_id": {client},
			"token_type_hint": {"access_token"}}, nil); w.Code != 200 {
			t.Fatalf("revoking: %d %s", w.Code, w.Body.String())
		}
	}
	revoke("https://other.example/client.json")
	if w := r.mcpCall(t, access); w.Code != 200 {
		t.Fatalf("another app's revocation ended this one's token: %d", w.Code)
	}
	revoke(testApp)
	if w := r.mcpCall(t, access); w.Code != 401 {
		t.Errorf("the revoked access token still works at /mcp: %d %s", w.Code, w.Body.String())
	}
	if w := r.do(t, "POST", "/oauth/token", "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {testApp}}, nil); w.Code != 400 {
		// The answer is not printed: when this fails, it holds new tokens.
		t.Errorf("the refresh token still works after the app revoked its access: %d", w.Code)
	}
}
