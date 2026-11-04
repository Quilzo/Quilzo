// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agentcred"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
)

// A browser grant takes two kinds of proof of possession: a token bound to
// a key, with a DPoP proof, and an agent credential, with its own proof.
// Pinned before the two proof checks are merged: each is let in with a
// proof made for this request, once, and each is refused with no proof,
// with the proof again, and with a proof made for another address.
func TestTheBrowserEndpointTakesAKeyBoundTokenAndAnAgentCredentialAlike(t *testing.T) {
	r := newIfaceRig(t)
	r.oauth = false
	r.srv.Throttle = nil
	r.srv.Interface.BrowserOffered = func(name string) bool { return name == "shop" }
	r.srv.Interface.Browser = func(req *http.Request, c *mcp.Caller, name string) (*mcp.Server, error) {
		s := mcp.NewServer("quilzo-browser-"+name, "test")
		s.Authorise = func(mcp.Operation) error { return nil }
		s.Register(mcp.Operation{Name: "whoami", NeedsRole: "reader", Summary: "who"},
			func(map[string]any) (any, error) { return "you are " + c.Principal + " via " + c.Client, nil })
		return s, nil
	}
	const here = "http://example.com/mcp/browser/shop"

	// The agent credential, issued and checked by agentcred as the
	// command's credentialCaller does, at the address the endpoint names.
	_, issuer, _ := ed25519.GenerateKey(rand.Reader)
	_, holder, _ := ed25519.GenerateKey(rand.Reader)
	pub := issuer.Public().(ed25519.PublicKey)
	now := time.Now()
	credential, err := agentcred.Issue(issuer, "http://example.com", agentcred.Credential{Agent: "buyer", Sponsor: "lee",
		Grant: "browser:shop", Act: true, Holder: holder.Public().(ed25519.PublicKey), ValidUntil: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	credReplays := &agentcred.Replays{}
	r.srv.Interface.Credential = func(req *http.Request, token, url, grant string) (auth.Token, error) {
		c, err := agentcred.Verify(token, map[string]ed25519.PublicKey{agentcred.KeyID(pub): pub}, time.Now())
		if err != nil {
			return auth.Token{}, err
		}
		if err := agentcred.CheckProof(c, req.Header.Get("Agent-Proof"), req.Method, url, time.Now(), credReplays); err != nil {
			return auth.Token{}, err
		}
		return auth.Token{Principal: c.Sponsor, Client: "agent:" + c.Agent, Role: auth.RoleAuthor}, nil
	}

	// The token bound to a program's key.
	key, thumb := programKey(t)
	bound, tok, err := r.srv.Tokens.IssueSession("program", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.srv.Tokens.BindKey(tok.ID, thumb); err != nil {
		t.Fatal(err)
	}

	call := func(scheme, token string, headers map[string]string) *httptest.ResponseRecorder {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"quilzo_read","arguments":{"operation":"whoami"},` +
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
		req := httptest.NewRequest("POST", "/mcp/browser/shop", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "quilzo_read")
		req.Header.Set("Authorization", scheme+" "+token)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		r.srv.Handler().ServeHTTP(w, req)
		return w
	}
	agentProof := func(url string) map[string]string {
		p, err := agentcred.Prove(holder, credential, "POST", url, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"Agent-Proof": p}
	}
	dpopProof := func(url string) map[string]string {
		return map[string]string{"DPoP": proved(t, key, "POST", url, bound)}
	}

	for _, kind := range []struct {
		name, scheme, token, who string
		proof                    func(url string) map[string]string
	}{
		{"a key-bound token", "DPoP", bound, "you are editor via ", dpopProof},
		{"an agent credential", "Bearer", credential, "you are lee via agent:buyer", agentProof},
	} {
		t.Run(kind.name, func(t *testing.T) {
			good := kind.proof(here)
			if w := call(kind.scheme, kind.token, good); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), kind.who) {
				t.Fatalf("with its proof: %d %s", w.Code, w.Body.String())
			}
			if w := call(kind.scheme, kind.token, good); w.Code == http.StatusOK {
				t.Error("the same proof was accepted twice")
			}
			if w := call(kind.scheme, kind.token, nil); w.Code == http.StatusOK {
				t.Error("accepted with no proof")
			}
			for _, other := range []string{"http://example.com/mcp", "http://example.com/mcp/browser/bank"} {
				if w := call(kind.scheme, kind.token, kind.proof(other)); w.Code == http.StatusOK {
					t.Errorf("accepted with a proof made for %s", other)
				}
			}
		})
	}
	// Refused, it is told what the door takes, DPoP and its algorithms
	// included, as /mcp and the gateway tell it. The browser grant answered
	// "Bearer" alone, so a client holding a key-bound token was not told
	// this door takes a proof at all.
	if w := call("Bearer", bound, nil); w.Code != http.StatusUnauthorized ||
		!strings.Contains(strings.Join(w.Header().Values("WWW-Authenticate"), " "), `DPoP algs="`) {
		t.Errorf("the key-bound token's refusal does not offer DPoP: %d %v", w.Code, w.Header().Values("WWW-Authenticate"))
	}
}
