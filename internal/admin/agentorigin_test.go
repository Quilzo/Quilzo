// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a2a"
	"github.com/quilzo/quilzo/internal/mcp"
)

// A page on a name pointed at this machine (DNS rebinding) is not the
// agent interface's own once admin.base_url says where the admin is.
//
// Every door of the interface took its own origin from the request's Host
// header. A page at http://rebound.example, its name pointed here, sends
// Host and Origin both rebound.example, which compared equal, so the one
// check the transport has against rebinding (mcp.Endpoint, and Origin
// alone at /a2a) let every such page through although base_url named the
// admin's real address. Without base_url, the Host header is all there is
// to go on, and is still what decides.
func TestARebindingPageIsNotTheInterfacesOwn(t *testing.T) {
	r := newIfaceRig(t)
	r.srv.Interface.Offered = func(name string) bool { return name == "tracker" }
	r.srv.Interface.Gateway = func(*http.Request, *mcp.Caller, string) (*mcp.Server, error) {
		return mcp.NewServer("gw", "test"), nil
	}
	r.srv.Interface.BrowserOffered = func(name string) bool { return name == "shop" }
	r.srv.Interface.Browser = func(*http.Request, *mcp.Caller, string) (*mcp.Server, error) {
		return mcp.NewServer("quilzo-browser-shop", "test"), nil
	}
	r.srv.Interface.Tasks = func() bool { return true }
	r.srv.Interface.A2A = func(*mcp.Caller) a2a.Host {
		return a2a.Host{Agents: func() []string { return []string{"tidy"} },
			Send: func(*http.Request, string, string) (a2a.Task, error) {
				return a2a.Task{ID: "t1", Status: a2a.TaskStatus{State: a2a.StateCompleted}}, nil
			}}
	}
	// As a browser sends it: from the page's own address, which is where
	// the request goes, so the browser calls it same-origin.
	call := func(path, origin string) *httptest.ResponseRecorder {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
		if path == "/a2a" {
			body = `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":` +
				`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"tidy up"}]}}}`
		}
		req := httptest.NewRequest("POST", origin+path, strings.NewReader(body))
		if strings.HasPrefix(origin, "https:") {
			req.TLS = &tls.ConnectionState{}
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/list")
		req.Header.Set("A2A-Version", "1.0")
		req.Header.Set("Authorization", "Bearer "+r.token)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		r.srv.Handler().ServeHTTP(w, req)
		return w
	}
	doors := []string{"/mcp", "/mcp/gateway/tracker", "/mcp/browser/shop", "/a2a"}
	for _, path := range doors {
		if w := call(path, "http://rebound.example"); w.Code != http.StatusForbidden {
			t.Errorf("%s took a rebound page's request: %d %s", path, w.Code, w.Body)
		}
		for _, own := range []string{"https://admin.example.org", "https://ADMIN.example.org"} {
			if w := call(path, own); w.Code != http.StatusOK {
				t.Errorf("%s refused a page at its own address, %s: %d %s", path, own, w.Code, w.Body)
			}
		}
	}
	r.oauth = false
	for _, path := range doors {
		if w := call(path, "http://rebound.example"); w.Code != http.StatusOK {
			t.Errorf("%s, with no address set, refused the page at the address it was reached by: %d %s", path, w.Code, w.Body)
		}
	}
}
