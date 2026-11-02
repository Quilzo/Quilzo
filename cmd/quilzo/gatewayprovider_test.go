// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/gateway"
)

func writeProviders(t *testing.T, root, body string) {
	t.Helper()
	if err := os.WriteFile(providersPath(root), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A route that names a provider sends its key the way the provider takes
// it, with the provider's headers, from a sealed credential, and nothing
// else: no Authorization header carrying the key twice.
func TestAProviderRouteSpeaksItsProvidersWay(t *testing.T) {
	root := demoStore(t)
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`))
	}))
	defer srv.Close()
	writeProviders(t, root, `{"providers":[{"id":"here","name":"A model here","group":"local","where":"this machine",
		"wire":"openai-chat","base":"`+srv.URL+`/v1","auth":"header:x-api-key","headers":{"x-team":"site"},
		"local":true,"verified":"unverified","data":{"trains":"no","retention":"none","residency":"here"}}]}`)
	t.Setenv("QUILZO_SECRET_HERE_KEY", "k-123")
	r := gateway.Route{Name: "here", Provider: "here", Model: "m", KeySecret: "here-key"}
	m, err := routeModel(root, r)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := m.Complete(context.Background(), "be brief", "hi"); err != nil || out != "hello" {
		t.Fatalf("%q %v", out, err)
	}
	h := <-seen
	if h.Get("X-Api-Key") != "k-123" || h.Get("X-Team") != "site" || h.Get("Authorization") != "" {
		t.Fatalf("%v", h)
	}
}

// A route reaches its provider and nothing else: an address on another
// host is refused when the route is built, and a hosted provider is never
// reached at this machine's addresses, where a key could be read.
func TestAProviderRouteReachesItsProviderOnly(t *testing.T) {
	root := demoStore(t)
	t.Setenv("QUILZO_SECRET_OPENAI", "sk-test")
	if _, err := routeModel(root, gateway.Route{Name: "o", Provider: "openai", Model: "gpt",
		KeySecret: "openai", URL: "https://evil.example/v1"}); err == nil || !strings.Contains(err.Error(), "nothing else") {
		t.Fatalf("a route on another host was built: %v", err)
	}
	m, err := routeModel(root, gateway.Route{Name: "o", Provider: "openai", Model: "gpt", KeySecret: "openai"})
	if err != nil || m.Host != "api.openai.com" || m.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("%+v %v", m, err)
	}
	// A hosted profile pointing at this machine: built, and refused at the dial.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a hosted provider was reached at this machine's address")
	}))
	defer srv.Close()
	writeProviders(t, root, `{"providers":[{"id":"inside","name":"Inside","group":"host","where":"x",
		"wire":"openai-chat","base":"`+srv.URL+`/v1","auth":"bearer","key":"inside","verified":"unverified",
		"data":{"trains":"no","retention":"none","residency":"here"}}]}`)
	t.Setenv("QUILZO_SECRET_INSIDE", "sk-inside")
	m, err = routeModel(root, gateway.Route{Name: "i", Provider: "inside", Model: "m", KeySecret: "inside"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Complete(context.Background(), "", "hi"); err == nil || !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("%v", err)
	}
}

// A hosted provider's route without its key says how to keep one sealed,
// and a provider that does not exist says where to look.
func TestAProviderRouteSaysWhatItNeeds(t *testing.T) {
	root := demoStore(t)
	_, err := routeModel(root, gateway.Route{Name: "g", Provider: "groq", Model: "llama"})
	if err == nil || !strings.Contains(err.Error(), "quilzo secret set groq") {
		t.Fatalf("%v", err)
	}
	if _, err := routeModel(root, gateway.Route{Name: "x", Provider: "nobody", Model: "m"}); err == nil ||
		!strings.Contains(err.Error(), "quilzo gateway providers") {
		t.Fatalf("%v", err)
	}
	if _, err := routeModel(root, gateway.Route{Name: "a", Provider: "azure-openai", Model: "m",
		KeySecret: "azure", ProviderParams: map[string]string{"resource": "evil.example#"}}); err == nil {
		t.Fatal("a resource that is not a name was put into a host")
	}
	// The provider's own output-limit field, unless the route says otherwise.
	if f := providerMaxTokens(root, gateway.Route{Provider: "openai"}); f != "max_completion_tokens" {
		t.Fatalf("%q", f)
	}
}
