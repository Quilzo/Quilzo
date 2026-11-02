// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every built-in profile is whole: an address that parses, https for
// anything hosted, a way to send its key, and where its address came from.
func TestEveryBuiltInProviderIsWhole(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	all := c.All()
	if len(all) < 40 {
		t.Fatalf("%d providers", len(all))
	}
	groups := map[string]bool{}
	for _, g := range Groups {
		groups[g.ID] = true
	}
	for _, p := range all {
		if !groups[p.Group] {
			t.Errorf("%s is in group %q", p.ID, p.Group)
		}
		if p.Data.Trains == "" || p.Data.Retention == "" || p.Data.Residency == "" {
			t.Errorf("%s does not say what it does with what it is sent", p.ID)
		}
		if !p.Local && p.Key == "" {
			t.Errorf("%s suggests no credential name", p.ID)
		}
		if p.Docs != "" && !strings.HasPrefix(p.Docs, "https://") {
			t.Errorf("%s's documentation is not an https address", p.ID)
		}
	}
	// In the order a person reads them: this machine first.
	if all[0].Group != "local" {
		t.Errorf("the first provider listed is %s", all[0].ID)
	}
}

// A parameter is checked before it goes into a host name, so it cannot
// make the address another host.
func TestAParameterCannotBecomeAnotherHost(t *testing.T) {
	c, _ := Load("")
	azure, ok := c.Get("azure-openai")
	if !ok {
		t.Fatal("no azure-openai")
	}
	base, host, err := azure.Endpoint(map[string]string{"resource": "contoso-ai"})
	if err != nil || base != "https://contoso-ai.openai.azure.com/openai/v1" || host != "contoso-ai.openai.azure.com" {
		t.Fatalf("%s %s %v", base, host, err)
	}
	for _, bad := range []string{"evil.com/x?", "a.b", "x@evil.com", "", "-x", strings.Repeat("a", 64), "UPPER"} {
		if _, _, err := azure.Endpoint(map[string]string{"resource": bad}); err == nil {
			t.Errorf("%q was taken as a resource", bad)
		}
	}
	cf, _ := c.Get("cloudflare")
	if _, _, err := cf.Endpoint(map[string]string{"account": "not-an-account"}); err == nil {
		t.Error("a Cloudflare account that is not 32 hexadecimal characters was taken")
	}
	if _, _, err := cf.Endpoint(map[string]string{"account": strings.Repeat("a1", 16)}); err != nil {
		t.Error(err)
	}
}

// A profile that would send a key over plain http, to nowhere, or in a
// header it may not set is refused, and an operator's file that has one
// fails to load, naming it.
func TestABadProfileIsRefused(t *testing.T) {
	good := Provider{ID: "acme", Name: "Acme", Group: "host", Where: "x", Wire: "openai-chat",
		Base: "https://api.acme.example/v1", Auth: "bearer", Key: "acme", Verified: "unverified",
		Data: Data{Trains: "no", Retention: "none", Residency: "EU"}}
	if err := good.Check(); err != nil {
		t.Fatal(err)
	}
	for why, change := range map[string]func(*Provider){
		"plain http hosted": func(p *Provider) { p.Base = "http://api.acme.example/v1" },
		"no key hosted":     func(p *Provider) { p.Auth = "none" },
		"auth header":       func(p *Provider) { p.Headers = map[string]string{"Authorization": "x"} },
		"host header":       func(p *Provider) { p.Headers = map[string]string{"Host": "evil.example"} },
		"undeclared param":  func(p *Provider) { p.Base = "https://{tenant}.acme.example/v1" },
		"query in address":  func(p *Provider) { p.Base = "https://api.acme.example/v1?key=x" },
		"user in address":   func(p *Provider) { p.Base = "https://u:p@api.acme.example/v1" },
		"unknown wire":      func(p *Provider) { p.Wire = "carrier-pigeon" },
		"bad auth":          func(p *Provider) { p.Auth = "header:bad header" },
		"no source":         func(p *Provider) { p.Verified = "" },
	} {
		p := good
		change(&p)
		if p.Check() == nil {
			t.Errorf("%s was accepted", why)
		}
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "providers.json")
	os.WriteFile(file, []byte(`{"providers":[{"id":"openai","name":"OpenAI via our proxy","group":"router","where":"here",
		"wire":"openai-chat","base":"https://llm.internal.example/v1","auth":"bearer","key":"proxy","verified":"unverified",
		"data":{"trains":"no","retention":"none","residency":"here"}}]}`), 0o600)
	c, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := c.Get("openai"); p.Base != "https://llm.internal.example/v1" {
		t.Fatalf("the operator's profile did not replace the built-in one: %+v", p)
	}
	os.WriteFile(file, []byte(`{"providers":[{"id":"leak","name":"Leak","group":"host","where":"x","wire":"openai-chat",
		"base":"http://leak.example/v1","auth":"bearer","key":"k","verified":"unverified","data":{"trains":"no","retention":"x","residency":"x"}}]}`), 0o600)
	if _, err := Load(file); err == nil || !strings.Contains(err.Error(), "leak") {
		t.Fatalf("a bad profile loaded: %v", err)
	}
}
