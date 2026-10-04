// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/xmldsig"
)

func TestTheRequestSaysWhatTheResponseIsCheckedAgainst(t *testing.T) {
	p := testProvider(t)
	p.SSOURL = "https://idp.northwind.example/sso?tenant=north&x=1"
	p.NameIDFormat = FormatEmail
	p.ForceAuthn = true
	p.AuthnContexts = []string{"https://refeds.org/profile/mfa"}
	id, err := NewRequestID()
	if err != nil || len(id) != 33 || id[0] != '_' {
		t.Fatalf("id %q %v", id, err)
	}
	raw, err := p.AuthnRequestURL(id, "rs-key", tNow)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if u.Host != "idp.northwind.example" || q.Get("tenant") != "north" || q.Get("x") != "1" {
		t.Errorf("the provider's own query was lost: %s", raw)
	}
	if q.Get("RelayState") != "rs-key" {
		t.Errorf("relay state %q", q.Get("RelayState"))
	}
	z, err := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	x, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		t.Fatal(err)
	}
	d, err := xmldsig.Read(x)
	if err != nil {
		t.Fatalf("the request does not read: %v\n%s", err, x)
	}
	r := d.Root
	for k, want := range map[string]string{
		"ID": id, "Version": "2.0", "Destination": p.SSOURL, "AssertionConsumerServiceURL": tACS,
		"ProtocolBinding": BindingPOST, "ForceAuthn": "true", "IssueInstant": "2026-10-04T09:00:00Z",
	} {
		if v, _ := r.Attr(k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}
	s := string(x)
	for _, want := range []string{"<saml:Issuer>" + tSP + "</saml:Issuer>", `Format="` + FormatEmail + `"`,
		`Comparison="minimum"`, "https://refeds.org/profile/mfa"} {
		if !strings.Contains(s, want) {
			t.Errorf("the request lacks %s", want)
		}
	}
	if !strings.Contains(s, "&amp;x=1") {
		t.Error("the destination was not escaped")
	}
}

func TestTheRequestGoesOnlyToHTTPS(t *testing.T) {
	p := testProvider(t)
	for addr, ok := range map[string]bool{
		"http://idp.example/sso": false, "javascript:alert(1)": false, "https://idp.example/sso": true,
		"http://localhost:8080/realms/x/protocol/saml": true, "http://127.0.0.1:8080/sso": true,
	} {
		p.SSOURL = addr
		_, err := p.AuthnRequestURL("_x", "r", tNow)
		if (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func idpMetadata(t testing.TB, certFile, sso, extra string) []byte {
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "keys", certFile+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="` + NSMetadata + `" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + tIdP + `">
  <md:IDPSSODescriptor protocolSupportEnumeration="` + NSProtocol + `"` + extra + `>
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
` + base64.StdEncoding.EncodeToString(blk.Bytes) + `
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(blk.Bytes) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="` + BindingPOST + `" Location="https://idp.example/post"/>
    <md:SingleSignOnService Binding="` + BindingRedirect + `" Location="` + sso + `"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`)
}

func TestMetadataIsReadStrictly(t *testing.T) {
	m, err := ParseMetadata(idpMetadata(t, "rsa", "https://idp.example/sso", ""))
	if err != nil {
		t.Fatal(err)
	}
	if m.EntityID != tIdP || m.SSOURL != "https://idp.example/sso" || len(m.Certs) != 1 || m.WantsSignedRequests {
		t.Errorf("%+v", m)
	}
	if _, err := SigningKey(m.Certs[0]); err != nil {
		t.Error(err)
	}
	if fp := Fingerprint(m.Certs[0]); len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Errorf("fingerprint %q", fp)
	}

	if _, err := ParseMetadata(idpMetadata(t, "rsa", "http://idp.example/sso", "")); err == nil {
		t.Error("an http sign-in address was accepted")
	}
	weak, err := ParseMetadata(idpMetadata(t, "rsa1024", "https://idp.example/sso", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SigningKey(weak.Certs[0]); err == nil {
		t.Error("a 1024-bit key was accepted for signing")
	}
	signed, _ := ParseMetadata(idpMetadata(t, "rsa", "https://idp.example/sso", ` WantAuthnRequestsSigned="true"`))
	if signed == nil || !signed.WantsSignedRequests {
		t.Error("a provider asking for signed requests was not noticed")
	}
	for _, bad := range []string{`<!DOCTYPE x><x/>`, `<md:EntityDescriptor xmlns:md="` + NSMetadata + `"/>`, `<html/>`} {
		if _, err := ParseMetadata([]byte(bad)); err == nil {
			t.Errorf("%s was accepted as metadata", bad)
		}
	}
}

func TestServiceMetadataReadsBack(t *testing.T) {
	b := ServiceMetadata(tSP, tACS, tNow.Add(365*24*time.Hour))
	d, err := xmldsig.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := d.Root.Attr("entityID"); v != tSP {
		t.Errorf("entityID %q", v)
	}
	if !bytes.Contains(b, []byte(`Location="`+tACS+`"`)) || !bytes.Contains(b, []byte(`WantAssertionsSigned="true"`)) {
		t.Errorf("%s", b)
	}
}

func TestEveryPresetIsInTheOrder(t *testing.T) {
	if len(PresetOrder) != len(Presets) {
		t.Fatalf("%d in the order, %d presets", len(PresetOrder), len(Presets))
	}
	for _, k := range PresetOrder {
		if _, ok := Presets[k]; !ok {
			t.Errorf("%s is ordered and not a preset", k)
		}
	}
}
