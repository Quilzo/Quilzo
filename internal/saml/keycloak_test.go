// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package saml

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Responses recorded from a running Keycloak 26.8: Quilzo's own request
// went out, a person signed in in Chromium, and the POST back was kept
// (testdata/keycloak). One client per way Keycloak can sign: the response,
// the assertion, both, and RSA-SHA512. The realm's metadata is the file
// Keycloak serves. This is the evidence that a real identity provider, not
// only the JDK's signer, interoperates.
func TestRecordedKeycloakResponsesSignIn(t *testing.T) {
	meta, err := os.ReadFile(filepath.Join("testdata", "keycloak", "descriptor.xml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMetadata(meta)
	if err != nil {
		t.Fatalf("Keycloak's own metadata: %v", err)
	}
	key, err := SigningKey(m.Certs[0])
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "keycloak", "*.json"))
	if len(files) < 4 {
		t.Fatalf("%d recordings", len(files))
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var rec struct {
			Name, Response string
			RequestID      string `json:"request_id"`
			Captured       time.Time
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		sp := "http://127.0.0.1:18780/saml/kc-" + rec.Name
		p := &Provider{EntityID: m.EntityID, SSOURL: m.SSOURL, Keys: []crypto.PublicKey{key},
			ServiceEntityID: sp, ACS: sp + "/acs"}
		a, err := p.ParseResponse(rec.Response, rec.RequestID, rec.Captured)
		if err != nil {
			t.Errorf("%s: %v", rec.Name, err)
			continue
		}
		if a.NameID != "dana.reyes@northwind.example" {
			t.Errorf("%s: signed in %q", rec.Name, a.NameID)
		}
		wantR := rec.Name == "doc" || rec.Name == "both"
		wantA := rec.Name != "doc"
		if a.ResponseSigned != wantR || a.AssertionSigned != wantA {
			t.Errorf("%s: response signed %v, assertion signed %v", rec.Name, a.ResponseSigned, a.AssertionSigned)
		}
		// The same response, an hour later, for another request, or for
		// another service, is refused.
		if _, err := p.ParseResponse(rec.Response, rec.RequestID, rec.Captured.Add(time.Hour)); err == nil {
			t.Errorf("%s: accepted an hour late", rec.Name)
		}
		if _, err := p.ParseResponse(rec.Response, "_another", rec.Captured); err == nil {
			t.Errorf("%s: accepted for another request", rec.Name)
		}
		q := *p
		q.ServiceEntityID, q.ACS = "http://127.0.0.1:18780/saml/kc-other", "http://127.0.0.1:18780/saml/kc-other/acs"
		if _, err := q.ParseResponse(rec.Response, rec.RequestID, rec.Captured); err == nil {
			t.Errorf("%s: accepted for another service", rec.Name)
		}
	}
}
