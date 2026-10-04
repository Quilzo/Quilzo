// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Command capture prints one Quilzo sign-in request per Keycloak client, for
// capture.js to follow through a real sign-in. See README.md. Under
// testdata, so no build or test ever runs it.
//
//	go run ./internal/saml/testdata/keycloak/capture descriptor.xml > requests.txt
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/quilzo/quilzo/internal/saml"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	m, err := saml.ParseMetadata(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "metadata:", err)
		os.Exit(1)
	}
	for _, v := range []string{"doc", "assert", "both", "rsa512"} {
		sp := "http://127.0.0.1:18780/saml/kc-" + v
		p := &saml.Provider{EntityID: m.EntityID, SSOURL: m.SSOURL, ServiceEntityID: sp, ACS: sp + "/acs"}
		id, err := saml.NewRequestID()
		if err != nil {
			panic(err)
		}
		u, err := p.AuthnRequestURL(id, "relay-"+v, time.Now())
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s %s %s\n", v, id, u)
	}
}
