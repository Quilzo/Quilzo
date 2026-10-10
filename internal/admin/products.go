// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"regexp"
	"strings"
)

// productNames is how a source's key reads to a person: the product's own
// name, as its maker writes it. The keys are what the connectors and the
// rules store; a screen shows the name.
var productNames = map[string]string{
	"entra":           "Entra ID",
	"okta":            "Okta",
	"knowbe4":         "KnowBe4",
	"vanta":           "Vanta",
	"endpointcentral": "Endpoint Central",
	"mdmplus":         "MDM Plus",
	"github":          "GitHub",
	"aws":             "AWS",
	"quilzo":          "Quilzo",
	"evm":             "EVM",
}

// productWord matches a source key standing as a word of its own in a
// sentence: "according to entra and knowbe4". A key inside an identifier
// (knowbe4:k-03, posture/token.admin-role) is left alone, since that is a
// value somebody may copy, not prose.
var productWord = regexp.MustCompile(`(^|[\s(,])(entra|okta|knowbe4|vanta|endpointcentral|mdmplus|github|aws|quilzo)($|[\s),.;])`)

// productName is one source key as its product's name, or the key itself
// when it is not one this knows.
func productName(key string) string {
	if n, ok := productNames[strings.ToLower(key)]; ok {
		return n
	}
	return key
}

// withProductNames rewrites the source keys a generated sentence carries
// into product names.
func withProductNames(s string) string {
	// Twice, because adjacent matches share the space between them.
	for i := 0; i < 2; i++ {
		s = productWord.ReplaceAllStringFunc(s, func(m string) string {
			sub := productWord.FindStringSubmatch(m)
			return sub[1] + productNames[sub[2]] + sub[3]
		})
	}
	return s
}
