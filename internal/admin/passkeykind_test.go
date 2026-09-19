// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

// webauthn.Credential.Identified is written at enrolment and was read by
// nothing.
//
// Its own comment says why it is recorded: "the useful question later is
// 'which of these are hardware keys' and it cannot be answered
// retrospectively: the authenticator only says at registration". So the field
// existed precisely to answer a question no surface asked.
//
// It matters most the moment somebody turns passkey.require_hardware on: from
// then a new synced passkey is refused, and the ones already enrolled keep
// working, invisibly, with nothing to say which they are.
func TestThePasskeyScreenSaysWhichAreHardware(t *testing.T) {
	src, err := assets.ReadFile("assets/passkeys.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, ".Identified") {
		t.Error("the passkeys screen does not say which credentials are " +
			"hardware keys, and every record carries the answer")
	}
	// And the warning for the case the field exists for.
	if !strings.Contains(body, ".RequiresHardware") ||
		!strings.Contains(body, ".Unidentified") {
		t.Error("the screen does not warn about credentials that predate " +
			"passkey.require_hardware")
	}
	// It must not claim they have stopped working, because they have not.
	if !strings.Contains(body, "They still work") {
		t.Error("the warning does not say the existing keys still work, " +
			"which is the first thing somebody reading it needs to know")
	}
}
