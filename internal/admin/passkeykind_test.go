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

// schema.Validated is written by every write path and was read by nothing.
//
// It answers a different question from the live gate: not "does this page
// satisfy its type now" but "is there a record that this exact content passed
// this exact type". That record is what an assurance claim rests on, and it
// could not be asked anywhere.
//
// So a page could satisfy its type and have no record of ever having been
// checked — written before records existed, or through the content API, which
// validated and wrote nothing down until it was fixed.
func TestTheTypesScreenListsWhatWasNeverAttested(t *testing.T) {
	src, err := assets.ReadFile("assets/types.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if !strings.Contains(body, ".Unattested") {
		t.Error("the types screen does not list pages with no recorded " +
			"validation, and every write path records one")
	}
	// It must not read as a failure. These pages are valid; what is missing
	// is the record.
	if !strings.Contains(body, "Valid, and never recorded as valid") {
		t.Error("the heading does not distinguish an unattested page from a " +
			"failing one, which are different problems with different fixes")
	}
}
