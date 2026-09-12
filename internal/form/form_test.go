// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package form

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func contact() *Form {
	return &Form{
		Name: "contact", Label: "Contact us",
		Notice: "We keep this for 90 days and use it only to reply.",
		Fields: []Field{
			{Name: "name", Label: "Your name", Kind: Line, Required: true},
			{Name: "email", Label: "Email", Kind: Email, Required: true},
			{Name: "topic", Label: "About", Kind: Choice,
				Choices: []string{"sales", "support"}},
			{Name: "message", Label: "Message", Kind: Para},
			{Name: "consent", Label: "You agree", Kind: Agree, Required: true},
		},
	}
}

func filled(extra map[string]string) map[string]string {
	v := map[string]string{
		"name": "Dana", "email": "dana@example.org", "topic": "sales",
		"message": "Hello", "consent": "yes",
		StampField: fmt.Sprint(time.Now().Add(-10 * time.Second).Unix()),
	}
	for k, val := range extra {
		v[k] = val
	}
	return v
}

func TestAValidSubmissionIsAccepted(t *testing.T) {
	got, err := Accept(contact(), filled(nil), "203.0.113.7", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Values["name"] != "Dana" || got.Values["consent"] != "yes" {
		t.Errorf("values are wrong: %v", got.Values)
	}
	if got.ID == "" || got.At == 0 {
		t.Error("the submission has no identifier or no time")
	}
}

// The honeypot: a field people never see and scripts fill in.
func TestTheHoneypotRefusesWithoutSayingWhy(t *testing.T) {
	_, err := Accept(contact(), filled(map[string]string{
		Honeypot: "http://spam.example",
	}), "", time.Now())
	if err == nil {
		t.Fatal("accepted a submission with the hidden field filled in")
	}
	// The message deliberately says nothing useful. Telling a script which
	// check caught it is telling it what to change.
	if strings.Contains(err.Error(), "honeypot") ||
		strings.Contains(err.Error(), Honeypot) {
		t.Errorf("the refusal names the check that caught it: %v", err)
	}
}

// A person cannot read a form and answer it in under two seconds.
func TestAnImpossiblyFastSubmissionIsRefused(t *testing.T) {
	now := time.Now()
	_, err := Accept(contact(), filled(map[string]string{
		StampField: fmt.Sprint(now.Unix()),
	}), "", now)
	if err == nil {
		t.Error("accepted a form answered in under a second")
	}
}

// Removing the timing field must not bypass the timing check.
func TestAMissingOrForgedStampIsRefused(t *testing.T) {
	for _, stamp := range []string{"", "not a number", "-1", "99999999999999"} {
		v := filled(nil)
		v[StampField] = stamp
		if _, err := Accept(contact(), v, "", time.Now()); err == nil {
			t.Errorf("accepted a submission with a stamp of %q; deleting the "+
				"field would be how the timing check is bypassed", stamp)
		}
	}
}

// A form left open for a week is answering questions that may have changed.
func TestAStaleFormIsRefused(t *testing.T) {
	now := time.Now()
	v := filled(map[string]string{
		StampField: fmt.Sprint(now.Add(-48 * time.Hour).Unix()),
	})
	if _, err := Accept(contact(), v, "", now); err == nil {
		t.Error("accepted a form opened two days ago")
	}
}

// Values are checked against their declared kinds.
func TestValuesAreCheckedAgainstTheirKinds(t *testing.T) {
	for field, bad := range map[string]string{
		"email": "not-an-address",
		"topic": "something-not-offered",
	} {
		if _, err := Accept(contact(), filled(map[string]string{field: bad}),
			"", time.Now()); err == nil {
			t.Errorf("accepted %q for %s", bad, field)
		}
	}
}

// A field nobody declared is dropped, not stored and not refused.
func TestAnUndeclaredFieldIsDropped(t *testing.T) {
	got, err := Accept(contact(), filled(map[string]string{
		"admin": "true", "role": "administrator", "__proto__": "x",
	}), "", time.Now())
	if err != nil {
		t.Fatalf("an extra field broke a valid submission: %v", err)
	}
	for _, sneaky := range []string{"admin", "role", "__proto__"} {
		if _, stored := got.Values[sneaky]; stored {
			t.Errorf("%q was stored; only declared fields may be", sneaky)
		}
	}
}

// Control characters are refused everywhere.
func TestControlCharactersAreRefused(t *testing.T) {
	for _, bad := range []string{"Dana\x00", "Dana\x1b[31m", "Dana\rSet-Cookie: x"} {
		if _, err := Accept(contact(), filled(map[string]string{"name": bad}),
			"", time.Now()); err == nil {
			t.Errorf("accepted %q, which breaks out of whatever renders it "+
				"later — a CSV, a terminal, a log line", bad)
		}
	}
}

// A one-line field cannot contain newlines.
func TestALineFieldCannotBeMultiline(t *testing.T) {
	if _, err := Accept(contact(),
		filled(map[string]string{"name": "Dana\nBcc: someone@else"}),
		"", time.Now()); err == nil {
		t.Error("accepted a newline in a single-line field")
	}
	// And a paragraph field may.
	if _, err := Accept(contact(),
		filled(map[string]string{"message": "line one\nline two"}),
		"", time.Now()); err != nil {
		t.Errorf("refused a newline in a paragraph field: %v", err)
	}
}

// A form without a privacy notice cannot be published.
func TestAFormWithoutAPrivacyNoticeIsRefused(t *testing.T) {
	f := contact()
	f.Notice = ""
	err := f.Validate()
	if err == nil {
		t.Fatal("accepted a form that collects personal data and says nothing " +
			"about what happens to it")
	}
	if !strings.Contains(err.Error(), "notice") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// A field cannot be named after the honeypot.
func TestAFieldCannotCollideWithTheHoneypot(t *testing.T) {
	f := contact()
	f.Fields = append(f.Fields, Field{Name: Honeypot, Label: "Website",
		Kind: Line})
	if err := f.Validate(); err == nil {
		t.Error("accepted a real field named after the hidden one; anybody " +
			"filling it in properly would be treated as a script")
	}
}

// Retention has a ceiling.
func TestRetentionHasACeiling(t *testing.T) {
	f := contact()
	f.RetentionDays = MaxRetentionDays + 1
	if err := f.Validate(); err == nil {
		t.Error("accepted a retention period past the ceiling")
	}
	f.RetentionDays = 0
	if got := f.Retention(); got != DefaultRetentionDays*24*time.Hour {
		t.Errorf("the default retention is %v", got)
	}
}

// The operation the content store cannot offer.
func TestSubmissionsCanBeDeletedAndExpire(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := contact()
	f.RetentionDays = 30
	set := &Set{Forms: []Form{*f}}
	now := time.Now()

	// Built directly rather than through Accept: a stamp sixty days old is
	// correctly refused as a stale form, which is a different test.
	old := Submission{ID: strings.Repeat("a", 32), Form: "contact",
		At:     now.Add(-60 * 24 * time.Hour).Unix(),
		Values: map[string]string{"name": "Older"}}
	recent, err := Accept(f, filled(nil), "", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Submission{old, recent} {
		if err := st.Put(s); err != nil {
			t.Fatal(err)
		}
	}

	n, err := st.Expire(set, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expired %d submissions, expected 1", n)
	}
	left, _ := st.List("contact")
	if len(left) != 1 || left[0].ID != recent.ID {
		t.Errorf("the wrong submission survived: %v", left)
	}

	if err := st.Delete("contact", recent.ID); err != nil {
		t.Fatal(err)
	}
	if left, _ := st.List("contact"); len(left) != 0 {
		t.Error("a deleted submission is still there")
	}
}

// An erasure request starts from an email address, not an identifier.
func TestSearchFindsWhatAnErasureRequestNames(t *testing.T) {
	st, _ := Open(t.TempDir())
	f := contact()
	set := &Set{Forms: []Form{*f}}
	mine, _ := Accept(f, filled(nil), "", time.Now())
	theirs, _ := Accept(f, filled(map[string]string{
		"email": "someone@example.net"}), "", time.Now())
	_ = st.Put(mine)
	_ = st.Put(theirs)

	got, err := st.Search(set, "dana@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != mine.ID {
		t.Errorf("found %d submissions, expected the one from dana", len(got))
	}
}

// An identifier from a request never becomes a path.
func TestATraversalInAnIdentifierIsRefused(t *testing.T) {
	st, _ := Open(t.TempDir())
	for _, id := range []string{
		"../../../etc/passwd", "..", "", strings.Repeat("f", 64),
	} {
		if err := st.Delete("contact", id); err == nil {
			t.Errorf("accepted %q as a submission identifier", id)
		}
	}
	for _, form := range []string{"../secrets", "a/b", ""} {
		if _, err := st.List(form); err == nil {
			t.Errorf("accepted %q as a form name", form)
		}
	}
}

// A closed form takes nothing more, and keeps what it has.
func TestAClosedFormAcceptsNothing(t *testing.T) {
	f := contact()
	f.Closed = true
	if _, err := Accept(f, filled(nil), "", time.Now()); err == nil {
		t.Error("a closed form accepted a submission")
	}
}

// A sweep carries on past a submission somebody else already removed.
//
// Two servers sweep now, and a person can delete one from the forms screen
// while a sweep is walking the directory. Expire used to return the first
// os.Remove error, so the loser of that race abandoned the rest of its sweep —
// over a file that had reached the state it was headed for anyway. With enough
// forms, retention would then hold for the first one and silently not for the
// others.
func TestExpireCarriesOnPastASubmissionAlreadyRemoved(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(dir) // the same directory, as a second process sees it
	if err != nil {
		t.Fatal(err)
	}

	f := contact()
	f.RetentionDays = 30
	set := &Set{Forms: []Form{*f}}
	now := time.Now()
	stale := now.Add(-60 * 24 * time.Hour).Unix()

	ids := []string{strings.Repeat("a", 32), strings.Repeat("b", 32),
		strings.Repeat("c", 32)}
	for _, id := range ids {
		if err := st.Put(Submission{ID: id, Form: "contact", At: stale,
			Values: map[string]string{"name": "Older"}}); err != nil {
			t.Fatal(err)
		}
	}

	// The other sweep gets to one of them first.
	if err := other.Delete("contact", ids[0]); err != nil {
		t.Fatal(err)
	}

	n, err := st.Expire(set, now)
	if err != nil {
		t.Fatalf("Expire stopped on a submission that was already gone: %v", err)
	}
	if n != 2 {
		t.Errorf("removed %d; the two that were still there should have gone", n)
	}
	if left, _ := st.List("contact"); len(left) != 0 {
		t.Errorf("%d submissions outlived their period because the sweep "+
			"stopped early: %v", len(left), left)
	}
}

// Deleting something that is not there is still an error for a person.
//
// Expire treats it as work already done; a person who names a submission that
// does not exist has made a mistake and should be told so.
func TestDeletingSomethingThatIsNotThereStillSaysSo(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = st.Delete("contact", strings.Repeat("a", 32))
	if err == nil {
		t.Fatal("deleting a submission that does not exist succeeded")
	}
	if !strings.Contains(err.Error(), "no such submission") {
		t.Errorf("the error does not say what was wrong: %v", err)
	}
}
