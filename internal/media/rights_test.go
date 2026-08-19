package media

import (
	"strings"
	"testing"
	"time"
)

var rightsNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func at(t time.Time) int64 { return t.Unix() }

// The one condition that stops a publication, and the two that do not.
//
// A gate that refuses three different things is a gate people switch off. Only
// an expiry that has passed blocks; undeclared and lapsing are reported.
func TestOnlyAnExpiryThatHasPassedBlocks(t *testing.T) {
	for name, c := range map[string]struct {
		r       Rights
		expired bool
	}{
		"nothing said at all":   {Rights{}, false},
		"perpetual":             {Rights{Licence: "own-work"}, false},
		"still in term":         {Rights{Licence: "stock", Until: at(rightsNow.AddDate(0, 1, 0))}, false},
		"ends tomorrow":         {Rights{Licence: "stock", Until: at(rightsNow.AddDate(0, 0, 1))}, false},
		"ended yesterday":       {Rights{Licence: "stock", Until: at(rightsNow.AddDate(0, 0, -1))}, true},
		"ends this very second": {Rights{Licence: "stock", Until: at(rightsNow)}, true},
	} {
		if got := c.r.Expired(rightsNow); got != c.expired {
			t.Errorf("%s: Expired = %v, want %v", name, got, c.expired)
		}
	}
}

// Lapsing is the useful half, and it is not the same question as expired.
//
// An expired licence cannot be fixed retroactively. One expiring in three
// weeks can be renewed, and a feature that only reported the first would tell
// people about problems exclusively once they were unfixable.
func TestLapsingIsReportedWhileItCanStillBeFixed(t *testing.T) {
	const month = 30 * 24 * time.Hour

	soon := Rights{Licence: "stock", Until: at(rightsNow.AddDate(0, 0, 20))}
	if !soon.Lapsing(rightsNow, month) {
		t.Error("a licence ending in 20 days is not reported as lapsing " +
			"within a month, so nobody learns until it is too late to renew")
	}
	if soon.Expired(rightsNow) {
		t.Error("a licence ending in 20 days is reported as already expired")
	}

	far := Rights{Licence: "stock", Until: at(rightsNow.AddDate(1, 0, 0))}
	if far.Lapsing(rightsNow, month) {
		t.Error("a licence with a year to run is reported as lapsing, which " +
			"is the noise that gets a report ignored")
	}

	// Already expired is not "lapsing" — it is a different and worse state,
	// and reporting it as lapsing would file it under things still fixable.
	gone := Rights{Licence: "stock", Until: at(rightsNow.AddDate(0, 0, -1))}
	if gone.Lapsing(rightsNow, month) {
		t.Error("an expired licence is reported as lapsing")
	}

	// Perpetual never lapses.
	if (Rights{Licence: "own-work"}).Lapsing(rightsNow, month) {
		t.Error("a perpetual licence is reported as lapsing")
	}
}

// The licence field is an identifier, so that something can group and count it.
func TestALicenceIsAnIdentifierAndNotAnEssay(t *testing.T) {
	for _, ok := range []string{
		"CC-BY-4.0", "commissioned", "own-work", "stock:shutterstock",
		"Adobe Stock Standard", "MIT",
	} {
		if err := (Rights{Licence: ok}).Validate(rightsNow); err != nil {
			t.Errorf("%q was refused: %v", ok, err)
		}
	}
	essay := "Licensed for use in the autumn campaign only, across web and " +
		"print, in the UK and Ireland, until the end of the season."
	err := (Rights{Licence: essay}).Validate(rightsNow)
	if err == nil {
		t.Fatal("a paragraph was accepted as a licence identifier, so nothing " +
			"can group or report on this field")
	}
	if !strings.Contains(err.Error(), "note") {
		t.Errorf("the refusal does not tell the author where the prose goes: %v", err)
	}
	// And the same prose IS acceptable as a note.
	if err := (Rights{Licence: "stock", Note: essay}).Validate(rightsNow); err != nil {
		t.Errorf("the note refused prose, which is the one place it belongs: %v", err)
	}
}

// A date already in the past is recorded, not refused.
//
// The important direction: "this licence ended last month" is a true and useful
// thing to write down, and refusing it would leave lying as the only way to
// describe the situation.
func TestAnExpiryInThePastIsRecordable(t *testing.T) {
	r := Rights{Licence: "stock", Until: at(rightsNow.AddDate(0, -1, 0))}
	if err := r.Validate(rightsNow); err != nil {
		t.Errorf("could not record a licence that has already ended: %v", err)
	}
	if !r.Expired(rightsNow) {
		t.Error("and it does not read as expired, so the gate would miss it")
	}
}

// A typo that turns a date into the year 50000 is caught.
func TestAnImplausibleExpiryIsRefused(t *testing.T) {
	if err := (Rights{Licence: "stock",
		Until: at(rightsNow.AddDate(2000, 0, 0))}).Validate(rightsNow); err == nil {
		t.Error("an expiry two thousand years out was accepted; a millisecond " +
			"timestamp in a seconds field looks exactly like this")
	}
}

// An expiry with nothing else said describes an end without a beginning.
func TestAnExpiryNeedsALicenceOrAHolder(t *testing.T) {
	if err := (Rights{Until: at(rightsNow.AddDate(0, 1, 0))}).Validate(rightsNow); err == nil {
		t.Error("an expiry with no licence and no holder was accepted; it " +
			"says permission ends without saying what permission")
	}
}

// The five states a person reads in a list are distinguishable.
func TestEveryStateIsDistinguishable(t *testing.T) {
	const month = 30 * 24 * time.Hour
	seen := map[string]bool{}
	for _, r := range []Rights{
		{},
		{Licence: "own-work"},
		{Licence: "stock", Until: at(rightsNow.AddDate(1, 0, 0))},
		{Licence: "stock", Until: at(rightsNow.AddDate(0, 0, 10))},
		{Licence: "stock", Until: at(rightsNow.AddDate(0, 0, -10))},
	} {
		seen[r.State(rightsNow, month)] = true
	}
	for _, want := range []string{
		"undeclared", "perpetual", "licensed", "lapsing", "expired"} {
		if !seen[want] {
			t.Errorf("no rights produce the state %q, so a list cannot show it",
				want)
		}
	}
	if len(seen) != 5 {
		t.Errorf("five inputs produced %d distinct states: %v — states that "+
			"collapse are states nobody can act on differently", len(seen), seen)
	}
}

// A licence date is a calendar date, not an instant where the server stands.
//
// Parsed as UTC and rendered in local time, "until 30 September" came back as
// "1 October" on a machine at +0545 — a date nobody agreed to, printed by the
// tool that had been told the right one. Found by running it in Kathmandu.
func TestAnExpiryReadsBackAsTheDateItWasWritten(t *testing.T) {
	// The end of 30 September, the way the CLI stores it.
	day := time.Date(2027, 9, 30, 0, 0, 0, 0, time.UTC).
		Add(24*time.Hour - time.Second)
	r := Rights{Licence: "stock", Until: day.Unix()}

	got, ok := r.UntilTime()
	if !ok {
		t.Fatal("no expiry came back")
	}
	if y, m, d := got.Date(); y != 2027 || m != time.September || d != 30 {
		t.Errorf("stored the end of 30 September 2027 and read back %s",
			got.Format("2 January 2006 15:04 MST"))
	}
	// And it is still in term the day before, and out of term the day after,
	// wherever the reader is.
	if r.Expired(time.Date(2027, 9, 30, 12, 0, 0, 0, time.UTC)) {
		t.Error("expired during the last day of its own term")
	}
	if !r.Expired(time.Date(2027, 10, 1, 12, 0, 0, 0, time.UTC)) {
		t.Error("still in term the day after it ended")
	}
}
