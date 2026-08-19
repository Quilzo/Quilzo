package media

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Who may use this picture, and until when.
//
// # The failure this exists for
//
// Every content tool has a licence field on an image. Almost nobody fills it
// in, because it is a text box that does nothing — and the one time it would
// have mattered, it was empty.
//
// The failure it should have caught is specific and it is not "we forgot who
// took the photograph". It is that image rights *end*. A stock licence runs
// for a term. A model release covers a campaign. A photographer's contract
// finishes. A brand asset is licensed for one territory and one year. On the
// day any of those lapse, nothing happens: the page stays published, the image
// stays served, and the site is now infringing with a full audit trail proving
// it was deliberate. Nobody is notified because nothing is watching.
//
// # So a licence is a publish window, and the same one
//
// A page carrying `expires` stops being served when the moment passes, checked
// at the point it is asked for rather than by a job that can be late. Rights
// are exactly that shape pointed at a file: an asset has a moment after which
// it may not be published, and the check belongs with the other publish gates.
//
// Reusing the concept rather than the code, because the questions differ at the
// edges — an expired page is quietly withdrawn, and an expired photograph has
// to *stop the publication*, because withdrawing an image silently would leave
// a page with a hole in it and nobody told.
//
// # And the warning half, which is the useful half
//
// An expired licence cannot be fixed retroactively. A licence expiring in three
// weeks can be renewed. So lapsing rights are reported long before they bite,
// and that report — not the refusal — is what makes this worth having.

// reLicence bounds what a licence identifier may look like.
//
// An identifier rather than prose: SPDX ids, a stock library's name, or an
// internal term. Prose belongs in Note, and a licence field full of paragraphs
// is one nothing can group, count or report on.
var reLicence = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:+-]{0,63}$`)

// Rights is the permission this file is published under.
type Rights struct {
	// Licence is what permits publication: an SPDX identifier, a supplier's
	// name, "commissioned", "own-work". Empty means nobody has said.
	Licence string `json:"licence,omitempty"`

	// Holder is who owns the underlying work, which is frequently not whoever
	// uploaded the file.
	Holder string `json:"holder,omitempty"`

	// Until is when permission ends, as a Unix time. Zero means it does not,
	// which is the ordinary case for work a business owns outright and is a
	// claim somebody should still have to make deliberately.
	Until int64 `json:"until,omitempty"`

	// Note is the restriction that does not fit a field: territory, medium,
	// a campaign it is tied to. Carried for the person, never parsed.
	Note string `json:"note,omitempty"`
}

// Declared reports whether anybody has said anything about rights.
func (r Rights) Declared() bool {
	return strings.TrimSpace(r.Licence) != "" || strings.TrimSpace(r.Holder) != ""
}

// Expired reports whether permission has ended.
//
// Not "expires soon" and not "undeclared" — only the one condition that must
// stop a publication. The other two are reported and do not block, because a
// gate that refuses three different things is a gate people switch off.
func (r Rights) Expired(now time.Time) bool {
	return r.Until != 0 && !now.Before(time.Unix(r.Until, 0).UTC())
}

// Lapsing reports whether permission ends within the window.
//
// The useful half. An expired licence cannot be fixed after the fact; one
// expiring in three weeks can be renewed, and this is what makes that
// difference visible while it still is one.
func (r Rights) Lapsing(now time.Time, within time.Duration) bool {
	if r.Until == 0 || r.Expired(now) {
		return false
	}
	return time.Unix(r.Until, 0).UTC().Sub(now) <= within
}

// Validate refuses rights that cannot mean what they appear to.
func (r Rights) Validate(now time.Time) error {
	lic := strings.TrimSpace(r.Licence)
	if lic != "" && !reLicence.MatchString(lic) {
		return fmt.Errorf(
			"%q is not a licence identifier. Use a short name — an SPDX id, "+
				"a supplier, \"commissioned\" — and put the terms in the note; "+
				"a licence field full of prose is one nothing can report on",
			truncate(lic, 40))
	}
	if r.Until != 0 {
		until := time.Unix(r.Until, 0).UTC()
		if until.Before(now) {
			// Accepted, not refused. Recording that a licence ended last month
			// is a true and useful thing to write down, and refusing it would
			// mean the only way to describe the situation is to lie about it.
			return nil
		}
		if until.Sub(now) > MaxRightsAhead {
			return fmt.Errorf(
				"permission ending in %s is not a term anybody agreed; check "+
					"the date", until.Format("2006"))
		}
	}
	if r.Until != 0 && !r.Declared() {
		return fmt.Errorf(
			"an expiry with no licence and no holder says permission ends " +
				"without saying what permission. Name at least one")
	}
	return nil
}

// MaxRightsAhead bounds an expiry date.
//
// A hundred years, which catches the two mistakes that actually happen — a
// millisecond timestamp in a seconds field, and a year typed as 20226 — and
// limits nobody's contract.
const MaxRightsAhead = 100 * 365 * 24 * time.Hour

// State describes rights for a person reading a list.
func (r Rights) State(now time.Time, within time.Duration) string {
	switch {
	case !r.Declared() && r.Until == 0:
		return "undeclared"
	case r.Expired(now):
		return "expired"
	case r.Lapsing(now, within):
		return "lapsing"
	case r.Until != 0:
		return "licensed"
	default:
		return "perpetual"
	}
}

// UntilTime reads the expiry, and whether there is one.
//
// In UTC, always. A licence expiry is a calendar date somebody typed off a
// contract, not an instant tied to where the server happens to be: parsed as
// UTC and rendered in local time, "until 30 September" came back as "1 October"
// on a machine at +0545 — which is a date nobody agreed to, printed by the
// tool that was told the right one.
func (r Rights) UntilTime() (time.Time, bool) {
	if r.Until == 0 {
		return time.Time{}, false
	}
	return time.Unix(r.Until, 0).UTC(), true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
