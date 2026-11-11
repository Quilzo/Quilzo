// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package schedule

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// Scheduling a publish, the same way from every surface.
//
// `quilzo schedule add` and the Publishing screen's form were two copies of
// this, down to a byte-identical parseWhen with its comment. They had
// already drifted where it matters most, in what they left in the audit
// log: the command line cut the note at its 200th byte, through an é, and
// the browser kept the whole note; the browser said who scheduled it in the
// record's detail and the command line did not. So the reading of a time,
// the change to the schedule and the record of it are here, and each
// surface keeps only its own words for a refusal.

// MaxNote bounds the note an audit record of scheduling keeps, in bytes.
// The entry keeps the whole note; the log is for what happened, and a
// paragraph pasted into the note box is not that.
const MaxNote = 200

// ParseWhen reads a time as a timestamp or a duration.
//
// Both, because "in 48h" is what somebody types for an embargo and an
// absolute time is what they type for a launch, and forcing one into the
// other is how a scheduled publish goes out at the wrong hour.
func ParseWhen(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("%q is not in the future", s)
		}
		return now.Add(d), nil
	}
	return time.Time{}, fmt.Errorf(
		"%q is neither a time (2026-09-01T09:00:00Z) nor a duration (48h)", s)
}

// Refused is the schedule declining an entry: a time in the past or more
// than a year away, a commit already scheduled, or not a commit. It is the
// person's to put right, where any other error from Queue is the store's.
type Refused struct{ Err error }

func (r *Refused) Error() string { return r.Err.Error() }
func (r *Refused) Unwrap() error { return r.Err }

// Queue adds commit, to publish at at, to the schedule update changes
// under the schedule's lock.
func Queue(update func(func(*Schedule) error) error, commit string, at time.Time, by Who,
	note string, now time.Time) error {

	var refused error
	if err := update(func(s *Schedule) error {
		refused = s.Add(commit, at, by, note, now)
		return refused
	}); err != nil {
		if refused != nil {
			return &Refused{refused}
		}
		return err
	}
	return nil
}

// ErrNothingPending is Withdraw finding no pending entry the commit names.
var ErrNothingPending = errors.New("nothing pending matches")

// Withdraw cancels the pending entry commit names, under the lock.
func Withdraw(update func(func(*Schedule) error) error, commit string) error {
	return update(func(s *Schedule) error {
		if !s.Cancel(commit) {
			return ErrNothingPending
		}
		return nil
	})
}

// Detail is what the audit record of scheduling commit says: what, when,
// why and who, the note on one line and clipped whole to MaxNote bytes.
func Detail(commit string, at time.Time, note, by string) map[string]string {
	return map[string]string{
		"scheduled": commit, "at": at.UTC().Format(time.RFC3339),
		"note": plaintext.Clip(strings.Join(strings.Fields(note), " "), MaxNote, "…"),
		"by":   by,
	}
}

// CancelDetail is what the audit record of cancelling one says.
func CancelDetail(commit, by string) map[string]string {
	return map[string]string{"cancelled": commit, "by": by}
}
