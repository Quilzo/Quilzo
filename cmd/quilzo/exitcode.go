// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/board"
	"github.com/quilzo/quilzo/internal/booking"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/handoff"
	"github.com/quilzo/quilzo/internal/member"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/note"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/research"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/shield"
)

// errNotFound marks a refusal because the thing the command was asked about
// is not there: no agent, page, entry or request by that name. It exits 4,
// which the help documents as "not found", rather than 1, which is a
// command that ran and failed.
type errNotFound struct{ error }

func (e errNotFound) Unwrap() error { return e.error }

// exitCode is the code an error leaves the program with, and the one place
// an error becomes one of the codes `quilzo help` documents.
//
// Each exit in main picked its own, and most picked 1: a mistyped command,
// a subcommand nobody has and a flag a command does not take were 1, as
// were a reader refused publish by the access policy, an administrator
// approving their own request and `agent show` of an agent nobody
// declared. The help tells a script to branch on the code rather than on
// the wording, and on these the code said only that something went wrong.
//
// What a package says is not there, or refused, is named here once, so the
// commands that pass its error on need not each remember to.
func exitCode(err error) int {
	var blocked errBlocked
	var misused errMisused
	var missing errNotFound
	switch {
	case err == nil:
		return out.OK
	case errors.As(err, &blocked), errors.Is(err, dual.ErrRefused),
		errors.Is(err, dual.ErrLastAdministrator), errors.Is(err, odp.ErrSameAdministrator),
		errors.Is(err, shield.ErrSameProposer), errors.Is(err, collection.ErrReserved):
		return out.ExitBlocked
	case errors.As(err, &misused):
		return out.ExitUsage
	case errors.As(err, &missing), errors.Is(err, errNoStore),
		errors.Is(err, dual.ErrNoRequest), errors.Is(err, member.ErrNotFound),
		errors.Is(err, board.ErrNotFound), errors.Is(err, booking.ErrNotFound),
		errors.Is(err, note.ErrNotFound), errors.Is(err, handoff.ErrNotFound),
		errors.Is(err, memory.ErrNoEntry), errors.Is(err, schedule.ErrNothingPending),
		errors.Is(err, research.ErrNotFound), errors.Is(err, research.ErrNoProject),
		errors.Is(err, auth.ErrNoToken), errors.Is(err, shield.ErrNoProtection),
		errors.Is(err, shield.ErrNoChange), errors.Is(err, shield.ErrNotTrusted),
		errors.Is(err, oauthas.ErrNoConnection),
		errors.Is(err, odp.ErrNoProposal), errors.Is(err, newsletter.ErrNoIssue),
		errors.Is(err, audit.ErrNoEntry):
		return out.ExitNotFound
	}
	return out.ExitFailure
}
