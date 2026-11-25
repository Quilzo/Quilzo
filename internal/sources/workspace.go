// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"time"

	"github.com/quilzo/quilzo/internal/evidence"
)

// Google Workspace, through the Admin SDK's directory: every account, by
// its primary address, whether it is suspended or archived, whether it is
// an administrator, and whether it is enrolled in and made to use 2-Step
// Verification.

func init() {
	define(&Recipe{
		Name: "google-workspace",
		Privilege: []string{
			"A service account of its own, with domain-wide delegation for one scope only: " +
				"https://www.googleapis.com/auth/admin.directory.user.readonly.",
			"It acts as one administrator whose role can read users and nothing else; a token whose granted " +
				"scopes include any other is refused before it is used.",
		},
		Fresh: 24 * time.Hour,
		pull:  pullWorkspace,
	})
}

func pullWorkspace(r *Run, to evidence.PullTo) error {
	users, err := r.Endpoint("users")
	if err != nil {
		return err
	}
	for _, u := range users.Records {
		id, err := to.Subject(u.Fields["email"], "account", u.Place)
		if err != nil {
			return err
		}
		f := &facts{to: to, about: id, place: u.Place}
		f.yes("account.suspended", u.Fields["suspended"])
		f.yes("account.archived", u.Fields["archived"])
		f.yes("account.admin", u.Fields["admin"])
		f.yes("account.delegated-admin", u.Fields["delegated_admin"])
		f.yes("2sv.enrolled", u.Fields["enrolled_2sv"])
		f.yes("2sv.enforced", u.Fields["enforced_2sv"])
		if f.err != nil {
			return f.err
		}
	}
	return nil
}
