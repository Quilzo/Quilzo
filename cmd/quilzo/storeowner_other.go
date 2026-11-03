// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

// storeOwnedByMe is false where ownership is not a user id this program can
// read with the standard library: a server there starts with a token, as it
// did before (need.server, privilege.go).
func storeOwnedByMe(string) bool { return false }

func storeOwnerHint(string) string {
	return "  on this system a server starts with a token: quilzo token issue NAME --principal YOU, then QUILZO_TOKEN"
}
