// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

// renamed are action names that were written for an act which has one name
// on every surface now, and the name it has.
//
// The same act was recorded under a different name depending on where it
// was done: a grant from the People screen as access.grant and from the
// command line as auth.granted, and a revocation from the People screen as
// access.revoke and from the command line and the access review as
// auth.revoke, and an export of this log from the Integrations screen as
// siem.export where both commands that export it write auditlog.export. A
// SIEM rule, the log screen's filter and the export's classification each
// matched one spelling, so every act done the other way was missed by
// whatever was looking for it.
//
// Entries already in the log keep the names they were written with: they are
// inside the hash chain, and rewriting them is what the chain exists to
// detect. So the old names are read as the new ones instead, here, by
// everything that selects or classifies records by action.
var renamed = map[string]string{
	"access.grant":  "auth.granted",
	"access.revoke": "auth.revoke",
	"siem.export":   "auditlog.export",
}

// Canonical is the name an act is recorded under now: action itself, or the
// name that replaced it. Anything that selects or classifies records by
// action compares Canonical names, so a record written before an act was
// renamed is found with the ones written after.
func Canonical(action string) string {
	if now, ok := renamed[action]; ok {
		return now
	}
	return action
}
