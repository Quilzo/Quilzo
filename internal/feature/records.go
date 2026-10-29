// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"fmt"
	"regexp"

	"github.com/quilzo/quilzo/internal/collection"
)

// Records a package brings: the posts of a blog brought from elsewhere, say.
//
// # By reference, not inline
//
// A blog's posts can be thousands of records and many megabytes. A package
// is something a person reads and approves, carried from the check to the
// install in a form, and a package that held every post would be neither
// readable nor carriable. So a package names its rows by the SHA-256 of a
// file staged in this installation, with the collection they go into and
// how many there are, and the install writes exactly the bytes that hash
// names: what is installed is what was read, as with the rest of it.
//
// Rows are brought once, when the package is first installed. A later
// version of the same package leaves them alone: by then they are content
// people may have changed, and writing over it is not an upgrade.

// MaxRecordSet bounds the rows one set brings.
const MaxRecordSet = 50000

// RecordSet is rows a package adds to one of its collections.
type RecordSet struct {
	Collection string `json:"collection"`
	Count      int    `json:"count"`
	// SHA256 names the staged file of rows, as lowercase hex.
	SHA256 string `json:"sha256"`
}

var reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validateRecords(p *Package, bad func(string, ...any)) {
	declared := map[string]bool{}
	for _, c := range p.Collections {
		declared[c.Name] = true
	}
	seen := map[string]bool{}
	for _, r := range p.Records {
		switch {
		case collection.ValidName(r.Collection) != nil:
			bad("records: %q is not a collection name", r.Collection)
		case !declared[r.Collection]:
			bad("records: %q is not a collection this package declares, so nothing says what its rows must be",
				r.Collection)
		case seen[r.Collection]:
			bad("records: %q is brought twice", r.Collection)
		case r.Count < 1 || r.Count > MaxRecordSet:
			bad("records: %d rows for %q; a set brings 1 to %d", r.Count, r.Collection, MaxRecordSet)
		case !reSHA256.MatchString(r.SHA256):
			bad("records: the rows for %q are not named by a SHA-256", r.Collection)
		}
		seen[r.Collection] = true
	}
}

// recordsLine is what the card says a set brings.
func recordsLine(r RecordSet) Line {
	return Line{Text: fmt.Sprintf("Brings %d record(s) into %q, once, when it is first installed", r.Count,
		r.Collection)}
}
