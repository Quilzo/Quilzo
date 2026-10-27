// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/quilzo/quilzo/internal/audit"
)

// No audit record names a person where the log keeps it in clear.
//
// The log pseudonymises the principal and the details under
// audit.IdentityKeys, and a stream to a SIEM promises the people in it stay
// pseudonymous. A person written into a resource, or into a sentence in
// another detail ("make lee admin on /", "dana is the only administrator"),
// went out in clear beside their own pseudonym. TestEveryDetailNamingAPerson
// IsPseudonymised reads the source for some of this; this watches every
// record every test in the package writes, against the people the store's
// policy names, and TestMain fails the run on any.

var leaked = struct {
	sync.Mutex
	seen map[string]string
}{seen: map[string]string{}}

func init() { auditWritten = noteNamesInClear }

// guardKey is a log key, for working out what a record looks like written.
var guardKey = []byte("a key the names guard writes with")

// noteNamesInClear looks for the store's people in what a keyed log writes
// in clear: the resource, and every detail not under an identity key. The
// log pseudonymises the people a record names under an identity key
// wherever the record mentions them, so what is left is a person the
// writer did not name as one.
func noteNamesInClear(root string, r audit.Record) {
	pol, err := loadPolicy(root)
	if err != nil {
		return
	}
	var people []*regexp.Regexp
	var names []string
	seen := map[string]bool{}
	for _, b := range pol.Bindings {
		if seen[b.Principal] || len(b.Principal) < 3 {
			continue
		}
		seen[b.Principal] = true
		names = append(names, b.Principal)
		people = append(people, regexp.MustCompile(`(^|[^\w@.-])`+regexp.QuoteMeta(b.Principal)+`($|[^\w@-])`))
	}
	resource, detail := audit.AsWritten(guardKey, r)
	fields := map[string]string{"resource": resource}
	for k, v := range detail {
		if !audit.IdentityKeys[k] {
			fields["detail "+k] = v
		}
	}
	for field, v := range fields {
		for i, re := range people {
			if re.MatchString(v) {
				leaked.Lock()
				key := r.Action + " " + field
				if _, ok := leaked.seen[key]; !ok {
					leaked.seen[key] = fmt.Sprintf("%s names %s: %q", key, names[i], v)
				}
				leaked.Unlock()
			}
		}
	}
}

func namesLeaked() []string {
	leaked.Lock()
	defer leaked.Unlock()
	var out []string
	for _, v := range leaked.seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
