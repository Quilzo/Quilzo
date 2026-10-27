// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/quilzo/quilzo/internal/audit"
)

// No audit record the admin writes names a person where the log keeps it
// in clear: not in the resource, and not in a detail outside
// audit.IdentityKeys. Watched for every record every test in the package
// writes, against the people the server's policy names; TestMain fails the
// run on any. cmd/quilzo/auditnames_test.go does the same for the command
// line.

var leaked = struct {
	sync.Mutex
	seen map[string]string
}{seen: map[string]string{}}

func init() { auditSeen = noteNamesInClear }

// guardKey is a log key, for working out what a record looks like written.
var guardKey = []byte("a key the names guard writes with")

// noteNamesInClear looks for the server's people in what a keyed log writes
// in clear, for the record the command line makes of this (adminRecord:
// whoever is under "by" acted).
func noteNamesInClear(s *Server, action, resource string, detail map[string]string) {
	if s.Policy == nil {
		return
	}
	var people []*regexp.Regexp
	var names []string
	seen := map[string]bool{}
	for _, b := range s.Policy.Snapshot() {
		if seen[b.Principal] || len(b.Principal) < 3 {
			continue
		}
		seen[b.Principal] = true
		names = append(names, b.Principal)
		people = append(people, regexp.MustCompile(`(^|[^\w@.-])`+regexp.QuoteMeta(b.Principal)+`($|[^\w@-])`))
	}
	r := audit.Record{Action: action, Resource: resource, Principal: detail["by"], Kind: audit.KindHuman, Detail: detail}
	if r.Principal == "" {
		r.Principal, r.Kind = "anonymous", audit.KindUnknown
	}
	resource, written := audit.AsWritten(guardKey, r)
	fields := map[string]string{"resource": resource}
	for k, v := range written {
		if !audit.IdentityKeys[k] {
			fields["detail "+k] = v
		}
	}
	for field, v := range fields {
		for i, re := range people {
			if re.MatchString(v) {
				leaked.Lock()
				key := action + " " + field
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
