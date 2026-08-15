// Package collection stores many records of one type, so this can hold an
// application's data rather than a site's pages.
//
// The measurement that produced this: one edit to a store of twenty thousand
// pages cost 201ms, and five writes a second is not an application. The cause
// was not content-addressing — it was that every write re-serialised and
// re-hashed every page and wrote one flat tree listing all of them, which is
// O(n) work to change one thing.
//
// Git has the same object model and does not have that cost, because it does
// two things this did not:
//
//	It reuses unchanged objects. A blob whose content has not changed already
//	exists under its hash, and there is nothing to write.
//
//	It nests trees. Writing one file rewrites the trees along its path and
//	nothing else, because every sibling subtree is still addressed by the hash
//	it already had.
//
// So records live in two levels of shards keyed by the first four hex
// characters of the record's id — the same shape as git's object directories.
// Writing one record touches its blob, its shard, the collection, and the
// root: four objects, whatever the collection holds. A million records in a
// collection means the shard a write lands in holds about fifteen of them.
//
// What this does not fix, and is worth being exact about: writes are still
// serialised by the store's ref lock, so the ceiling is one writer at a time
// rather than one writer per collection. That is the next thing to change and
// it is a different change.
package collection

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Record is one row.
//
// The id is separate from the fields rather than a field inside them, because
// an identifier that lives in the data is an identifier somebody can edit. It
// is assigned once, by the store, and never by the caller — which is what lets
// it be the address of the thing rather than a claim about it.
type Record struct {
	ID     string         `json:"id"`
	Fields map[string]any `json:"fields"`
	// Created and Updated are stamped by the store. Both are held in the
	// record rather than derived from history, because deriving "when was this
	// last changed" from a commit walk is O(history) and this is asked on
	// every listing.
	Created int64 `json:"created"`
	Updated int64 `json:"updated"`
}

// Name rules for a collection: the same shape as a content type name, because
// a collection is the plural of one and two different rules would be two
// different things to get wrong.
var reName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidName reports whether a collection may be called this.
func ValidName(s string) error {
	if !reName.MatchString(s) {
		return fmt.Errorf(
			"%q is not a usable collection name: lowercase letters, digits "+
				"and underscores, starting with a letter", s)
	}
	// Reserved because the tree holds pages under this name already, and a
	// collection called "pages" would be two things at one address.
	if s == "pages" {
		return fmt.Errorf(
			"%q is reserved: it is where the site's pages live", s)
	}
	return nil
}

// IDLen is the length of a generated identifier in hex characters.
//
// 128 bits. Long enough that identifiers can be minted independently — by two
// processes, or by a client that has not asked — without a collision being
// something anybody has to think about, and short enough to appear in a URL
// without being the whole URL.
const IDLen = 32

var reID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// NewID mints an identifier.
func NewID() (string, error) {
	b := make([]byte, IDLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("no entropy for an identifier: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ValidID reports whether a string can address a record.
//
// Checked rather than trusted, because the id becomes a path inside the tree.
// An id containing a slash would place a record in a shard nobody can find it
// in, and one containing a dot would be a traversal.
func ValidID(id string) error {
	if !reID.MatchString(id) {
		return fmt.Errorf(
			"%q is not a record id: 32 hexadecimal characters", id)
	}
	return nil
}

// Path returns where a record lives inside the store's tree.
//
// Two levels of shard, from the id's own first four characters. The id is
// random, so the shards fill evenly without anybody balancing them — and
// because the id is fixed at creation, a record's path never changes, which is
// what lets a write touch one shard rather than reorganise a collection.
//
//	data/devices/a3/f9/a3f9c0...
func Path(collection, id string) string {
	return "data/" + collection + "/" + id[0:2] + "/" + id[2:4] + "/" + id
}

// Prefix returns the path prefix a whole collection lives under.
func Prefix(collection string) string { return "data/" + collection + "/" }

// IsCollectionPath reports whether a tree entry belongs to a collection, and
// which one.
//
// Used to walk a store's tree without a separate index of what collections
// exist. An index would be a second thing to keep true, and the tree already
// knows.
func IsCollectionPath(path string) (collection, id string, ok bool) {
	if !strings.HasPrefix(path, "data/") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, "data/"), "/")
	if len(parts) != 4 {
		return "", "", false
	}
	if ValidName(parts[0]) != nil || ValidID(parts[3]) != nil {
		return "", "", false
	}
	// The shards have to agree with the id, or the record is somewhere it
	// cannot be found by its own address.
	if parts[1] != parts[3][0:2] || parts[2] != parts[3][2:4] {
		return "", "", false
	}
	return parts[0], parts[3], true
}

// Query is how records are selected.
//
// Deliberately small, and the shape is the argument. Every field is a value to
// match or a bound to compare, never an expression — the moment a query
// carries an expression it needs an evaluator, and an evaluator over
// user-supplied input in a data store is the shape of every injection
// vulnerability there has ever been.
//
// It is also what makes the cost predictable: a query is a scan with a filter,
// and there is no arrangement of these fields that is accidentally quadratic.
type Query struct {
	// Equals matches fields exactly. All of them must match.
	Equals map[string]any
	// Contains matches a substring, case-insensitively, in a string field.
	Contains map[string]string
	// Since and Until bound Updated, in unix seconds. Zero means unbounded.
	Since, Until int64
	// Sort names a field to order by. Empty means by id, which is stable and
	// meaningless — deliberately, so nobody mistakes insertion order for
	// something the store promises.
	Sort string
	// Descending reverses the order.
	Descending bool
	// Limit and Offset page the result. A zero limit means DefaultLimit rather
	// than everything: a query with no limit against a million records is a
	// question somebody asked by accident.
	Limit, Offset int
}

// DefaultLimit and MaxLimit bound a query.
const (
	DefaultLimit = 50
	MaxLimit     = 1000
)

// Match reports whether a record satisfies a query's filters.
func (q Query) Match(r Record) bool {
	for field, want := range q.Equals {
		if !equal(r.Fields[field], want) {
			return false
		}
	}
	for field, want := range q.Contains {
		got, ok := r.Fields[field].(string)
		if !ok {
			return false
		}
		if !strings.Contains(strings.ToLower(got), strings.ToLower(want)) {
			return false
		}
	}
	if q.Since > 0 && r.Updated < q.Since {
		return false
	}
	if q.Until > 0 && r.Updated > q.Until {
		return false
	}
	return true
}

// equal compares two values the way JSON round-tripping leaves them.
//
// A number that went through JSON is a float64 whatever it started as, so an
// integer typed in a query would never match an integer stored in a record
// without this. That mismatch produces a query that silently returns nothing,
// which is the worst failure a data store has: it looks like an answer.
func equal(got, want any) bool {
	if got == nil || want == nil {
		return got == want
	}
	gs, gok := got.(string)
	ws, wok := want.(string)
	if gok && wok {
		return gs == ws
	}
	if gf, ok := toFloat(got); ok {
		if wf, ok := toFloat(want); ok {
			return gf == wf
		}
	}
	gb, gok := got.(bool)
	wb, wok := want.(bool)
	if gok && wok {
		return gb == wb
	}
	return fmt.Sprint(got) == fmt.Sprint(want)
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}

// Apply filters, sorts and pages a set of records.
//
// In memory, over records the caller has already loaded. That is honest about
// what this is: a scan, not an index. It is fast enough for the collections a
// single node holds and it is not a query planner, and saying so here stops
// somebody expecting one.
func (q Query) Apply(in []Record) (out []Record, total int) {
	for _, r := range in {
		if q.Match(r) {
			out = append(out, r)
		}
	}
	total = len(out)

	field := q.Sort
	sort.SliceStable(out, func(i, j int) bool {
		var less bool
		switch field {
		case "":
			less = out[i].ID < out[j].ID
		case "created":
			less = out[i].Created < out[j].Created
		case "updated":
			less = out[i].Updated < out[j].Updated
		default:
			less = compare(out[i].Fields[field], out[j].Fields[field]) < 0
		}
		if q.Descending {
			return !less
		}
		return less
	})

	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > len(out) {
		offset = len(out)
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[offset:end], total
}

// compare orders two field values.
//
// Numbers numerically, strings lexically, and anything else by its printed
// form — which is arbitrary but total, and a total order is what a sort needs.
// A comparison that is not total makes sort.Slice produce a different answer
// on the same input depending on the initial arrangement.
func compare(a, b any) int {
	if af, ok := toFloat(a); ok {
		if bf, ok := toFloat(b); ok {
			switch {
			case af < bf:
				return -1
			case af > bf:
				return 1
			}
			return 0
		}
	}
	as, bs := fmt.Sprint(a), fmt.Sprint(b)
	// nil sorts first and consistently, rather than as the string "<nil>"
	// landing in the middle of the alphabet.
	if a == nil && b != nil {
		return -1
	}
	if b == nil && a != nil {
		return 1
	}
	return strings.Compare(as, bs)
}

// Stamp fills in the timestamps for a write.
func Stamp(r *Record, now time.Time, existing *Record) {
	ts := now.Unix()
	r.Updated = ts
	if existing != nil && existing.Created > 0 {
		// Created never moves. A record whose creation time changes on every
		// edit cannot answer "how long have we had this", which is most of
		// what a creation time is for.
		r.Created = existing.Created
		return
	}
	r.Created = ts
}
