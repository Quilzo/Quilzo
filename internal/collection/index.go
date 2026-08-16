package collection

import (
	"sort"
	"sync"

	"github.com/rsh1k/scrivet/internal/store"
)

// Reading a collection without reading it again.
//
// # The measurement that produced this
//
// Filtering a collection meant walking the tree, reading every record's blob
// off disk and JSON-decoding it, on every query. Measured:
//
//	    100 records    5.9ms
//	  1,000 records   48.7ms
//	 10,000 records  382.1ms
//
// Linear, and the constant is disk. That is survivable for an occasional
// listing on an admin screen and it is not survivable for the thing this was
// built to support: a page that embeds three listings renders in over a second
// at ten thousand records, and a site with a hundred such pages cannot be
// rebuilt at all.
//
// # Why the cache can never be stale
//
// The store is content-addressed, so a tree's name is a hash of everything
// under it. Two different contents cannot share a tree identifier, which means
// an index keyed by tree identifier is correct by construction — there is no
// invalidation to get wrong, no TTL to tune, and no window in which a reader
// sees the previous version.
//
// Most systems pay for cache invalidation because their identifiers are names
// rather than hashes. This one gets it for nothing, and that is worth stating
// plainly because it is the entire reason this file is fifty lines rather than
// five hundred.
//
// # Why a new commit is cheap
//
// A write rewrites the trees along one path and nothing else, so a record whose
// blob did not change keeps the same blob identifier. The index therefore
// carries its decoded records keyed by blob identifier, and building the next
// index reuses every one it recognises. Editing one record in ten thousand
// costs one read.
//
// That is the same property the store already rests on, used a second time.

// Index is a decoded collection at one tree.
//
// Immutable once built. Sharing one between goroutines is safe because nothing
// mutates it; the cache below is what needs a lock.
type Index struct {
	// Tree is the tree this was built from, which is also its identity.
	Tree string
	// Collection is which one.
	Collection string
	// Records, sorted by id so a listing without an explicit sort is stable.
	Records []Record
	// bySubtree is what makes the next build cheap: every tree object this
	// walked, mapped to the records beneath it. A subtree whose identifier is
	// unchanged has unchanged contents — that is what content addressing
	// means — so the next build takes those records wholesale and does not
	// descend.
	bySubtree map[string][]Record
}

// Len is how many records this holds.
func (i *Index) Len() int { return len(i.Records) }

// Query runs a filter over the decoded records.
//
// No disk, no decode. This is the operation a rendered page performs, and it is
// the reason the rest of the file exists.
func (i *Index) Query(q Query) (out []Record, total int) {
	return q.Apply(i.Records)
}

// Build reads a collection, reusing whatever a previous index already decoded.
//
// prev may be nil, and may be an index of a different tree — reuse is keyed on
// blob identifiers, which are global, so an index of any earlier state helps.
// Passing an index of an unrelated collection is harmless and simply reuses
// nothing.
func Build(s *store.Store, tree, collection string, prev *Index) (*Index, error) {
	if err := ValidName(collection); err != nil {
		return nil, err
	}
	idx := &Index{Tree: tree, Collection: collection,
		bySubtree: map[string][]Record{}}
	if tree == "" {
		return idx, nil
	}

	// Descend by name rather than flattening.
	//
	// The first version of this called GetNested, which walks every tree
	// object under the root and returns one flat map. Reuse then skipped the
	// blob reads and still paid for the walk: rebuilding after a single edit
	// to a ten-thousand-record collection cost 250ms, because the walk alone
	// is about twenty-seven hundred reads. Descending manually means an
	// unchanged shard is one map lookup and no read at all.
	root, err := s.GetTree(tree)
	if err != nil {
		return nil, err
	}
	dataOID, ok := root["data"]
	if !ok {
		return idx, nil
	}
	data, err := s.GetTree(dataOID)
	if err != nil {
		return nil, err
	}
	collOID, ok := data[collection]
	if !ok {
		return idx, nil
	}
	if err := idx.walk(s, collOID, prev, 0); err != nil {
		return nil, err
	}

	// Sorted here, once, rather than on every query. Map iteration order is
	// randomised in Go, so without this the same query would return the same
	// records in a different order on each call — which looks like data
	// changing to anybody reading a page.
	sort.Slice(idx.Records, func(a, b int) bool {
		return idx.Records[a].ID < idx.Records[b].ID
	})
	return idx, nil
}

// shardDepth is how many levels of shard sit between a collection and its
// records: data/<collection>/<aa>/<bb>/<id>, so two.
//
// Known rather than discovered, because asking whether each object is a tree
// costs a read per object — which is the expense this whole file is removing.
const shardDepth = 2

// walk descends one subtree, reusing anything the previous index already has.
func (i *Index) walk(s *store.Store, oid string, prev *Index, depth int) error {
	// The reuse. A tree identifier is a hash of everything beneath it, so an
	// identifier this index has seen before names bytes that have not changed
	// — there is nothing to re-read and nothing to check.
	if prev != nil {
		if recs, known := prev.bySubtree[oid]; known {
			i.Records = append(i.Records, recs...)
			i.bySubtree[oid] = recs
			return nil
		}
	}

	entries, err := s.GetTree(oid)
	if err != nil {
		return err
	}
	var mine []Record
	for _, child := range entries {
		if depth < shardDepth {
			before := len(i.Records)
			if err := i.walk(s, child, prev, depth+1); err != nil {
				return err
			}
			mine = append(mine, i.Records[before:]...)
			continue
		}
		r, rerr := read(s, child)
		if rerr != nil {
			// One unreadable record must not make the collection unreadable.
			// `verify` is the tool that reports it; a listing that fails
			// entirely tells somebody their data is gone when one row is
			// damaged.
			continue
		}
		i.Records = append(i.Records, *r)
		mine = append(mine, *r)
	}
	i.bySubtree[oid] = mine
	return nil
}

// MaxCached is how many trees the cache keeps per process.
//
// Small, because the point is to serve the current tree and the one before it
// — a render loop asks for the same tree repeatedly, and a publish moves it
// once. Keeping more would hold decoded records for states nobody is looking
// at, which is memory spent on history the store already has on disk.
const MaxCached = 4

// Cache holds indexes by tree, bounded.
//
// One per process. Safe for concurrent use, which matters because it is read
// by every request the admin and the public site serve.
type Cache struct {
	mu    sync.Mutex
	byKey map[string]*Index
	order []string
}

func NewCache() *Cache {
	return &Cache{byKey: map[string]*Index{}}
}

// For returns the index for a collection at a tree, building it if needed.
//
// The build happens under the lock. That serialises two requests that both
// arrive for a tree nobody has indexed yet, which is the correct trade: the
// alternative is both of them doing the same expensive read, and the second
// one throwing its answer away.
func (c *Cache) For(s *store.Store, tree, collection string) (*Index, error) {
	if c == nil {
		return Build(s, tree, collection, nil)
	}
	key := tree + "\x00" + collection

	c.mu.Lock()
	defer c.mu.Unlock()

	if idx, have := c.byKey[key]; have {
		return idx, nil
	}

	// Any index of this collection is a useful starting point, whatever tree
	// it came from: unchanged records keep their blob identifiers, so the
	// overlap between two adjacent commits is nearly total.
	var prev *Index
	for _, k := range c.order {
		if cand := c.byKey[k]; cand != nil && cand.Collection == collection {
			prev = cand
		}
	}

	idx, err := Build(s, tree, collection, prev)
	if err != nil {
		return nil, err
	}
	c.byKey[key] = idx
	c.order = append(c.order, key)
	for len(c.order) > MaxCached {
		delete(c.byKey, c.order[0])
		c.order = c.order[1:]
	}
	return idx, nil
}

// Names is Names, through the cache.
//
// Deliberately not cached itself: it reads the tree structure rather than the
// records, which is the cheap half, and caching it would mean a second thing
// keyed on the same tree that could be evicted at a different time.
func (c *Cache) Names(s *store.Store, tree string) ([]string, error) {
	return Names(s, tree)
}
