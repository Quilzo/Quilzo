package public

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"

	"github.com/lithoform/lithoform/internal/listing"
	"github.com/lithoform/lithoform/internal/site"
)

// Serving a page that shows a query.
//
// Two things have to be right for this to work at all, and neither is obvious
// from the feature description.
//
// The first is that resolution happens before rendering, because the template
// language has no calls in it. That is not a limitation being worked around —
// it is why a template cannot be made to run a query somebody smuggled into
// content.
//
// The second is caching, and it is the one that would have shipped broken. A
// page's ETag here is its content hash, which is exact and free and stops being
// either the moment the page's output depends on something else. See renderTag.

// dataTree is the tree the published content lives in.
//
// Listings read records out of the same tree the pages come from, so this is
// what changes when any record changes — which is precisely the thing a page
// embedding a listing has to notice.
func (st *Site) dataTree() string {
	ref := st.Ref
	if ref == "" {
		ref = site.RefLive
	}
	commit := st.Store.GetRef(ref)
	if commit == "" {
		return ""
	}
	c, err := st.Store.GetCommit(commit)
	if err != nil {
		return ""
	}
	return c.Tree
}

// renderTag names everything a rendered page depended on.
//
// The page's own hash, the tree its listings read, and the arguments they were
// given. Any of the three changing produces a different name, which is what an
// ETag is for — and the reason to compute it rather than fall back to
// no-caching is that a listing page is exactly the page that gets traffic.
//
// Only the arguments a listing actually declares are mixed in. Including the
// whole query string would give every tracking parameter its own cache entry,
// which is a cache that never hits.
func renderTag(pageHash, dataTree string, names []string,
	args map[string]string) string {

	h := sha256.New()
	h.Write([]byte(pageHash))
	h.Write([]byte{0})
	h.Write([]byte(dataTree))
	for _, n := range names {
		h.Write([]byte{0})
		h.Write([]byte(n))
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k))
		h.Write([]byte{1})
		h.Write([]byte(args[k]))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// firstOf flattens a query string to one value per name.
func firstOf(v url.Values) map[string]string {
	out := make(map[string]string, len(v))
	for k, vals := range v {
		if len(vals) > 0 {
			out[k] = vals[0]
		}
	}
	return out
}

var _ = listing.Data
