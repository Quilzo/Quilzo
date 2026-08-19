// Package replica copies objects between stores that were deliberately paired.
//
// # One mechanism, three features
//
// Local-first sync, Holochain-style agent-centric validation and edge
// distribution look like three roadmap items. In a content-addressed store they
// are one: move objects by hash, verify each against its own name, and advance
// a ref only when the move is a fast-forward.
//
//	local-first  an editor works offline against its own store and syncs when
//	             it reconnects. Conflicts are exact rather than heuristic —
//	             either the incoming commit descends from what is here or it
//	             does not, and no timestamp is consulted to decide.
//	agent-centric a peer's chain of commits is verified by the receiver rather
//	             than trusted from the sender. Holochain calls this validating
//	             the source chain; here it falls out of the object id being the
//	             hash, which is why there are no signatures in this file.
//	edge         a read-only replica near the reader holds the same objects
//	             under the same names, so "is this the same content" is a string
//	             comparison rather than a cache-invalidation protocol.
//
// # What a peer is trusted for, which is almost nothing
//
// A peer is trusted to answer, and for nothing else. It cannot substitute
// content, because the name of an object is the hash of the object and PutRaw
// refuses bytes that hash to anything else. It cannot make this store forget
// anything, because a pull only ever adds. It cannot publish, because a pull
// lands on a quarantine ref and moving that into the site is a local decision a
// person makes.
//
// It can decline to answer, and it can answer slowly and enormously, so the
// walk is bounded in objects and bytes and refuses cycles.
//
// # Why a pull never lands on the site
//
// The obvious design advances the local draft or live ref to whatever the peer
// says. That makes replication a publishing channel: anybody who can get a peer
// added, or who compromises one that already exists, changes what this site
// serves. The same reasoning that keeps an agent's write off the live ref
// keeps a peer's objects off it — incoming data lands somewhere named for
// where it came from, and a person moves it.
//
// # Why there is no push
//
// Pull only, deliberately. A push means this store accepts objects it did not
// ask for, from a peer that chose the moment — which is an unauthenticated
// write endpoint with extra steps, and it is how every federation protocol
// acquires a spam problem. A store that wants content pulls it.
package replica

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/store"
)

// Limits bound what one pull may cost.
//
// A peer answering slowly and enormously is the failure this cannot verify its
// way out of: every object it sends is correct, there are simply too many. So
// the receiver decides in advance how much it is willing to accept, and stops.
type Limits struct {
	// MaxObjects is how many objects one pull may fetch.
	MaxObjects int
	// MaxBytes is the total payload one pull may accept.
	MaxBytes int
	// MaxDepth bounds the commit history walked back. A peer's chain is as
	// long as the peer says it is.
	MaxDepth int
}

// DefaultLimits are sized for a site rather than for an archive.
//
// Generous enough that an ordinary sync never notices, small enough that a
// hostile peer fills a disk slowly enough to be seen doing it. An operator
// replicating something genuinely large raises them on purpose, which is the
// point at which they think about how much disk they have.
func DefaultLimits() Limits {
	return Limits{MaxObjects: 50_000, MaxBytes: 512 << 20, MaxDepth: 1_000}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxObjects <= 0 {
		l.MaxObjects = d.MaxObjects
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	return l
}

// Source is a peer, as the walk needs it.
//
// An interface with two methods, because that is the whole protocol: what does
// your ref point at, and give me this object. Everything else — which objects
// are missing, what order to fetch them in, whether the result may be adopted —
// is decided by the receiver, which is the side with an interest in getting it
// right.
type Source interface {
	// Ref resolves a ref name to a commit id on the peer.
	Ref(ctx context.Context, name string) (string, error)
	// Object returns one object's kind and payload by id.
	Object(ctx context.Context, oid string) (kind string, payload []byte, err error)
}

// Result is what a pull did, for a person deciding whether it did the right
// thing.
type Result struct {
	// Head is the commit the peer's ref pointed at.
	Head string
	// Fetched is how many objects were new here.
	Fetched int
	// Present is how many the peer offered that this store already had. The
	// interesting number on the second sync: it should be nearly everything.
	Present int
	// Bytes is the payload accepted.
	Bytes int
	// Ref is the local ref that was moved, which is never the site's own.
	Ref string
	// FastForward reports whether the incoming head descends from what this
	// store already had at that ref.
	FastForward bool
	// Diverged is the local commit the incoming head does not descend from,
	// when it does not. Empty on a clean fast-forward.
	Diverged string
}

// QuarantineRef is where a peer's head lands.
//
// Prefixed rather than named after the remote ref, so nothing a peer says can
// produce a local ref name that collides with "draft" or "live". A peer called
// "live" gets peer-live, and the site is unaffected — the prefix does the work,
// not a list of reserved names that whoever adds the next ref would have to
// know to update.
//
// A dash rather than a slash because refs are one flat segment; a separator
// would be refused by the store, and discovering that after a pull had already
// spent its budget is the wrong place to find out.
func QuarantineRef(peer string) string { return "peer-" + peer }

// PeerPrefix is what marks a ref as a peer's rather than the site's.
const PeerPrefix = "peer-"

// Pull copies everything reachable from a peer's ref into this store.
//
// Nothing is trusted on the way in and nothing the site serves is changed. The
// local ref that moves is the peer's quarantine ref; adopting the result into
// the draft is a separate decision with a person behind it.
func Pull(ctx context.Context, s *store.Store, src Source, peer, ref string,
	lim Limits) (Result, error) {

	lim = lim.withDefaults()
	if err := ValidPeerName(peer); err != nil {
		return Result{}, err
	}
	local := QuarantineRef(peer)
	res := Result{Ref: local}

	head, err := src.Ref(ctx, ref)
	if err != nil {
		return res, fmt.Errorf("cannot read %s from %s: %w", ref, peer, err)
	}
	if !looksLikeID(head) {
		return res, fmt.Errorf(
			"%s answered with %q, which is not an object id", peer, head)
	}
	res.Head = head

	// The walk. Breadth-first over commits, then their trees, then blobs,
	// fetching only what is missing — which on every sync after the first is
	// almost nothing, because an object already here is already correct.
	if err := (&walk{
		ctx: ctx, s: s, src: src, peer: peer, lim: lim, res: &res,
	}).run(head); err != nil {
		return res, err
	}

	// Whether this is a fast-forward, decided after the objects are here so
	// the ancestry can be read locally rather than asked of the peer. A peer
	// asserting its own descent is a peer being trusted for the one thing
	// this whole design refuses to trust it for.
	was := s.GetRef(local)
	res.FastForward, res.Diverged = descends(s, head, was, lim.MaxDepth)
	if !res.FastForward {
		// The objects stay. They are verified, immutable and addressed by
		// their own hashes, so keeping them costs disk and nothing else — and
		// throwing them away would mean re-fetching everything to look at the
		// divergence somebody now has to resolve.
		return res, &Divergence{
			Peer: peer, Ref: ref, Head: head, Local: was}
	}
	if head == was {
		return res, nil
	}
	return res, s.SetRef(local, head)
}

// Divergence is a peer's head that does not descend from what this store had.
//
// Its own type because it is not a failure: it is the ordinary outcome of two
// people editing the same site in two places, which is what local-first means.
// A caller has to be able to tell it from a broken transfer, because one of
// them is somebody's afternoon and the other is a network problem.
type Divergence struct {
	Peer, Ref, Head, Local string
}

func (d *Divergence) Error() string {
	return fmt.Sprintf(
		"%s is at %s and this store is at %s, and neither descends from the "+
			"other. The objects were fetched and nothing was moved; compare "+
			"them and decide",
		d.Peer, shortID(d.Head), shortID(d.Local))
}

// IsDivergence reports whether an error is two stores having diverged.
func IsDivergence(err error) bool {
	_, ok := err.(*Divergence)
	return ok
}

// walk carries the state of one pull.
type walk struct {
	ctx  context.Context
	s    *store.Store
	src  Source
	peer string
	lim  Limits
	res  *Result
	seen map[string]bool
}

func (w *walk) run(head string) error {
	w.seen = map[string]bool{}

	// Commits first, oldest work last: the queue is the frontier and depth is
	// counted so a peer cannot hand over an unbounded chain.
	queue := []string{head}
	depth := 0
	var trees []string

	for len(queue) > 0 {
		if depth++; depth > w.lim.MaxDepth {
			return fmt.Errorf(
				"%s offered more than %d commits of history. Stopped rather "+
					"than following it: the length of a peer's chain is "+
					"whatever the peer says it is", w.peer, w.lim.MaxDepth)
		}
		var next []string
		for _, cid := range queue {
			if w.seen[cid] {
				// A cycle is impossible in a store built by this program and
				// trivial to construct by hand. Skipped rather than trusted
				// not to exist.
				continue
			}
			w.seen[cid] = true
			if err := w.fetch(cid, store.KindCommit); err != nil {
				return err
			}
			c, err := w.s.GetCommit(cid)
			if err != nil {
				return err
			}
			if c.Tree != "" {
				trees = append(trees, c.Tree)
			}
			next = append(next, c.Parents...)
		}
		queue = next
	}

	// Then the trees, which name more trees and blobs.
	for len(trees) > 0 {
		var next []string
		for _, tid := range trees {
			if w.seen[tid] {
				continue
			}
			w.seen[tid] = true
			if err := w.fetch(tid, store.KindTree); err != nil {
				return err
			}
			entries, err := w.s.GetTree(tid)
			if err != nil {
				return err
			}
			// Sorted, so a pull that fails partway through fails in the same
			// place twice and the second run is a resumption rather than a
			// different walk.
			names := make([]string, 0, len(entries))
			for n := range entries {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				oid := entries[n]
				if w.seen[oid] {
					continue
				}
				// A tree entry is a tree or a blob and the entry does not say
				// which. Tried as a tree; anything that is not one is a blob,
				// and a peer that sends neither is refused by PutRaw.
				if err := w.fetchEither(oid, &next); err != nil {
					return err
				}
			}
		}
		trees = next
	}
	return nil
}

// fetchEither stores an object whose kind the tree did not record, queueing it
// for descent if it turned out to be a tree.
func (w *walk) fetchEither(oid string, next *[]string) error {
	if w.s.Has(oid) {
		w.res.Present++
		// Already here and already verified when it arrived. Still descended
		// into if it is a tree, because having a tree is not having what it
		// names — an interrupted pull leaves exactly that state.
		if _, err := w.s.GetTree(oid); err == nil {
			*next = append(*next, oid)
		}
		w.seen[oid] = true
		return nil
	}
	kind, payload, err := w.src.Object(w.ctx, oid)
	if err != nil {
		return fmt.Errorf("%s could not supply %s: %w", w.peer, shortID(oid), err)
	}
	if err := w.accept(oid, kind, payload); err != nil {
		return err
	}
	if kind == store.KindTree {
		*next = append(*next, oid)
	} else {
		w.seen[oid] = true
	}
	return nil
}

// fetch stores one object of a known kind.
func (w *walk) fetch(oid, kind string) error {
	if w.s.Has(oid) {
		w.res.Present++
		return nil
	}
	got, payload, err := w.src.Object(w.ctx, oid)
	if err != nil {
		return fmt.Errorf("%s could not supply %s: %w", w.peer, shortID(oid), err)
	}
	if got != kind {
		return fmt.Errorf(
			"%s offered %s as a %s where a %s was expected",
			w.peer, shortID(oid), got, kind)
	}
	return w.accept(oid, kind, payload)
}

// accept applies the budget and hands the bytes to the store, which is where
// they are checked against their own name.
func (w *walk) accept(oid, kind string, payload []byte) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.res.Fetched >= w.lim.MaxObjects {
		return fmt.Errorf(
			"stopped after %d objects from %s. Nothing is wrong with them "+
				"individually; there are more than this store agreed to take",
			w.lim.MaxObjects, w.peer)
	}
	if w.res.Bytes+len(payload) > w.lim.MaxBytes {
		return fmt.Errorf(
			"stopped at %d bytes from %s, which is the limit for one pull",
			w.res.Bytes, w.peer)
	}
	if err := w.s.PutRaw(oid, kind, payload); err != nil {
		return err
	}
	w.res.Fetched++
	w.res.Bytes += len(payload)
	return nil
}

// descends reports whether head has ancestor in its history.
//
// Read locally, from objects already verified. The empty ancestor case is a
// fast-forward by definition: a ref that pointed at nothing is one that cannot
// have diverged.
func descends(s *store.Store, head, ancestor string, maxDepth int) (bool, string) {
	if ancestor == "" || head == ancestor {
		return true, ""
	}
	seen := map[string]bool{}
	queue := []string{head}
	for depth := 0; len(queue) > 0 && depth < maxDepth; depth++ {
		var next []string
		for _, cid := range queue {
			if seen[cid] {
				continue
			}
			seen[cid] = true
			if cid == ancestor {
				return true, ""
			}
			c, err := s.GetCommit(cid)
			if err != nil {
				continue
			}
			next = append(next, c.Parents...)
		}
		queue = next
	}
	return false, ancestor
}

// ValidPeerName refuses a name that could not be a ref segment.
//
// The name becomes part of a local ref path, so it has the same rule as any
// other segment. Checked here rather than relying on SetRef to refuse, because
// the failure would otherwise land after a pull has already spent its budget.
func ValidPeerName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("a peer needs a name, so a ref can be named after it")
	}
	// Sixty-four is the store's whole segment budget, and the prefix is part
	// of it. Checked against what the ref will actually be rather than against
	// the name alone, which is how a limit ends up off by the length of a
	// constant nobody re-read.
	if len(QuarantineRef(name)) > 64 {
		return fmt.Errorf("%q is too long for a peer name", name)
	}
	if strings.HasPrefix(name, PeerPrefix) {
		// Otherwise peer "peer-x" and peer "x" both reach for different refs
		// that look like each other's, and a person reading `quilzo peers`
		// has to work out which is which.
		return fmt.Errorf(
			"%q starts with %q, which is how this store marks a peer's ref. "+
				"Pick a name that is not already prefixed", name, PeerPrefix)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf(
				"%q is not a usable peer name: letters, digits, dash and "+
					"underscore. The name becomes a ref path, and a separator "+
					"in it is a ref somewhere else", name)
		}
	}
	return nil
}

func looksLikeID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "nothing"
	}
	return s
}
