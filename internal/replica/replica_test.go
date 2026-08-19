package replica

import (
	"context"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// storeSource is a peer backed by a real store, which is what a peer is.
type storeSource struct {
	s *store.Store
	// tamper rewrites what is served, for the tests about a hostile peer.
	tamper func(oid, kind string, payload []byte) (string, []byte, error)
	// asked counts what was requested, so "it did not re-fetch" is checkable.
	asked map[string]int
}

func (p *storeSource) Ref(_ context.Context, name string) (string, error) {
	return p.s.GetRef(name), nil
}

func (p *storeSource) Object(_ context.Context, oid string) (string, []byte, error) {
	if p.asked == nil {
		p.asked = map[string]int{}
	}
	p.asked[oid]++
	kind, payload, err := p.s.GetRaw(oid)
	if err != nil {
		return "", nil, err
	}
	if p.tamper != nil {
		return p.tamper(oid, kind, payload)
	}
	return kind, payload, nil
}

func peerStore(t *testing.T, pages map[string]any) (*store.Store, string) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := site.SaveDraft(s, pages, "peer content", "them")
	if err != nil {
		t.Fatal(err)
	}
	return s, cid
}

func emptyStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The ordinary pull, so the refusals below are about refusing rather than about
// a path that never worked.
func TestAPullCopiesEverythingReachable(t *testing.T) {
	remote, head := peerStore(t, map[string]any{
		"index":   map[string]any{"title": "Home", "body": "Hello."},
		"pricing": map[string]any{"title": "Pricing", "body": "Numbers."},
	})
	local := emptyStore(t)

	res, err := Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{})
	if err != nil {
		t.Fatalf("a clean pull failed: %v", err)
	}
	if res.Head != head {
		t.Errorf("pulled %s, the peer is at %s", res.Head, head)
	}
	if res.Fetched == 0 {
		t.Error("nothing was fetched")
	}
	if !res.FastForward {
		t.Error("a pull into an empty store is not a fast-forward")
	}

	// The content is here and readable, which is the only proof that matters.
	pages, err := site.PagesAt(local, res.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Errorf("got %d pages, want 2: %v", len(pages), pages)
	}
	body, _ := pages["pricing"].(map[string]any)
	if body["body"] != "Numbers." {
		t.Errorf("the content did not survive: %v", pages["pricing"])
	}
}

// A pull lands in quarantine and does not touch the site.
//
// The design this rejects advances the local draft to whatever the peer says,
// which makes replication a publishing channel: anybody who gets a peer added,
// or compromises one already there, changes what this site serves.
func TestAPullDoesNotTouchTheSite(t *testing.T) {
	remote, _ := peerStore(t, map[string]any{
		"index": map[string]any{"title": "Theirs"}})
	local := emptyStore(t)
	if _, err := site.SaveDraft(local, map[string]any{
		"index": map[string]any{"title": "Ours"}}, "ours", "us"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(local, ""); err != nil {
		t.Fatal(err)
	}
	liveBefore, draftBefore := local.GetRef(site.RefLive), local.GetRef(site.RefDraft)

	res, err := Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	if local.GetRef(site.RefLive) != liveBefore {
		t.Error("a pull moved the live ref, which makes replication a way to " +
			"publish")
	}
	if local.GetRef(site.RefDraft) != draftBefore {
		t.Error("a pull moved the draft")
	}
	if res.Ref != "peer-origin" || local.GetRef("peer-origin") != res.Head {
		t.Errorf("the peer's head did not land on its own ref: %+v", res)
	}
	// And the site still serves what it served.
	pages, _ := site.PagesAt(local, site.RefLive)
	body, _ := pages["index"].(map[string]any)
	if body["title"] != "Ours" {
		t.Errorf("the live site changed: %v", pages["index"])
	}
}

// A peer that substitutes content is caught by the name, not by a signature.
func TestAPeerCannotSubstituteContent(t *testing.T) {
	remote, _ := peerStore(t, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Genuine."}})
	local := emptyStore(t)

	src := &storeSource{s: remote, tamper: func(oid, kind string, payload []byte) (string, []byte, error) {
		if kind == store.KindBlob {
			return kind, []byte(`{"body":"Substituted.","title":"Home"}`), nil
		}
		return kind, payload, nil
	}}

	_, err := Pull(context.Background(), local, src, "origin", site.RefDraft, Limits{})
	if err == nil {
		t.Fatal("a peer substituted content and the pull accepted it")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Errorf("the refusal does not explain that the name is the hash: %v", err)
	}
	// And nothing landed.
	if local.GetRef("peer-origin") != "" {
		t.Error("the quarantine ref moved despite the refusal")
	}
}

// A peer that mislabels an object's kind is refused.
//
// Kind is folded into the object id, so a blob and a tree with identical bytes
// have different names — which is what stops content an attacker controls from
// also being read as a tree.
func TestAPeerCannotMislabelAnObject(t *testing.T) {
	remote, _ := peerStore(t, map[string]any{
		"index": map[string]any{"title": "Home"}})
	local := emptyStore(t)

	src := &storeSource{s: remote, tamper: func(oid, kind string, payload []byte) (string, []byte, error) {
		if kind == store.KindBlob {
			return store.KindTree, payload, nil
		}
		return kind, payload, nil
	}}

	if _, err := Pull(context.Background(), local, src, "origin",
		site.RefDraft, Limits{}); err == nil {
		t.Fatal("a peer relabelled a blob as a tree and it was stored")
	}
}

// An object kind this build has never heard of is refused rather than stored.
func TestAnUnknownObjectKindIsRefused(t *testing.T) {
	remote, _ := peerStore(t, map[string]any{
		"index": map[string]any{"title": "Home"}})
	local := emptyStore(t)

	src := &storeSource{s: remote, tamper: func(oid, kind string, payload []byte) (string, []byte, error) {
		if kind == store.KindBlob {
			return "attachment", payload, nil
		}
		return kind, payload, nil
	}}

	if _, err := Pull(context.Background(), local, src, "origin",
		site.RefDraft, Limits{}); err == nil {
		t.Fatal("an object of an unknown kind was stored")
	}
}

// Divergence is reported as itself, not as a failure.
//
// Two people editing the same site in two places is what local-first means, and
// a caller has to be able to tell that afternoon's work from a network problem.
func TestDivergenceIsReportedAndNothingIsMoved(t *testing.T) {
	remote, _ := peerStore(t, map[string]any{
		"index": map[string]any{"title": "Theirs"}})
	local := emptyStore(t)

	// First sync: clean.
	if _, err := Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{}); err != nil {
		t.Fatal(err)
	}
	adopted := local.GetRef("peer-origin")

	// Both sides now write, from the same base but not from each other.
	if _, err := site.SaveDraft(local, map[string]any{
		"index": map[string]any{"title": "Ours now"}}, "local", "us"); err != nil {
		t.Fatal(err)
	}
	if err := local.SetRef("peer-origin", local.GetRef(site.RefDraft)); err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(remote, map[string]any{
		"index": map[string]any{"title": "Theirs now"}}, "remote", "them"); err != nil {
		t.Fatal(err)
	}

	before := local.GetRef("peer-origin")
	res, err := Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{})
	if err == nil {
		t.Fatal("two diverged stores synced without anybody noticing")
	}
	if !IsDivergence(err) {
		t.Errorf("divergence is reported as an ordinary error, so a caller "+
			"cannot tell it from a broken transfer: %v", err)
	}
	if local.GetRef("peer-origin") != before {
		t.Error("the ref moved despite the divergence")
	}
	if res.FastForward {
		t.Error("a diverged pull reported itself as a fast-forward")
	}
	_ = adopted

	// The objects were kept. Throwing them away would mean re-fetching
	// everything to look at the divergence somebody now has to resolve.
	if !local.Has(res.Head) {
		t.Error("the peer's commit was discarded, so the divergence cannot " +
			"be examined without fetching it all again")
	}
}

// A second sync fetches almost nothing.
func TestASecondSyncFetchesWhatChangedAndNoMore(t *testing.T) {
	remote, _ := peerStore(t, map[string]any{
		"index":   map[string]any{"title": "Home"},
		"pricing": map[string]any{"title": "Pricing"},
	})
	local := emptyStore(t)

	first, err := Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{})
	if err != nil {
		t.Fatal(err)
	}

	// One page changes on the peer.
	pages, err := site.PagesAt(remote, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["pricing"] = map[string]any{"title": "Pricing", "body": "New."}
	if _, err := site.SaveDraft(remote, pages, "update", "them"); err != nil {
		t.Fatal(err)
	}

	second, err := Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{})
	if err != nil {
		t.Fatalf("the second sync failed: %v", err)
	}
	if !second.FastForward {
		t.Error("a peer that moved forward was reported as diverged")
	}
	if second.Fetched >= first.Fetched {
		t.Errorf("the second sync fetched %d of %d objects. Content already "+
			"here is already correct, and re-fetching it is the cost this "+
			"whole design exists to avoid", second.Fetched, first.Fetched)
	}
	if second.Present == 0 {
		t.Error("nothing was recognised as already present")
	}
}

// The budget stops a peer that is enormous rather than wrong.
func TestAPullIsBounded(t *testing.T) {
	pages := map[string]any{}
	for i := 'a'; i <= 'z'; i++ {
		pages[string(i)] = map[string]any{"title": string(i), "body": "x"}
	}
	remote, _ := peerStore(t, pages)
	local := emptyStore(t)

	_, err := Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{MaxObjects: 3})
	if err == nil {
		t.Fatal("an unbounded pull succeeded")
	}
	if !strings.Contains(err.Error(), "agreed to take") {
		t.Errorf("the refusal does not say it was a limit: %v", err)
	}

	_, err = Pull(context.Background(), local, &storeSource{s: remote},
		"origin", site.RefDraft, Limits{MaxBytes: 40})
	if err == nil {
		t.Fatal("a pull ignored the byte limit")
	}
}

// A peer's name cannot become a ref somewhere else.
func TestAPeerNameCannotEscapeItsRefNamespace(t *testing.T) {
	for _, name := range []string{
		"", "../live", "live/../..", "a/b", "peer name", strings.Repeat("x", 100),
	} {
		if err := ValidPeerName(name); err == nil {
			t.Errorf("%q was accepted as a peer name", name)
		}
	}
	if err := ValidPeerName("peer-origin"); err == nil {
		t.Error("a peer called \"peer-origin\" was accepted, and its ref is " +
			"indistinguishable from peer \"origin\"'s")
	}
	for _, name := range []string{"origin", "edge-1", "a_b", "EU"} {
		if err := ValidPeerName(name); err != nil {
			t.Errorf("%q was refused: %v", name, err)
		}
	}
	// And the quarantine ref keeps a peer out of the site's namespace even
	// when it is called something deliberately confusing.
	if QuarantineRef("live") == site.RefLive {
		t.Error("a peer called \"live\" writes to the live ref")
	}
	if QuarantineRef("draft") == site.RefDraft {
		t.Error("a peer called \"draft\" writes to the draft")
	}
}

// A peer answering with something that is not an object id is refused before
// anything is fetched.
func TestARefThatIsNotAnObjectIDIsRefused(t *testing.T) {
	local := emptyStore(t)
	src := &fixedRef{head: "not-an-id"}
	if _, err := Pull(context.Background(), local, src, "origin",
		site.RefDraft, Limits{}); err == nil {
		t.Fatal("a peer answered with rubbish and the pull continued")
	}
	if len(src.asked) != 0 {
		t.Error("objects were requested before the head was checked")
	}
}

type fixedRef struct {
	head  string
	asked []string
}

func (f *fixedRef) Ref(context.Context, string) (string, error) { return f.head, nil }
func (f *fixedRef) Object(_ context.Context, oid string) (string, []byte, error) {
	f.asked = append(f.asked, oid)
	return "", nil, nil
}
