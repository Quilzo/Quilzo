package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/replica"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Peers: other stores this one replicates from.
//
// # The credential is not in this file
//
// peers.json records where a peer is and what to read from it. The token lives
// in an environment variable, named per peer, exactly as the OIDC secret does.
// A configuration file gets committed, backed up, copied to a colleague and
// pasted into an issue, and a file that is safe to do all of that with is worth
// more than one that saves typing an export.
//
// # Adding a peer is not pulling from it
//
// Two commands, because they are two decisions. Somebody adds a peer once, and
// pulls from it repeatedly or on a schedule, and the second should not be able
// to surprise them by also having been the first.

const peerTokenPrefix = "QUILZO_PEER_"

// Peer is another store this one replicates from.
type Peer struct {
	Name string `json:"name"`
	// URL is the peer's origin. https, no path.
	URL string `json:"url"`
	// Ref is what to read from it. The peer's draft is deliberately allowed:
	// an editor working offline syncs a draft, and refusing it would leave
	// local-first sync able to move only published content.
	Ref string `json:"ref"`
	// TokenEnv names the environment variable holding the credential. Empty
	// means the default for this peer's name.
	TokenEnv string `json:"token_env,omitempty"`
}

// tokenEnv is where this peer's credential is read from.
func (p Peer) tokenEnv() string {
	if p.TokenEnv != "" {
		return p.TokenEnv
	}
	return peerTokenPrefix + strings.ToUpper(
		strings.ReplaceAll(p.Name, "-", "_")) + "_TOKEN"
}

type peerFile struct {
	Peers []Peer `json:"peers"`
}

func peersPath(root string) string { return filepath.Join(root, "peers.json") }

func loadPeers(root string) (*peerFile, error) {
	f := &peerFile{}
	return f, loadJSON(peersPath(root), f)
}

func cmdPeer(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return peerList(root)
	case "add":
		return peerAdd(root, args[1:])
	case "remove":
		return peerRemove(root, args[1:])
	case "pull":
		return peerPull(root, args[1:])
	case "adopt":
		return peerAdopt(root, args[1:])
	default:
		return fmt.Errorf("unknown peer command %q; try list, add, remove, "+
			"pull or adopt", args[0])
	}
}

func peerList(root string) error {
	f, err := loadPeers(root)
	if err != nil {
		return err
	}
	if len(f.Peers) == 0 {
		fmt.Printf("  %sno peers. `quilzo peer add NAME https://host --ref draft`%s\n",
			dim, reset)
		return nil
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	sort.Slice(f.Peers, func(i, j int) bool { return f.Peers[i].Name < f.Peers[j].Name })
	for _, p := range f.Peers {
		fmt.Printf("%s%s%s  %s %s%s%s\n", bold, p.Name, reset, p.URL, dim, p.Ref, reset)
		at := s.GetRef(replica.QuarantineRef(p.Name))
		if at == "" {
			fmt.Printf("  %snever pulled%s\n", dim, reset)
		} else {
			fmt.Printf("  at %s\n", shortCommit(at))
		}
		if os.Getenv(p.tokenEnv()) == "" {
			// Said now rather than at pull time. A peer whose credential is
			// not in the environment is one that will fail on the next
			// scheduled sync, and finding that out from a log is worse.
			fmt.Printf("  %sno credential: set %s%s\n", yellow, p.tokenEnv(), reset)
		}
	}
	return nil
}

func peerAdd(root string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf(
			"usage: quilzo peer add NAME https://host [--ref draft]")
	}
	name, url := args[0], args[1]
	ref := site.RefLive
	for i := 2; i < len(args); i++ {
		if args[i] == "--ref" && i+1 < len(args) {
			ref = args[i+1]
		}
		if v, ok := strings.CutPrefix(args[i], "--ref="); ok {
			ref = v
		}
	}
	if err := replica.ValidPeerName(name); err != nil {
		return err
	}
	// Validated now, so a typo fails here rather than partway through the
	// first pull.
	if _, err := replica.NewHTTPSource(url, "placeholder"); err != nil {
		return err
	}
	if strings.HasPrefix(ref, replica.PeerPrefix) {
		return fmt.Errorf(
			"%q is another peer's ref. Pair with that store directly rather "+
				"than reading its copy of a third one", ref)
	}

	f, err := loadPeers(root)
	if err != nil {
		return err
	}
	for _, p := range f.Peers {
		if p.Name == name {
			return fmt.Errorf("there is already a peer called %q", name)
		}
	}
	p := Peer{Name: name, URL: url, Ref: ref}
	f.Peers = append(f.Peers, p)
	if err := saveJSON(peersPath(root), f); err != nil {
		return err
	}

	fmt.Printf("added %s%s%s  %s %s%s%s\n", bold, name, reset, url, dim, ref, reset)
	fmt.Printf("  %sset the credential: export %s=…%s\n", dim, p.tokenEnv(), reset)
	fmt.Printf("  %s`quilzo peer pull %s` — it lands on %s and does not touch "+
		"this site%s\n", dim, name, replica.QuarantineRef(name), reset)
	return nil
}

func peerRemove(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo peer remove NAME")
	}
	name := args[0]
	f, err := loadPeers(root)
	if err != nil {
		return err
	}
	kept := f.Peers[:0]
	found := false
	for _, p := range f.Peers {
		if p.Name == name {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return fmt.Errorf("no peer called %q", name)
	}
	f.Peers = kept
	if err := saveJSON(peersPath(root), f); err != nil {
		return err
	}
	// The ref stays. Objects are immutable and addressed by their hashes, and
	// deleting the ref would drop the record of what was last received from a
	// peer somebody may be removing precisely because they are investigating
	// it.
	fmt.Printf("removed %s\n", name)
	fmt.Printf("  %s%s still points at what was last pulled%s\n",
		dim, replica.QuarantineRef(name), reset)
	return nil
}

func peerPull(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo peer pull NAME")
	}
	name := args[0]
	f, err := loadPeers(root)
	if err != nil {
		return err
	}
	var peer *Peer
	for i := range f.Peers {
		if f.Peers[i].Name == name {
			peer = &f.Peers[i]
		}
	}
	if peer == nil {
		return fmt.Errorf("no peer called %q; `quilzo peer list`", name)
	}
	token := strings.TrimSpace(os.Getenv(peer.tokenEnv()))
	if token == "" {
		return fmt.Errorf(
			"no credential for %s. Set %s — it is not in peers.json on "+
				"purpose, because that file gets committed", name, peer.tokenEnv())
	}
	src, err := replica.NewHTTPSource(peer.URL, token)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := replica.Pull(ctx, s, src, peer.Name, peer.Ref, replica.Limits{})
	if replica.IsDivergence(err) {
		// Not a failure. Two people editing the same site in two places is
		// what local-first means, and reporting it as an error code would put
		// it in a log rather than in front of somebody.
		fmt.Printf("%s%s%s and this store have diverged\n", bold, name, reset)
		fmt.Printf("  %s is at %s\n", name, shortCommit(res.Head))
		fmt.Printf("  here      %s\n", shortCommit(res.Diverged))
		fmt.Printf("  %s%d objects were fetched and nothing was moved. "+
			"Compare them and decide.%s\n", dim, res.Fetched, reset)
		return nil
	}
	if err != nil {
		return err
	}

	fmt.Printf("%s%s%s  %s\n", bold, name, reset, shortCommit(res.Head))
	fmt.Printf("  %d new, %d already here, %d bytes\n",
		res.Fetched, res.Present, res.Bytes)
	fmt.Printf("  %slanded on %s — this site is unchanged%s\n",
		dim, res.Ref, reset)
	if res.Fetched > 0 {
		fmt.Printf("  %s`quilzo peer adopt %s` to make it the draft%s\n",
			dim, name, reset)
	}
	record(root, resolveCaller(root, "").auditRecord(
		"peer.pull", "/", audit.Success, map[string]string{
			"peer": name, "head": shortCommit(res.Head),
			"fetched": fmt.Sprint(res.Fetched),
			"present": fmt.Sprint(res.Present)}))
	return nil
}

// peerAdopt makes what was pulled the local draft.
//
// The separate step is the point. A pull is a transfer and adoption is an
// editorial decision, and collapsing them would make anybody who can get a peer
// added — or who compromises one that already exists — able to change what this
// store is working on.
//
// It stops at the draft. Publishing is still publishing, with whatever review
// this install requires, because content arriving over a wire is not a reason
// to skip the step that content typed into a form cannot skip.
func peerAdopt(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo peer adopt NAME")
	}
	name := args[0]
	if err := replica.ValidPeerName(name); err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	head := s.GetRef(replica.QuarantineRef(name))
	if head == "" {
		return fmt.Errorf("nothing has been pulled from %q", name)
	}
	current := s.GetRef(site.RefDraft)
	if current == head {
		fmt.Printf("  %sthe draft is already %s%s\n", dim, shortCommit(head), reset)
		return nil
	}
	// Fast-forward only, checked here as well as in the pull. The pull checked
	// the peer's ref against the peer's ref; this checks it against the draft,
	// which is a different question and the one that decides whether adopting
	// discards somebody's work.
	if current != "" && !descendsFrom(s, head, current) {
		return fmt.Errorf(
			"the draft is at %s and %s is at %s, and neither descends from "+
				"the other. Adopting would discard what is here; compare them "+
				"first", shortCommit(current), name, shortCommit(head))
	}
	if err := s.SetRef(site.RefDraft, head); err != nil {
		return err
	}
	fmt.Printf("the draft is now %s, from %s\n", shortCommit(head), name)
	fmt.Printf("  %spublishing it is still publishing%s\n", dim, reset)
	record(root, resolveCaller(root, "").auditRecord(
		"peer.adopt", "/", audit.Success, map[string]string{
			"peer": name, "commit": shortCommit(head)}))
	return nil
}

// descendsFrom reports whether head has ancestor in its history.
func descendsFrom(s *store.Store, head, ancestor string) bool {
	seen := map[string]bool{}
	queue := []string{head}
	for depth := 0; len(queue) > 0 && depth < 10_000; depth++ {
		var next []string
		for _, cid := range queue {
			if seen[cid] {
				continue
			}
			seen[cid] = true
			if cid == ancestor {
				return true
			}
			c, err := s.GetCommit(cid)
			if err != nil {
				continue
			}
			next = append(next, c.Parents...)
		}
		queue = next
	}
	return false
}
