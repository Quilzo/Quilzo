// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package outpost is the public instance: a second Quilzo process, on a
// host of its own, that serves an organisation's public faces and holds
// nothing else.
//
// # Why a second process
//
// The first question an application security team asks of a public page is
// what a bug in its handler reaches. Served by the instance that holds the
// record, the answer is everything: the register, the admin, the keys, the
// credentials of every connector. Served from here, it is what was
// published, which was public already. So the internal instance never faces
// the internet, and this one holds no register, no admin, no tokens, no
// vault and no secret of any kind: its configuration is one public key, and
// its content is what it was sent.
//
// # One way, signed
//
// Content arrives one way: the internal instance sends it, as a
// marking/transfer manifest signed with its head keys, over HTTP to the
// intake or carried as a directory, and this instance takes a transfer only
// when it is signed by the one key it was pinned to (Init). It never asks
// the internal instance for anything, holds no address of it, and opens no
// connection off its host at all (cmd/quilzo runs it offline). A transfer
// carries the projection and nothing else: the attestations (internal/
// attest), the head feed and security.txt, each from a closed list of
// names, each parsed and checked here before any of it is served, and none
// of it markup: the page is drawn by this program's own code from typed
// data, so a transfer cannot put a script on the public page even when it
// is signed. replica's rule holds here too: a peer is trusted to answer and
// for nothing else, so what arrives is bounded in files and bytes before it
// is read, and a transfer older than the one served is refused, so a
// replayed one cannot put back what was withdrawn. Nor is the head feed
// taken back: a newer feed may add heads, and may not drop below or rewrite
// a head already published here (extends).
package outpost

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/attest"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/marking"
	"github.com/quilzo/quilzo/internal/replica"
)

// The files of an instance and of a projection.
const (
	// ConfigFile is the instance's configuration: the pinned key.
	ConfigFile = "instance.json"
	// CurrentFile names the projection being served.
	CurrentFile = "current"
	// AttestationsFile, FeedFile and SecurityTxtFile are the projection:
	// the only names a transfer may carry.
	AttestationsFile = "attestations.json"
	FeedFile         = "heads.json"
	SecurityTxtFile  = "security.txt"
)

// Projection is every name a transfer may carry.
var Projection = []string{AttestationsFile, FeedFile, SecurityTxtFile}

// MaxEnvelope bounds one transfer: what it carries is a page of facts and a
// feed of heads, and a sender that offers more is not this instance's
// internal instance.
const MaxEnvelope = 1 << 20

// MaxHeads bounds the head feed.
const MaxHeads = 1000

// limits are replica's bounds on what one peer may make this store accept,
// sized for a projection rather than a site.
func limits() replica.Limits {
	return replica.Limits{MaxObjects: len(Projection) + 2, MaxBytes: MaxEnvelope}
}

// Pinned is the public half of the internal instance's head keys, as its
// head.pub.json publishes them.
type Pinned struct {
	KeyID   string `json:"key_id"`
	Ed25519 string `json:"ed25519"`
	MLDSA   string `json:"mldsa"`
	Note    string `json:"note,omitempty"`
}

func (p Pinned) verifier() (*audit.HeadVerifier, error) {
	ed, err := base64.StdEncoding.DecodeString(p.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("the pinned Ed25519 key is not base64: %w", err)
	}
	ml, err := base64.StdEncoding.DecodeString(p.MLDSA)
	if err != nil {
		return nil, fmt.Errorf("the pinned ML-DSA key is not base64: %w", err)
	}
	v, err := audit.NewHeadVerifier(ed, ml)
	if err != nil {
		return nil, fmt.Errorf("the pinned key is not a key: %w", err)
	}
	if p.KeyID != v.KeyID() {
		return nil, fmt.Errorf("the pinned key says it is %s and it is %s", p.KeyID, v.KeyID())
	}
	return v, nil
}

// Config is what an instance is, written once by Init.
type Config struct {
	Format  int       `json:"format"`
	Profile string    `json:"profile"`
	Pinned  Pinned    `json:"pinned"`
	Created time.Time `json:"created"`
}

// Init makes a public instance in dir, pinned to the key published in
// pinned (the internal instance's head.pub.json, copied here).
func Init(dir string, pinned []byte, now time.Time) error {
	var p Pinned
	if err := json.Unmarshal(pinned, &p); err != nil {
		return fmt.Errorf("the key to pin is not a published key file (head.pub.json): %w", err)
	}
	if _, err := p.verifier(); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, ConfigFile)); err == nil {
		return fmt.Errorf("%s is a public instance already. Pinning another key is a decision about "+
			"whom it believes: remove %s by hand to make it", dir, ConfigFile)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(Config{Format: 1, Profile: "public", Pinned: p, Created: now.UTC()}, "", "  ")
	if err != nil {
		return err
	}
	// Readable by anybody: it holds a public key and nothing else.
	return atomicfile.Write(filepath.Join(dir, ConfigFile), append(body, '\n'), 0o644)
}

// IsInstance reports whether dir holds a public instance.
func IsInstance(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ConfigFile))
	return err == nil
}

// Instance is a public instance, serving what it was last sent.
type Instance struct {
	dir    string
	cfg    Config
	pinned *audit.HeadVerifier
	// Now is the clock the page's status words are worked out on.
	Now func() time.Time
	// Intake takes transfers posted over HTTP. Off, the instance takes
	// only transfers carried to it as directories (Import).
	Intake bool

	mu      sync.Mutex // one import at a time
	busy    atomic.Bool
	serving sync.RWMutex
	cur     *served
	problem string
}

// served is a projection, checked.
type served struct {
	transfer *marking.Transfer
	made     time.Time
	file     *attest.File
	feed     *HeadFeed
	raw      map[string][]byte
}

// Open is the instance in dir, serving the projection it last took, checked
// again: a projection changed on disk since it was taken is not served.
func Open(dir string) (*Instance, error) {
	body, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	if err != nil {
		return nil, fmt.Errorf("%s is not a public instance (quilzo init --profile public --pin FILE makes one): %w", dir, err)
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s does not parse: %w", ConfigFile, err)
	}
	if cfg.Format != 1 || cfg.Profile != "public" {
		return nil, fmt.Errorf("%s is not a public instance's configuration", ConfigFile)
	}
	v, err := cfg.Pinned.verifier()
	if err != nil {
		return nil, err
	}
	in := &Instance{dir: dir, cfg: cfg, pinned: v, Now: time.Now, Intake: true}
	if name, err := os.ReadFile(filepath.Join(dir, CurrentFile)); err == nil {
		proj := filepath.Join(dir, "projections", filepath.Base(strings.TrimSpace(string(name))))
		s, err := in.check(proj)
		if err != nil {
			in.problem = "what was last taken is not served, because it no longer checks: " + err.Error()
		} else {
			in.cur = s
		}
	}
	return in, nil
}

// Dir is the instance's directory.
func (in *Instance) Dir() string { return in.dir }

// KeyID is the key the instance is pinned to.
func (in *Instance) KeyID() string { return in.cfg.Pinned.KeyID }

// Refused is a transfer the instance will not take: unsigned, signed by
// another key, carrying something it may not, or older than what is
// served. Distinguished so the intake can answer 403 and not 500.
type Refused struct{ Err error }

func (r Refused) Error() string { return r.Err.Error() }
func (r Refused) Unwrap() error { return r.Err }

func refused(format string, a ...any) error { return Refused{fmt.Errorf(format, a...)} }

// Receipt is what an import took.
type Receipt struct {
	Created  string   `json:"created"`
	Approved string   `json:"approved_by"`
	Carried  string   `json:"carried_by"`
	Reason   string   `json:"reason"`
	Files    []string `json:"files"`
	Bytes    int64    `json:"bytes"`
	KeyID    string   `json:"key_id"`
	Served   string   `json:"served"`
	// Taken is when this instance took it, by its own clock.
	Taken time.Time `json:"taken,omitzero"`
}

// Import takes a transfer carried to the instance as a directory, and
// serves it from the next request.
func (in *Instance) Import(src string, now time.Time) (Receipt, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	s, err := in.check(src)
	if err != nil {
		return Receipt{}, err
	}
	in.serving.RLock()
	cur := in.cur
	in.serving.RUnlock()
	if cur != nil && !s.made.After(cur.made) {
		return Receipt{}, refused("this transfer was made %s, which is not newer than the one served (%s): "+
			"an older transfer is refused, so a replayed one cannot put back what was withdrawn",
			s.transfer.Created, cur.transfer.Created)
	}
	if err := s.extends(cur); err != nil {
		return Receipt{}, err
	}
	name := s.made.UTC().Format("20060102T150405.000000000Z")
	proj := filepath.Join(in.dir, "projections", name)
	if err := os.MkdirAll(proj, 0o755); err != nil {
		return Receipt{}, err
	}
	for _, f := range append(slices.Clone(Projection), marking.TransferName, marking.TransferSigName) {
		body, err := os.ReadFile(filepath.Join(src, f))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Receipt{}, err
		}
		if err := os.WriteFile(filepath.Join(proj, f), body, 0o644); err != nil {
			return Receipt{}, err
		}
	}
	if err := atomicfile.Write(filepath.Join(in.dir, CurrentFile), []byte(name+"\n"), 0o644); err != nil {
		return Receipt{}, err
	}
	in.serving.Lock()
	in.cur, in.problem = s, ""
	in.serving.Unlock()
	in.prune(name)
	var files []string
	for f := range s.transfer.Files {
		files = append(files, f)
	}
	sort.Strings(files)
	return Receipt{Created: s.transfer.Created, Approved: s.transfer.Approved, Carried: s.transfer.Carried,
		Reason: s.transfer.Reason, Files: files, Bytes: s.transfer.Bytes, KeyID: in.KeyID(), Served: name,
		Taken: now.UTC()}, nil
}

// extends refuses a head feed that takes back what the one served
// published.
//
// The feed is publication: whoever fetched it holds heads the record has to
// go on matching, and a feed that a later transfer could rewrite would show
// the next reader a history nobody can check against the first. So a newer
// feed may add heads and let the oldest go (the internal instance keeps the
// last MaxHeads), and may not commit to fewer entries than the newest head
// served, publish a size already published under another root, or carry no
// feed at all. A signed transfer that does is the internal instance's own
// record gone back, restored from an old backup or rewritten, and that is
// exactly what a published head is there to show.
func (s *served) extends(cur *served) error {
	if cur == nil || cur.feed == nil || len(cur.feed.Heads) == 0 {
		return nil
	}
	const back = "; the internal instance's record has gone back on a head already published here, " +
		"and a head feed is kept so that this shows. If that is meant, it is said on this host, by " +
		"removing the instance's current file so that it starts empty, and not by a transfer"
	if s.feed == nil || len(s.feed.Heads) == 0 {
		return refused("this transfer carries no head feed, and would withdraw the heads published here%s", back)
	}
	was, now := cur.feed.Heads[len(cur.feed.Heads)-1], s.feed.Heads[len(s.feed.Heads)-1]
	if now.Size < was.Size {
		return refused("the newest head in this transfer commits to %d entries, and the newest published "+
			"here to %d%s", now.Size, was.Size, back)
	}
	published := map[int]string{}
	for _, h := range cur.feed.Heads {
		published[h.Size] = h.Root
	}
	for _, h := range s.feed.Heads {
		if root, ok := published[h.Size]; ok && root != h.Root {
			return refused("this transfer's head of %d entries has the root %s, and the one published here "+
				"has %s%s", h.Size, h.Root, root, back)
		}
	}
	return nil
}

// prune keeps the projection served and the two before it, so a person
// looking into a complaint can see what was served yesterday.
func (in *Instance) prune(keep string) {
	entries, err := os.ReadDir(filepath.Join(in.dir, "projections"))
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && e.Name() != keep {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > 2 {
		_ = os.RemoveAll(filepath.Join(in.dir, "projections", names[0]))
		names = names[1:]
	}
}

// check verifies a transfer in dir and parses what it carries, without
// serving it.
func (in *Instance) check(dir string) (*served, error) {
	// Bounded before anything is read: a directory of a thousand files is
	// refused by counting, not by verifying each.
	lim := limits()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	// Named first, from the listing alone: a transfer carrying anything but
	// the projection is refused for what it carries, before it is counted.
	for _, e := range entries {
		if n := e.Name(); !slices.Contains(Projection, n) && n != marking.TransferName && n != marking.TransferSigName {
			return nil, refused("the transfer carries %s, and a public instance takes %s and nothing else",
				n, strings.Join(Projection, ", "))
		}
	}
	if len(entries) > lim.MaxObjects {
		return nil, refused("the transfer holds %d files, and a projection is at most %d", len(entries), lim.MaxObjects)
	}
	var total int64
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, refused("%s is not a plain file, and a transfer carries plain files only", e.Name())
		}
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		total += fi.Size()
	}
	if total > int64(lim.MaxBytes) {
		return nil, refused("the transfer is %d bytes, and a projection is at most %d", total, lim.MaxBytes)
	}
	t, problems, err := marking.VerifySignedTransfer(dir, in.pinned)
	if err != nil {
		return nil, Refused{err}
	}
	if len(problems) > 0 {
		return nil, refused("what arrived is not what left:\n  %s", strings.Join(problems, "\n  "))
	}
	for name := range t.Files {
		if !slices.Contains(Projection, name) {
			return nil, refused("the transfer carries %s, and a public instance takes %s and nothing else",
				name, strings.Join(Projection, ", "))
		}
	}
	made, err := time.Parse(time.RFC3339Nano, t.Created)
	if err != nil {
		return nil, refused("the transfer's time %q is not a time", t.Created)
	}
	s := &served{transfer: t, made: made, raw: map[string][]byte{}}
	for name := range t.Files {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		s.raw[name] = body
	}
	att, ok := s.raw[AttestationsFile]
	if !ok {
		return nil, refused("the transfer carries no %s, which is what the page is drawn from", AttestationsFile)
	}
	// Checked as of when the transfer was made, which is when the internal
	// instance checked it too: this host's clock is not the one the dates
	// were written against, and a report issued this morning is not one
	// from the future because the two clocks differ by an hour.
	if s.file, err = attest.Parse(att, made); err != nil {
		return nil, Refused{err}
	}
	if body, ok := s.raw[FeedFile]; ok {
		if s.feed, err = ParseFeed(body, in.pinned); err != nil {
			return nil, Refused{err}
		}
	}
	if body, ok := s.raw[SecurityTxtFile]; ok {
		if err := checkSecurityTxt(body); err != nil {
			return nil, Refused{err}
		}
	}
	return s, nil
}

// checkSecurityTxt holds security.txt to RFC 9116's shape: fields and
// comments, a contact and an expiry, plain text.
func checkSecurityTxt(body []byte) error {
	if len(body) > 8<<10 {
		return errors.New("security.txt is larger than 8 KiB")
	}
	if !utf8.Valid(body) {
		return errors.New("security.txt is not UTF-8 text")
	}
	has := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		for _, r := range line {
			if unicode.IsControl(r) && r != '\t' {
				return errors.New("security.txt holds a control character")
			}
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		field, _, ok := strings.Cut(line, ": ")
		if !ok || field == "" || strings.ContainsAny(field, " \t") {
			return fmt.Errorf("security.txt has a line that is neither a field nor a comment: %q", line)
		}
		has[strings.ToLower(field)] = true
	}
	if !has["contact"] || !has["expires"] {
		return errors.New("security.txt names no Contact or no Expires, which RFC 9116 requires")
	}
	return nil
}

// HeadFeed is the heads of the internal instance's record published so far:
// publication, not a co-signature, and a witness only for whoever fetches
// and keeps it.
type HeadFeed struct {
	Format int                `json:"format"`
	KeyID  string             `json:"key_id"`
	Heads  []audit.SignedHead `json:"heads"`
}

// ParseFeed reads a head feed and checks every head against the pinned key,
// in order: a log only grows, so neither its size nor its time goes back.
func ParseFeed(body []byte, pinned *audit.HeadVerifier) (*HeadFeed, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var f HeadFeed
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("the head feed does not parse: %w", err)
	}
	if f.Format != 1 {
		return nil, fmt.Errorf("the head feed is format %d, and this reads format 1", f.Format)
	}
	if f.KeyID != pinned.KeyID() {
		return nil, fmt.Errorf("the head feed is signed by %s, and the pinned key is %s", f.KeyID, pinned.KeyID())
	}
	if len(f.Heads) > MaxHeads {
		return nil, fmt.Errorf("the head feed holds %d heads, and at most %d are kept", len(f.Heads), MaxHeads)
	}
	var last time.Time
	for i, h := range f.Heads {
		if err := pinned.Verify(h); err != nil {
			return nil, fmt.Errorf("head %d of the feed is not signed by the pinned key: %w", i+1, err)
		}
		at, err := time.Parse(time.RFC3339, h.At)
		if err != nil {
			return nil, fmt.Errorf("head %d of the feed was taken at %q, which is not a time", i+1, h.At)
		}
		if i > 0 && (h.Size < f.Heads[i-1].Size || at.Before(last)) {
			return nil, fmt.Errorf("head %d of the feed is smaller or older than the one before it, and a log only grows", i+1)
		}
		// Two heads of one size are one head signed twice, or the record
		// forked: the second is refused, since a reader cannot tell which.
		if i > 0 && h.Size == f.Heads[i-1].Size && h.Root != f.Heads[i-1].Root {
			return nil, fmt.Errorf("heads %d and %d of the feed both commit to %d entries, with different roots: "+
				"the record forked", i, i+1, h.Size)
		}
		last = at
	}
	return &f, nil
}

// envelope is a transfer as it travels over HTTP: the manifest's bytes, its
// signature's and each file's, exactly as they were written.
type envelope struct {
	Format    int               `json:"format"`
	Transfer  string            `json:"transfer"`
	Signature string            `json:"signature,omitempty"`
	Files     map[string]string `json:"files"`
}

// Pack is a transfer directory as one envelope, for the internal instance
// to post. Only the projection's names are packed.
func Pack(dir string) ([]byte, error) {
	man, err := os.ReadFile(filepath.Join(dir, marking.TransferName))
	if err != nil {
		return nil, fmt.Errorf("%s carries no transfer manifest: %w", dir, err)
	}
	env := envelope{Format: 1, Transfer: base64.StdEncoding.EncodeToString(man), Files: map[string]string{}}
	if sig, err := os.ReadFile(filepath.Join(dir, marking.TransferSigName)); err == nil {
		env.Signature = base64.StdEncoding.EncodeToString(sig)
	}
	for _, name := range Projection {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		env.Files[name] = base64.StdEncoding.EncodeToString(body)
	}
	return json.Marshal(env)
}

// ErrTooLarge is an envelope over MaxEnvelope.
var ErrTooLarge = fmt.Errorf("a transfer is at most %d bytes", MaxEnvelope)

// ImportEnvelope takes a transfer posted to the intake.
func (in *Instance) ImportEnvelope(r io.Reader, now time.Time) (Receipt, error) {
	body, err := io.ReadAll(io.LimitReader(r, MaxEnvelope+1))
	if err != nil {
		return Receipt{}, err
	}
	if len(body) > MaxEnvelope {
		return Receipt{}, ErrTooLarge
	}
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return Receipt{}, fmt.Errorf("the transfer does not parse: %w", err)
	}
	if env.Format != 1 {
		return Receipt{}, fmt.Errorf("the transfer is format %d, and this takes format 1", env.Format)
	}
	// Every name is checked before anything is written, so a name that is
	// a path never reaches the disk.
	for name := range env.Files {
		if !slices.Contains(Projection, name) {
			return Receipt{}, refused("the transfer carries %q, and a public instance takes %s and nothing else",
				name, strings.Join(Projection, ", "))
		}
	}
	tmp, err := os.MkdirTemp(in.dir, "incoming-")
	if err != nil {
		return Receipt{}, err
	}
	defer os.RemoveAll(tmp)
	write := func(name, b64 string) error {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("%s in the transfer is not base64: %w", name, err)
		}
		return os.WriteFile(filepath.Join(tmp, name), raw, 0o600)
	}
	if err := write(marking.TransferName, env.Transfer); err != nil {
		return Receipt{}, err
	}
	if env.Signature != "" {
		if err := write(marking.TransferSigName, env.Signature); err != nil {
			return Receipt{}, err
		}
	}
	for name, b64 := range env.Files {
		if err := write(name, b64); err != nil {
			return Receipt{}, err
		}
	}
	return in.Import(tmp, now)
}

// Status is what the instance serves, for `quilzo public status` on its host.
type Status struct {
	KeyID   string   `json:"pinned_key"`
	Served  *Receipt `json:"served,omitempty"`
	Problem string   `json:"problem,omitempty"`
}

// Status says what is served and what is pinned.
func (in *Instance) Status() Status {
	in.serving.RLock()
	defer in.serving.RUnlock()
	st := Status{KeyID: in.KeyID(), Problem: in.problem}
	if c := in.cur; c != nil {
		var files []string
		for f := range c.transfer.Files {
			files = append(files, f)
		}
		sort.Strings(files)
		st.Served = &Receipt{Created: c.transfer.Created, Approved: c.transfer.Approved, Carried: c.transfer.Carried,
			Reason: c.transfer.Reason, Files: files, Bytes: c.transfer.Bytes, KeyID: in.KeyID()}
	}
	return st
}
