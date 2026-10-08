// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package member keeps the people who have an account on a published site.
//
// # Why this exists
//
// A site built with Quilzo could publish to anybody and be edited by its
// staff, and nothing in between: no visitor could have an account. That is
// the first thing every application needs — a community, a course, a video
// site, a team's own chat — and the thing a content system is most often
// replaced over.
//
// # Why it is not in the content store
//
// For the reason form submissions are not. A member is personal data that
// its owner may ask to have erased, and an append-only store addressed by
// hash cannot erase anything without breaking every hash above it. So each
// member is a plain file, deletable on its own, and deleting an account
// deletes it: the record, its passkeys, its recovery codes and its sessions.
//
// # What a member is, and is not
//
// A random identifier, a display name the member chose, the passkeys that
// sign them in, and the hashes of their unused recovery codes. No email
// address, no password, nothing else. Every field a site keeps is a field it
// has to protect, disclose and erase, so the account holds what signing in
// needs and nothing more.
//
// Passkeys rather than passwords: a passkey cannot be phished onto another
// site, cannot be reused from a breach somewhere else, and leaves nothing
// here worth stealing — the public key is public. Recovery codes rather than
// email: they need no mail server, and a lost phone is not a locked account
// for somebody who kept them.
//
// # Files
//
//	members/ID.json            one member
//	members/keys/HASH          a credential id's hash, holding the member id
//	members/recovery/HASH      an unused recovery code's hash, likewise
//	members/sessions/HASH      a session token's hash, holding the session
//	members/invites/HASH       an unused invitation code's hash
//
// Only hashes of secrets are stored: a copy of this directory signs nobody
// in. Files are written with atomicfile and mode 0600.
package member

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/webauthn"
)

// Member is one account.
type Member struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	// Disabled members cannot sign in, and their sessions end. Set by the
	// site's staff; a member deletes their own account instead.
	Disabled bool `json:"disabled,omitempty"`
	// Passkeys sign the member in. At least one, always.
	Passkeys []webauthn.Credential `json:"passkeys"`
	// Recovery counts the unused recovery codes; the codes themselves are
	// kept only as hashes, under recovery/.
	Recovery int `json:"recovery"`
}

// Session is one signed-in browser.
type Session struct {
	Member  string    `json:"member"`
	Created time.Time `json:"created"`
	Seen    time.Time `json:"seen"`
}

// Invite is an unused invitation, for a site whose sign-up is by invitation.
type Invite struct {
	Hash    string    `json:"hash"`
	By      string    `json:"by"`
	Note    string    `json:"note,omitempty"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// Limits on what a session and an invitation are good for.
const (
	// SessionIdle ends a session nobody has used for this long.
	SessionIdle = 14 * 24 * time.Hour
	// SessionMax ends any session this long after it began, used or not.
	SessionMax = 90 * 24 * time.Hour
	// InviteLife is how long an invitation code may wait to be used.
	InviteLife = 14 * 24 * time.Hour
	// RecoveryCodes is how many codes a new account is given.
	RecoveryCodes = 8
	// MaxPasskeys bounds one account's passkeys.
	MaxPasskeys = 10
	// MaxName is the longest display name, in characters.
	MaxName = 40
)

// Errors a caller distinguishes.
var (
	ErrNotFound = errors.New("no such member")
	ErrDisabled = errors.New("this account is disabled")
	ErrNoCode   = errors.New("that code is not valid")
)

// Store is a site's members, in a directory.
type Store struct {
	Dir string
	// Now is the clock, for tests. Nil means time.Now.
	Now func() time.Time

	mu sync.Mutex
}

// Open returns the store under dir, creating its directories.
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"", "keys", "recovery", "sessions", "invites"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

var reID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidName reports why a display name cannot be used, or nil.
//
// Printable, trimmed, and short. Not unique: two people may be called the
// same thing, and refusing the second leaks that the first exists.
func ValidName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("choose a name to be shown as")
	}
	if utf8.RuneCountInString(name) > MaxName {
		return fmt.Errorf("a name is at most %d characters", MaxName)
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("a name is letters, numbers, spaces and punctuation")
		}
	}
	return nil
}

// Create makes an account with its first passkey, and returns the recovery
// codes, which are shown once and never again.
func (s *Store) Create(name string, cred webauthn.Credential) (Member, []string, error) {
	name = strings.TrimSpace(name)
	if err := ValidName(name); err != nil {
		return Member{}, nil, err
	}
	if len(cred.ID) == 0 || len(cred.PublicKey) == 0 {
		return Member{}, nil, fmt.Errorf("an account needs a passkey")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.readIndex("keys", hashOf(cred.ID)); err == nil {
		return Member{}, nil, fmt.Errorf("that passkey already belongs to an account")
	}
	id, err := randomHex(16)
	if err != nil {
		return Member{}, nil, err
	}
	now := s.now()
	cred.Principal = id
	cred.CreatedAt = now.Unix()
	if cred.Label == "" {
		cred.Label = "First passkey"
	}
	m := Member{ID: id, Name: name, Created: now, LastSeen: now,
		Passkeys: []webauthn.Credential{cred}}
	codes, err := s.newRecovery(id, RecoveryCodes)
	if err != nil {
		return Member{}, nil, err
	}
	m.Recovery = len(codes)
	if err := s.writeIndex("keys", hashOf(cred.ID), id); err != nil {
		return Member{}, nil, err
	}
	if err := s.write(m); err != nil {
		return Member{}, nil, err
	}
	return m, codes, nil
}

// Get reads one member.
func (s *Store) Get(id string) (Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(id)
}

// List is every member, newest first.
func (s *Store) List() ([]Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []Member
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !reID.MatchString(id) {
			continue
		}
		if m, err := s.read(id); err == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// ByCredential finds the member a passkey belongs to.
func (s *Store) ByCredential(credID []byte) (Member, webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := s.readIndex("keys", hashOf(credID))
	if err != nil {
		return Member{}, webauthn.Credential{}, ErrNotFound
	}
	m, err := s.read(id)
	if err != nil {
		return Member{}, webauthn.Credential{}, ErrNotFound
	}
	for _, c := range m.Passkeys {
		if string(c.ID) == string(credID) {
			return m, c, nil
		}
	}
	return Member{}, webauthn.Credential{}, ErrNotFound
}

// Used records a passkey's use: its new counter and when.
func (s *Store) Used(id string, credID []byte, count uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return err
	}
	now := s.now()
	for i := range m.Passkeys {
		if string(m.Passkeys[i].ID) == string(credID) {
			m.Passkeys[i].SignCount = count
			m.Passkeys[i].LastUsed = now.Unix()
		}
	}
	m.LastSeen = now
	return s.write(m)
}

// AddPasskey gives a member another passkey.
func (s *Store) AddPasskey(id string, cred webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return err
	}
	if len(m.Passkeys) >= MaxPasskeys {
		return fmt.Errorf("an account has at most %d passkeys; remove one first", MaxPasskeys)
	}
	if _, err := s.readIndex("keys", hashOf(cred.ID)); err == nil {
		return fmt.Errorf("that passkey already belongs to an account")
	}
	cred.Principal = id
	cred.CreatedAt = s.now().Unix()
	if cred.Label == "" {
		cred.Label = fmt.Sprintf("Passkey %d", len(m.Passkeys)+1)
	}
	if err := s.writeIndex("keys", hashOf(cred.ID), id); err != nil {
		return err
	}
	m.Passkeys = append(m.Passkeys, cred)
	return s.write(m)
}

// RemovePasskey takes one away. The last one cannot go: an account with no
// passkey is one nobody can sign in to, which is what deleting it is for.
func (s *Store) RemovePasskey(id string, credID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return err
	}
	if len(m.Passkeys) <= 1 {
		return fmt.Errorf("this is the account's only passkey; add another first, or delete the account")
	}
	kept := m.Passkeys[:0]
	found := false
	for _, c := range m.Passkeys {
		if string(c.ID) == string(credID) {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		return ErrNotFound
	}
	m.Passkeys = kept
	_ = os.Remove(s.indexPath("keys", hashOf(credID)))
	return s.write(m)
}

// NewRecoveryCodes replaces a member's recovery codes with fresh ones.
func (s *Store) NewRecoveryCodes(id string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return nil, err
	}
	s.dropIndexFor("recovery", id)
	codes, err := s.newRecovery(id, RecoveryCodes)
	if err != nil {
		return nil, err
	}
	m.Recovery = len(codes)
	return codes, s.write(m)
}

// Recover uses a recovery code, once, and returns whose it was.
func (s *Store) Recover(code string) (Member, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := hashOf([]byte(normaliseCode(code)))
	id, err := s.readIndex("recovery", h)
	if err != nil {
		return Member{}, ErrNoCode
	}
	// Spent before anything else can fail: a code that worked once must
	// never work twice, whatever happens next.
	if err := os.Remove(s.indexPath("recovery", h)); err != nil {
		return Member{}, ErrNoCode
	}
	m, err := s.read(id)
	if err != nil {
		return Member{}, ErrNoCode
	}
	if m.Disabled {
		return Member{}, ErrDisabled
	}
	if m.Recovery > 0 {
		m.Recovery--
	}
	m.LastSeen = s.now()
	return m, s.write(m)
}

// SetDisabled disables or enables an account. Disabling ends its sessions.
func (s *Store) SetDisabled(id string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return err
	}
	m.Disabled = disabled
	if disabled {
		s.dropSessionsFor(id)
	}
	return s.write(m)
}

// Rename changes a member's display name.
func (s *Store) Rename(id, name string) error {
	name = strings.TrimSpace(name)
	if err := ValidName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return err
	}
	m.Name = name
	return s.write(m)
}

// Delete erases an account and everything that pointed at it.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return err
	}
	for _, c := range m.Passkeys {
		_ = os.Remove(s.indexPath("keys", hashOf(c.ID)))
	}
	s.dropIndexFor("recovery", id)
	s.dropSessionsFor(id)
	return os.Remove(filepath.Join(s.Dir, id+".json"))
}

// -- sessions ---------------------------------------------------------------

// StartSession signs a member in and returns the token for the cookie. Only
// its hash is kept.
func (s *Store) StartSession(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.read(id)
	if err != nil {
		return "", err
	}
	if m.Disabled {
		return "", ErrDisabled
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	now := s.now()
	b, _ := json.Marshal(Session{Member: id, Created: now, Seen: now})
	if err := atomicfile.Write(s.sessionPath(token), b, 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// SessionMember is the member a session token signs in, if it still does.
//
// A session past either limit is removed as it is found. A use more than a
// minute after the last refreshes it, so an active session stays alive and
// an idle one does not, without a write on every request.
func (s *Store) SessionMember(token string) (Member, error) {
	if !reToken.MatchString(token) {
		return Member{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.sessionPath(token)
	b, err := os.ReadFile(path)
	if err != nil {
		return Member{}, ErrNotFound
	}
	var sess Session
	if json.Unmarshal(b, &sess) != nil {
		return Member{}, ErrNotFound
	}
	now := s.now()
	if now.Sub(sess.Seen) > SessionIdle || now.Sub(sess.Created) > SessionMax {
		_ = os.Remove(path)
		return Member{}, ErrNotFound
	}
	m, err := s.read(sess.Member)
	if err != nil || m.Disabled {
		_ = os.Remove(path)
		return Member{}, ErrNotFound
	}
	if now.Sub(sess.Seen) > time.Minute {
		sess.Seen = now
		nb, _ := json.Marshal(sess)
		_ = atomicfile.Write(path, nb, 0o600)
	}
	return m, nil
}

// EndSession signs one browser out.
func (s *Store) EndSession(token string) {
	if !reToken.MatchString(token) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = os.Remove(s.sessionPath(token))
}

// EndSessions signs a member out everywhere.
func (s *Store) EndSessions(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropSessionsFor(id)
}

// Sessions counts a member's live sessions.
func (s *Store) Sessions(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	s.eachSession(func(_ string, sess Session) {
		if sess.Member == id {
			n++
		}
	})
	return n
}

// Sweep removes sessions past their limits and invitations past theirs.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.eachSession(func(path string, sess Session) {
		if now.Sub(sess.Seen) > SessionIdle || now.Sub(sess.Created) > SessionMax {
			_ = os.Remove(path)
		}
	})
	for _, inv := range s.invites() {
		if now.After(inv.Expires) {
			_ = os.Remove(filepath.Join(s.Dir, "invites", inv.Hash))
		}
	}
}

// -- invitations ------------------------------------------------------------

// NewInvite makes an invitation code, returned once; only its hash is kept.
func (s *Store) NewInvite(by, note string) (string, Invite, error) {
	code, err := newCode()
	if err != nil {
		return "", Invite{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	inv := Invite{Hash: hashOf([]byte(normaliseCode(code))), By: by,
		Note: strings.TrimSpace(note), Created: now, Expires: now.Add(InviteLife)}
	b, _ := json.Marshal(inv)
	if err := atomicfile.Write(filepath.Join(s.Dir, "invites", inv.Hash), b, 0o600); err != nil {
		return "", Invite{}, err
	}
	return code, inv, nil
}

// Invites is every unused invitation, oldest first.
func (s *Store) Invites() []Invite {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.invites()
}

// RevokeInvite withdraws an invitation by its hash, or a prefix of it.
func (s *Store) RevokeInvite(prefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var match []Invite
	for _, inv := range s.invites() {
		if prefix != "" && strings.HasPrefix(inv.Hash, prefix) {
			match = append(match, inv)
		}
	}
	if len(match) != 1 {
		return fmt.Errorf("%d invitations match %q; give more of it", len(match), prefix)
	}
	return os.Remove(filepath.Join(s.Dir, "invites", match[0].Hash))
}

// CheckInvite reports whether a code is a live invitation, without using it.
func (s *Store) CheckInvite(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.invite(code)
	return err
}

// UseInvite spends an invitation.
func (s *Store) UseInvite(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, err := s.invite(code)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.Dir, "invites", inv.Hash)); err != nil {
		return ErrNoCode
	}
	return nil
}

func (s *Store) invite(code string) (Invite, error) {
	h := hashOf([]byte(normaliseCode(code)))
	b, err := os.ReadFile(filepath.Join(s.Dir, "invites", h))
	if err != nil {
		return Invite{}, ErrNoCode
	}
	var inv Invite
	if json.Unmarshal(b, &inv) != nil || s.now().After(inv.Expires) {
		return Invite{}, ErrNoCode
	}
	return inv, nil
}

func (s *Store) invites() []Invite {
	entries, _ := os.ReadDir(filepath.Join(s.Dir, "invites"))
	var out []Invite
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(s.Dir, "invites", e.Name()))
		if err != nil {
			continue
		}
		var inv Invite
		if json.Unmarshal(b, &inv) == nil && inv.Hash == e.Name() {
			out = append(out, inv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// -- files ------------------------------------------------------------------

func (s *Store) read(id string) (Member, error) {
	if !reID.MatchString(id) {
		return Member{}, ErrNotFound
	}
	b, err := os.ReadFile(filepath.Join(s.Dir, id+".json"))
	if err != nil {
		return Member{}, ErrNotFound
	}
	var m Member
	if err := json.Unmarshal(b, &m); err != nil || m.ID != id {
		return Member{}, ErrNotFound
	}
	return m, nil
}

func (s *Store) write(m Member) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(s.Dir, m.ID+".json"), b, 0o600)
}

var reHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Store) indexPath(kind, hash string) string {
	return filepath.Join(s.Dir, kind, hash)
}

func (s *Store) readIndex(kind, hash string) (string, error) {
	if !reHash.MatchString(hash) {
		return "", ErrNotFound
	}
	b, err := os.ReadFile(s.indexPath(kind, hash))
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if !reID.MatchString(id) {
		return "", ErrNotFound
	}
	return id, nil
}

func (s *Store) writeIndex(kind, hash, id string) error {
	return atomicfile.Write(s.indexPath(kind, hash), []byte(id), 0o600)
}

func (s *Store) dropIndexFor(kind, id string) {
	entries, _ := os.ReadDir(filepath.Join(s.Dir, kind))
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(s.Dir, kind, e.Name()))
		if err == nil && strings.TrimSpace(string(b)) == id {
			_ = os.Remove(filepath.Join(s.Dir, kind, e.Name()))
		}
	}
}

func (s *Store) newRecovery(id string, n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		code, err := newCode()
		if err != nil {
			return nil, err
		}
		if err := s.writeIndex("recovery", hashOf([]byte(normaliseCode(code))), id); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

var reToken = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func (s *Store) sessionPath(token string) string {
	return filepath.Join(s.Dir, "sessions", hashOf([]byte(token)))
}

func (s *Store) eachSession(fn func(path string, sess Session)) {
	dir := filepath.Join(s.Dir, "sessions")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var sess Session
		if json.Unmarshal(b, &sess) == nil {
			fn(path, sess)
		}
	}
}

func (s *Store) dropSessionsFor(id string) {
	s.eachSession(func(path string, sess Session) {
		if sess.Member == id {
			_ = os.Remove(path)
		}
	})
}

// -- secrets ----------------------------------------------------------------

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// newCode is a recovery or invitation code: 80 random bits, in four groups
// of letters and digits a person can read back without confusing 0 and O.
func newCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	s := codeEncoding.EncodeToString(b)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16], nil
}

// Crockford's alphabet: no I, L, O or U.
var codeEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// normaliseCode forgives how a person types a code back: case, spaces,
// dashes, and the letters Crockford's alphabet reads as digits.
func normaliseCode(code string) string {
	code = strings.ToUpper(code)
	code = strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(code)
	return code
}
