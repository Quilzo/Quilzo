// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package newsletter keeps a site's mailing list: the addresses that asked
// for its newsletter and confirmed it, and the ones that asked to stop.
//
// # Nothing is sent before the address says yes
//
// Signing up writes the address down and mails it one link. Until that
// link is followed, and a button on the page it opens is pressed, the
// address gets nothing else, and a week later it is forgotten. A button
// rather than the link alone, because mail filters open links to look at
// them, and a filter is not a person saying yes. This is double opt-in, and
// it is the only way an address joins from the web.
//
// # What the public site may do with it
//
// Sign an address up, which writes it once; confirm it, which writes a
// marker; and let it leave, which removes it. It never reads an address
// back: none of the three needs to, so a flaw in the part of Quilzo facing
// the internet could add to the list or shorten it, and not hand it over.
// Reading the list, and sending to it, is the admin's and the command
// line's.
//
// # Ids and links that need nothing stored
//
// An address's id is a keyed hash of the address, so signing up twice
// finds the same record without searching, and the links in a mail are a
// keyed hash of the id, so checking one reads nothing either. The key is
// made once, kept at the store's root, and never written again.
//
// # Leaving is kept
//
// An address that leaves, or that the site's staff remove, is deleted, and
// its id is kept in left/: a keyed hash, not the address. That is what stops
// an old export imported again from writing it back. Asking again on the
// site, and confirming, is the one way back.
//
// # Files
//
//	newsletter.key                   at the store's root: the key, made once
//	newsletter/subscribers/ID.json   one address, written once
//	newsletter/confirmed/ID          it was confirmed, and when
//	newsletter/left/ID               it asked to stop, or was removed
//	newsletter/issues/ID.json        an issue: proposed, sending, or sent
//	newsletter/issues/ID.sent        the ids an issue reached, one a line
package newsletter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"time"
	"unicode"
	"unicode/utf8"
)

// Keep is how long an address that has not confirmed is kept.
const Keep = 7 * 24 * time.Hour

// ResendAfter is how soon one address may be mailed a link again. Anybody
// can type anybody's address into a form, so this is what stops the form
// being used to fill somebody's inbox.
const ResendAfter = time.Hour

// List is a site's mailing list.
type List struct {
	dir string
	key []byte
}

// Subscriber is one address on the list.
type Subscriber struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	// Name is kept when an import brings one, so a list taken elsewhere
	// again loses nothing. The site's own form does not ask.
	Name string    `json:"name,omitempty"`
	At   time.Time `json:"at"`
	// Source is how it joined: "web", "import" or "added".
	Source string `json:"source"`
	// Consent is what the address was told it was agreeing to, in the words
	// it was shown, or where an import says it agreed.
	Consent string `json:"consent"`
	// Page is the page it signed up on.
	Page string `json:"page,omitempty"`

	// Confirmed is when it said yes; zero while it has not.
	Confirmed time.Time `json:"confirmed,omitempty"`
}

// Errors.
var (
	ErrAddress  = errors.New("give an email address, such as you@example.com")
	ErrNotFound = errors.New("that address is not on the list, or the link is not whole")
	ErrNoKey    = errors.New("the newsletter's key is not made; the site cannot take sign-ups until it is")
)

var reEmail = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$`)

// Normalize checks an address and puts it in the one form the list keeps:
// trimmed and in lower case, so one inbox is one entry.
func Normalize(addr string) (string, error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if len(addr) > 254 || !reEmail.MatchString(addr) || strings.IndexFunc(addr, unicode.IsControl) >= 0 {
		return "", ErrAddress
	}
	return addr, nil
}

// MakeKey makes the key at path when there is none. It is made by the
// process that is not yet confined; the confined site only reads it.
func MakeKey(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	err := createOnce(path, []byte(hex.EncodeToString(key)+"\n"))
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	return err
}

// Open opens the list in dir with the key at keyPath, making the
// directories it writes to.
func Open(dir, keyPath string) (*List, error) {
	raw, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) < 32 {
		return nil, fmt.Errorf("%s is not a newsletter key", filepath.Base(keyPath))
	}
	for _, d := range []string{"subscribers", "confirmed", "left", "issues"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, err
		}
	}
	return &List{dir: dir, key: key}, nil
}

func (l *List) mac(parts ...string) []byte {
	h := hmac.New(sha256.New, l.key)
	h.Write([]byte(strings.Join(parts, "\x00")))
	return h.Sum(nil)
}

// ID is an address's id: the same address, the same id.
func (l *List) ID(addr string) string { return hex.EncodeToString(l.mac("subscriber", addr)[:12]) }

var reID = regexp.MustCompile(`^[0-9a-f]{24}$`)

// ValidID says whether a string is an id.
func ValidID(id string) bool { return reID.MatchString(id) }

// Link purposes.
const (
	ForConfirm = "confirm"
	ForLeave   = "leave"
)

// Token is what a link for one purpose carries for one id.
func (l *List) Token(purpose, id string) string {
	return base64.RawURLEncoding.EncodeToString(l.mac("link", purpose, id))[:22]
}

// Check says whether a link's token is the one for this purpose and id.
func (l *List) Check(purpose, id, token string) bool {
	return ValidID(id) && subtle.ConstantTimeCompare([]byte(l.Token(purpose, id)), []byte(token)) == 1
}

func (l *List) subscriberPath(id string) string {
	return filepath.Join(l.dir, "subscribers", id+".json")
}
func (l *List) marker(kind, id string) string { return filepath.Join(l.dir, kind, id) }

// Outcome is what signing up asks of the caller.
type Outcome int

const (
	// Mail: a new address, or one that has not confirmed and was last sent
	// a link more than ResendAfter ago. Mail it the link.
	Mail Outcome = iota
	// Quiet: already confirmed, or mailed a link within the hour. Send
	// nothing, and say the same to the visitor as for Mail, so the form
	// does not tell anybody who is on the list.
	Quiet
)

// SignUp writes an address down, once, waiting for it to confirm.
func (l *List) SignUp(s Subscriber, now time.Time) (Subscriber, Outcome, error) {
	addr, err := Normalize(s.Email)
	if err != nil {
		return s, Quiet, err
	}
	s.Email, s.ID, s.At, s.Confirmed = addr, l.ID(addr), now.UTC(), time.Time{}
	s.Name = clip(oneLine(s.Name), 100)
	s.Consent = clip(oneLine(s.Consent), 600)
	body, err := json.Marshal(s)
	if err != nil {
		return s, Quiet, err
	}
	path := l.subscriberPath(s.ID)
	err = createOnce(path, body)
	if err == nil {
		return s, Mail, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return s, Quiet, err
	}
	// Already here. When it last had a link is the record's time, so asking
	// again is answered from the file's clock and not by reading it.
	if exists(l.marker("confirmed", s.ID)) {
		return s, Quiet, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return s, Quiet, err
	}
	if now.Sub(info.ModTime()) < ResendAfter {
		return s, Quiet, nil
	}
	if err := os.Chtimes(path, now, now); err != nil {
		return s, Quiet, err
	}
	return s, Mail, nil
}

// Unsent says a link was not sent after all, so the address may ask again
// at once rather than in an hour.
func (l *List) Unsent(id string, now time.Time) {
	if ValidID(id) {
		old := now.Add(-ResendAfter - time.Minute)
		_ = os.Chtimes(l.subscriberPath(id), old, old)
	}
}

// Waiting says whether an id is on the list and has not confirmed, by the
// files that exist rather than what is in them.
func (l *List) Waiting(id string) bool {
	return ValidID(id) && exists(l.subscriberPath(id)) && !exists(l.marker("confirmed", id))
}

// Has says whether an id is on the list, confirmed or not, by whether its
// file exists.
func (l *List) Has(id string) bool { return ValidID(id) && exists(l.subscriberPath(id)) }

// Confirm records that an address said yes. Confirming twice is not an
// error; confirming an address that is not on the list is.
func (l *List) Confirm(id, token string, now time.Time) error {
	if !l.Check(ForConfirm, id, token) || !exists(l.subscriberPath(id)) {
		return ErrNotFound
	}
	if err := createOnce(l.marker("confirmed", id), []byte(now.UTC().Format(time.RFC3339)+"\n")); err != nil &&
		!errors.Is(err, os.ErrExist) {
		return err
	}
	// Asked again and said yes: no longer one that left.
	if err := os.Remove(l.marker("left", id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Leave takes an address off the list for whoever holds its link. It
// answers the same whether the address was on the list or not: leaving
// is never refused, and the answer tells nobody anything.
func (l *List) Leave(id, token, how string, now time.Time) (bool, error) {
	if !l.Check(ForLeave, id, token) {
		return false, ErrNotFound
	}
	was := exists(l.subscriberPath(id))
	return was, l.drop(id, how, now)
}

// Remove takes an address off the list for the site's staff, as leaving
// does: deleted, and kept from being imported back.
func (l *List) Remove(id string, now time.Time) (bool, error) {
	if !ValidID(id) {
		return false, ErrNotFound
	}
	was := exists(l.subscriberPath(id))
	return was, l.drop(id, "removed", now)
}

func (l *List) drop(id, how string, now time.Time) error {
	if err := os.WriteFile(l.marker("left", id), []byte(now.UTC().Format(time.RFC3339)+" "+how+"\n"), 0o600); err != nil {
		return err
	}
	for _, p := range []string{l.subscriberPath(id), l.marker("confirmed", id)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Left says whether an id asked to stop, or was removed.
func (l *List) Left(id string) bool { return ValidID(id) && exists(l.marker("left", id)) }

// Get reads one address: the admin's, and the sender's.
func (l *List) Get(id string) (Subscriber, error) {
	if !ValidID(id) {
		return Subscriber{}, ErrNotFound
	}
	return l.read(id)
}

func (l *List) read(id string) (Subscriber, error) {
	body, err := os.ReadFile(l.subscriberPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return Subscriber{}, ErrNotFound
	}
	if err != nil {
		return Subscriber{}, err
	}
	var s Subscriber
	if err := json.Unmarshal(body, &s); err != nil {
		return Subscriber{}, fmt.Errorf("subscriber %s: %w", id, err)
	}
	s.Confirmed = time.Time{}
	if b, err := os.ReadFile(l.marker("confirmed", id)); err == nil {
		s.Confirmed, _ = time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	}
	return s, nil
}

// All is every address on the list, the newest first: the admin's.
func (l *List) All() ([]Subscriber, error) {
	names, err := filepath.Glob(filepath.Join(l.dir, "subscribers", "*.json"))
	if err != nil {
		return nil, err
	}
	out := make([]Subscriber, 0, len(names))
	for _, n := range names {
		id := strings.TrimSuffix(filepath.Base(n), ".json")
		if !ValidID(id) {
			continue
		}
		s, err := l.read(id)
		if errors.Is(err, ErrNotFound) {
			continue // left while this was reading
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ConfirmedIDs is the ids that said yes: who an issue goes to.
func (l *List) ConfirmedIDs() ([]string, error) {
	names, err := filepath.Glob(filepath.Join(l.dir, "confirmed", "*"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		id := filepath.Base(n)
		if ValidID(id) && exists(l.subscriberPath(id)) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Counts is how many have confirmed, are waiting to, and have left.
type Counts struct {
	Subscribed int `json:"subscribed"`
	Waiting    int `json:"waiting"`
	Left       int `json:"left"`
}

// Count counts the list by its files, reading no address.
func (l *List) Count() (Counts, error) {
	var c Counts
	subs, err := filepath.Glob(filepath.Join(l.dir, "subscribers", "*.json"))
	if err != nil {
		return c, err
	}
	for _, n := range subs {
		id := strings.TrimSuffix(filepath.Base(n), ".json")
		if !ValidID(id) {
			continue
		}
		if exists(l.marker("confirmed", id)) {
			c.Subscribed++
		} else {
			c.Waiting++
		}
	}
	left, err := filepath.Glob(filepath.Join(l.dir, "left", "*"))
	if err != nil {
		return c, err
	}
	for _, n := range left {
		if ValidID(filepath.Base(n)) {
			c.Left++
		}
	}
	return c, nil
}

// Expire forgets addresses that did not confirm within Keep of their last
// link, by the files' clocks, reading none of them.
func (l *List) Expire(now time.Time) (int, error) {
	subs, err := filepath.Glob(filepath.Join(l.dir, "subscribers", "*.json"))
	if err != nil {
		return 0, err
	}
	gone := 0
	for _, n := range subs {
		id := strings.TrimSuffix(filepath.Base(n), ".json")
		if !ValidID(id) || exists(l.marker("confirmed", id)) {
			continue
		}
		info, err := os.Stat(n)
		if err != nil || now.Sub(info.ModTime()) < Keep {
			continue
		}
		if err := os.Remove(n); err != nil && !errors.Is(err, os.ErrNotExist) {
			return gone, err
		}
		gone++
	}
	return gone, nil
}

// Add puts an address on the list as confirmed, for an import of people
// who agreed elsewhere. It is refused for an address that left: that
// person said no here, which an older list from somewhere else does not
// undo. It says whether the address was added.
func (l *List) Add(s Subscriber, now time.Time) (bool, error) {
	addr, err := Normalize(s.Email)
	if err != nil {
		return false, err
	}
	s.Email, s.ID = addr, l.ID(addr)
	if exists(l.marker("left", s.ID)) {
		return false, nil
	}
	if s.At.IsZero() || s.At.After(now) {
		s.At = now
	}
	s.At = s.At.UTC()
	s.Name = clip(oneLine(s.Name), 100)
	s.Consent = clip(oneLine(s.Consent), 600)
	confirmed := s.Confirmed
	s.Confirmed = time.Time{}
	body, err := json.Marshal(s)
	if err != nil {
		return false, err
	}
	err = createOnce(l.subscriberPath(s.ID), body)
	if errors.Is(err, os.ErrExist) {
		// Already here, perhaps waiting to confirm: an import that says it
		// agreed elsewhere confirms it.
		err = nil
	} else if err != nil {
		return false, err
	}
	if confirmed.IsZero() {
		confirmed = now
	}
	err = createOnce(l.marker("confirmed", s.ID), []byte(confirmed.UTC().Format(time.RFC3339)+"\n"))
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	return err == nil, err
}

// createOnce writes a file that must not exist yet, whole or not at all:
// written beside it and linked into place, which fails if it is there.
func createOnce(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".new-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Link(tmp.Name(), path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func oneLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
