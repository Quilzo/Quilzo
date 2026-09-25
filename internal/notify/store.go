// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Keeping the list, the notices and what has been delivered.
//
// Plain files, 0600, in a directory of their own. The contact list is
// personal data and the suppression list is a list of people who asked to be
// left alone, so neither goes in the content store the web process serves and
// neither is exported by anything that exports a site.
//
// The fingerprinting key lives beside them in a file of its own, which is a
// compromise worth naming rather than hiding: a key in the same directory as
// the file it protects is a key an attacker who reads the directory has. It
// buys one thing — a stolen suppression list is useless without also having
// taken the key — and it is the same arrangement the audit log makes for the
// same reason. A deployment that can hold the key elsewhere should.

// Inbox is what a contact has waiting in the product.
type Inbox struct {
	To         telemetry.ID `json:"to"`
	Notice     string       `json:"notice"`
	Kind       Kind         `json:"kind"`
	Subject    string       `json:"subject"`
	Body       string       `json:"body"`
	At         time.Time    `json:"at"`
	ReadAt     time.Time    `json:"read_at,omitempty"`
	Urgent     bool         `json:"urgent,omitempty"`
	Declinable bool         `json:"declinable"`
}

// Store holds the audience, the notices and the outbox on disk.
type Store struct {
	dir string
	key []byte
}

type stored struct {
	Contacts   []Contact            `json:"contacts"`
	Suppressed map[string]time.Time `json:"suppressed,omitempty"`
}

// OpenStore prepares the directory and loads or creates the key.
func OpenStore(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("the notification store needs a directory")
	}
	if err := os.MkdirAll(filepath.Join(dir, "notices"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "inbox"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	path := filepath.Join(dir, "notify.key")
	b, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		k, kerr := NewKey()
		if kerr != nil {
			return nil, kerr
		}
		if werr := atomicfile.Write(path, k, 0o600); werr != nil {
			return nil, werr
		}
		s.key = k
	case err != nil:
		return nil, err
	default:
		s.key = b
	}
	return s, nil
}

// Audience loads the list.
func (s *Store) Audience() (*Audience, error) {
	a, err := NewAudience(s.key)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "contacts.json"))
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	var in stored
	if uerr := json.Unmarshal(b, &in); uerr != nil {
		return nil, fmt.Errorf("the contact list is unreadable: %w", uerr)
	}
	a.Load(in.Contacts, in.Suppressed)
	return a, nil
}

// SaveAudience writes the list back.
func (s *Store) SaveAudience(a *Audience) error {
	b, err := json.MarshalIndent(stored{
		Contacts: a.All(), Suppressed: a.Suppressions(),
	}, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(s.dir, "contacts.json"), b, 0o600)
}

// SaveNotice stores a drafted notice.
func (s *Store) SaveNotice(n Notice) error {
	b, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(
		filepath.Join(s.dir, "notices", n.ID+".json"), b, 0o600)
}

// Notice loads one.
func (s *Store) Notice(id string) (Notice, error) {
	var n Notice
	b, err := os.ReadFile(filepath.Join(s.dir, "notices", id+".json"))
	if os.IsNotExist(err) {
		return n, fmt.Errorf("there is no notice %s", id)
	}
	if err != nil {
		return n, err
	}
	return n, json.Unmarshal(b, &n)
}

// Notices lists what has been drafted, newest awareness first.
func (s *Store) Notices() ([]Notice, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "notices"))
	if err != nil {
		return nil, err
	}
	var out []Notice
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		if id == e.Name() {
			continue
		}
		n, nerr := s.Notice(id)
		if nerr != nil {
			return nil, nerr
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Aware.After(out[j].Aware) })
	return out, nil
}

// Outbox loads what has already been delivered.
func (s *Store) Outbox() (*Outbox, error) {
	o := NewOutbox()
	b, err := os.ReadFile(filepath.Join(s.dir, "outbox.json"))
	if os.IsNotExist(err) {
		return o, nil
	}
	if err != nil {
		return nil, err
	}
	var done map[string]time.Time
	if uerr := json.Unmarshal(b, &done); uerr != nil {
		return nil, fmt.Errorf("the outbox is unreadable: %w", uerr)
	}
	o.Load(done)
	return o, nil
}

// SaveOutbox writes it back.
//
// Called after every delivery rather than at the end of a run. An outbox
// written once at the end is one that loses everything a crash interrupts,
// and what it loses is the knowledge of who has already been told.
func (s *Store) SaveOutbox(o *Outbox) error {
	b, err := json.MarshalIndent(o.Done(), "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(s.dir, "outbox.json"), b, 0o600)
}

// inboxPath is where a contact's waiting notices live.
func (s *Store) inboxPath(to telemetry.ID) string {
	name := strings.NewReplacer("/", "_", "\\", "_", ":", "_",
		"..", "_").Replace(to.String())
	return filepath.Join(s.dir, "inbox", name+".jsonl")
}

// AppSender delivers in the product: a notice waiting for somebody who signs
// in. The only channel where delivery is a fact rather than a hope, and the
// only one that cannot be read in transit by whoever runs the mail server.
type AppSender struct {
	Store *Store
	At    func() time.Time
}

// Send appends to the contact's inbox.
func (s AppSender) Send(n Notice, d Delivery) error {
	at := time.Now().UTC()
	if s.At != nil {
		at = s.At()
	}
	item := Inbox{
		To: d.To, Notice: n.ID, Kind: n.Kind, Subject: n.Subject,
		Body: n.Body, At: at, Urgent: n.Kind.Urgent(),
		Declinable: n.Kind.Objectable(),
	}
	b, err := json.Marshal(item)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.Store.inboxPath(d.To),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// InboxFor reads what a contact has waiting.
func (s *Store) InboxFor(to telemetry.ID) ([]Inbox, error) {
	b, err := os.ReadFile(s.inboxPath(to))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Inbox
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var item Inbox
		if uerr := json.Unmarshal([]byte(line), &item); uerr != nil {
			return nil, uerr
		}
		out = append(out, item)
	}
	return out, nil
}

// ForgetInbox removes a contact's waiting notices.
//
// Part of honouring an erasure: the inbox holds the body of every notice sent
// to somebody, addressed to them, which is personal data however
// pseudonymously the audit record was written. The audit record of the
// delivery stays, because Article 33(5) requires the documentation and it
// holds no address.
func (s *Store) ForgetInbox(to telemetry.ID) error {
	err := os.Remove(s.inboxPath(to))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
