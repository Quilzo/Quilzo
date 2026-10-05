// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package shield is Quilzo protecting itself before harm is done: blocking
// a source, turning a public feature down, locking the admin to its
// strongest sign-ins, freezing publishing, pausing an agent. Each is a
// protection with an end, and every one of them can be undone.
//
// # Why only what can be undone
//
// The time between the first sign of an attack and the damage is now
// seconds to minutes; waiting for a person to approve a block is waiting
// until afterwards. So these act at once, with nobody asked, and that is
// safe for one reason only: each is reversible and ends by itself. An
// address blocked by mistake is a person told to try again in an hour.
// Anything that cannot be undone that way, or that reaches another system,
// is not here: restoring content and acting on other tools stay with
// people, and two of them, as they always have.
//
// # The guardrails, enforced here rather than trusted to whoever asks
//
//   - Every protection ends: automatically applied ones within MaxAuto
//     (24 hours) of when they began, ones a person sets within MaxManual
//     (seven days). An attack that outlasts a protection meets a new one,
//     with its own start, from the playbook's next stage; nothing is
//     quietly renewed past its limit.
//   - Addresses on the inside (loopback, private networks, carrier-grade
//     NAT; clientip.Local) and the networks the operator declared trusted
//     are never blocked, so the machine, the office and the proxy in front
//     are always a way in; and the command line on the machine never goes
//     through any of this, so `quilzo shield lift all` there is the way
//     out of anything.
//   - A source an administrator signed in from with a passkey or single
//     sign-on in the last thirty days is not blocked from the admin by a
//     playbook: that is the security contact's call, and they are told.
//   - The admin's sign-in pages and the shield's own screen cannot be
//     shielded, and lockdown never refuses a passkey or single sign-on, or
//     a token made after it began.
//   - A bounded number are active at once, so a flood of spoofed signals
//     cannot grow the list without limit.
//
// # What is stored
//
// No addresses. A single source is blocked by the handle the audit log
// already gives it (audit.Pseudonym), and the enforcement point computes
// the same handle for each request. A network is stored as the range an
// operator typed, and a provider by its autonomous system number.
package shield

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/clientip"
)

// Kinds of protection.
const (
	Block    = "block"    // refuse requests from a source, network or provider
	Feature  = "feature"  // turn a feature down or off
	Lockdown = "lockdown" // admin sign-in by passkey or single sign-on only
	Freeze   = "freeze"   // no publishing
	Agent    = "agent"    // an agent does not run
)

// Where a block applies.
const (
	Admin = "admin"
	Site  = "site"
	All   = "all"
)

// Levels of a feature shield.
const (
	Off     = "off"     // the feature is not available
	Limited = "limited" // a chatbot answers from pages only, with no model
)

// Limits.
const (
	MaxAuto   = 24 * time.Hour
	MaxManual = 7 * 24 * time.Hour
	MaxActive = 5000
	maxKept   = 500
)

// Features are what a feature shield may name: the public surfaces an
// attacker can reach and a site can do without for an hour. The admin's
// sign-in, its screens and this package's own are deliberately absent.
var Features = map[string]string{
	"chatbots":       "every chatbot on the site",
	"chatbot":        "one chatbot, by name",
	"forms":          "every form on the site",
	"form":           "one form, by name",
	"boards":         "members posting to boards",
	"signup":         "making a new member account",
	"search-answers": "AI answers in site search",
	"api":            "the content API",
	"mcp":            "the machine interface",
	"scim":           "provisioning from the identity provider",
	"uploads":        "media uploads",
	"import":         "importing content",
	"feeds":          "deliveries from other systems",
}

// Protection is one thing the shield is doing.
type Protection struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"`
	Target string    `json:"target"`
	Where  string    `json:"where,omitempty"`
	Level  string    `json:"level,omitempty"`
	Reason string    `json:"reason"`
	By     string    `json:"by"`
	Auto   bool      `json:"auto,omitempty"`
	At     time.Time `json:"at"`
	Until  time.Time `json:"until"`
	// Lifted is when a person ended it early, and who.
	Lifted   time.Time `json:"lifted,omitzero"`
	LiftedBy string    `json:"lifted_by,omitempty"`
	// Playbook and Stage name what applied it, when one did.
	Playbook string `json:"playbook,omitempty"`
	Stage    int    `json:"stage,omitempty"`
	// ReplacedBy is the protection that took over from this one: a person
	// setting the same thing, or a playbook needing it past this one's
	// limit.
	ReplacedBy string `json:"replaced_by,omitempty"`
	// Verdict is a person's judgement of it afterwards, Mistake or Right,
	// which is what a playbook's precision is counted from.
	Verdict   string `json:"verdict,omitempty"`
	VerdictBy string `json:"verdict_by,omitempty"`
}

// Verdicts on a protection.
const (
	Mistake = "mistake"
	Right   = "right"
)

// limit is the longest a protection of this sort may last.
func (p Protection) limit() time.Duration {
	if p.Auto {
		return MaxAuto
	}
	return MaxManual
}

// ActiveAt reports whether it is in force. A record that says it lasts
// longer than any protection may (written by hand, by an older version or
// by a bug) ends when it would have had to.
func (p Protection) ActiveAt(now time.Time) bool {
	if !p.Lifted.IsZero() || !now.Before(p.Until) {
		return false
	}
	return p.At.IsZero() || !now.After(p.At.Add(p.limit()+time.Minute))
}

// State is everything the shield holds.
type State struct {
	Protections []Protection `json:"protections"`
	// Ended are the most recent that expired or were lifted, for the
	// history and for a rule's precision to be judged against.
	Ended []Protection `json:"ended,omitempty"`
	// Trusted are networks never blocked: an office, a VPN, the admins'.
	Trusted []string `json:"trusted,omitempty"`
	// Responses are what playbooks did, most recent last.
	Responses []Response `json:"responses,omitempty"`
	// Decoys are planted credentials, by hash.
	Decoys []Decoy `json:"decoys,omitempty"`
	// Vouched are sources an administrator signed in from with a passkey
	// or single sign-on, by handle, most recent last.
	Vouched []Vouched `json:"vouched,omitempty"`
	// Watching, when set, holds every playbook to watching: one
	// administrator may set it, because it is the safe direction; letting
	// them act again takes a second (Book).
	Watching *Hold `json:"watching,omitempty"`
}

// Vouched is a source somebody signed in from strongly.
type Vouched struct {
	Handle string    `json:"handle"`
	At     time.Time `json:"at"`
}

// Hold is every playbook held to watching, and who did it.
type Hold struct {
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

// VouchFor is how long a strong sign-in keeps its source from being
// blocked from the admin by a playbook.
const VouchFor = 30 * 24 * time.Hour

const maxVouched = 1000

// IsVouched reports whether a source handle signed in strongly lately.
func (s *State) IsVouched(handles []string, now time.Time) bool {
	for _, v := range s.Vouched {
		if now.Sub(v.At) > VouchFor {
			continue
		}
		for _, h := range handles {
			if h != "" && v.Handle == h {
				return true
			}
		}
	}
	return false
}

// Active are the protections in force.
func (s *State) Active(now time.Time) []Protection {
	var out []Protection
	for _, p := range s.Protections {
		if p.ActiveAt(now) {
			out = append(out, p)
		}
	}
	return out
}

// Path is where the shield is kept for a store.
func Path(root string) string { return filepath.Join(root, "shield.json") }

// Load reads the shield; a store that has never had one has an empty one.
func Load(root string) (*State, error) {
	b, err := os.ReadFile(Path(root))
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	st := &State{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("shield.json: %w", err)
	}
	return st, nil
}

// Change reads, changes and writes the shield under a lock, moving what
// has ended into the history as it goes.
func Change(root string, now time.Time, fn func(*State) error) error {
	unlock, err := lock(Path(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	st, err := Load(root)
	if err != nil {
		return err
	}
	var keep []Protection
	for _, p := range st.Protections {
		if p.ActiveAt(now) {
			keep = append(keep, p)
		} else {
			st.Ended = append(st.Ended, p)
		}
	}
	st.Protections = keep
	if err := fn(st); err != nil {
		return err
	}
	if len(st.Ended) > maxKept {
		st.Ended = st.Ended[len(st.Ended)-maxKept:]
	}
	var vouched []Vouched
	for _, v := range st.Vouched {
		if now.Sub(v.At) <= VouchFor {
			vouched = append(vouched, v)
		}
	}
	if len(vouched) > maxVouched {
		vouched = vouched[len(vouched)-maxVouched:]
	}
	st.Vouched = vouched
	b, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	return atomicfile.Write(Path(root), b, 0o600)
}

func lock(path string) (func(), error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if fi, serr := os.Stat(path); serr == nil && time.Since(fi.ModTime()) > 30*time.Second {
			os.Remove(path) // left by a process that died
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("the shield is being changed by another process")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "sh-" + hex.EncodeToString(b)
}

var (
	reHandle = regexp.MustCompile(`^p_[0-9a-f]{32}$`)
	reName   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// Validate checks a protection before it is applied, whoever asked.
func (p Protection) Validate(now time.Time) error {
	max := MaxManual
	if p.Auto {
		max = MaxAuto
	}
	if !p.Until.After(now) {
		return errors.New("a protection has to end in the future")
	}
	if p.Until.Sub(now) > max+time.Minute {
		return fmt.Errorf("a protection set %s ends within %s", map[bool]string{true: "automatically", false: "by a person"}[p.Auto], max)
	}
	if strings.TrimSpace(p.Reason) == "" || len(p.Reason) > 300 {
		return errors.New("a protection says why, in at most 300 characters")
	}
	if strings.TrimSpace(p.By) == "" {
		return errors.New("a protection says who or what applied it")
	}
	switch p.Kind {
	case Block:
		if p.Where != Admin && p.Where != Site && p.Where != All {
			return errors.New("a block is on the admin, the site, or both")
		}
		kind, value, _ := strings.Cut(p.Target, ":")
		switch kind {
		case "source":
			if !reHandle.MatchString(value) {
				return errors.New("a source is blocked by its handle in the audit log")
			}
		case "net":
			pfx, err := netip.ParsePrefix(value)
			if err != nil {
				return fmt.Errorf("%q is not a network", value)
			}
			// Wider than a /16 or /48 is most of a country or a provider:
			// that is a decision with a name, the provider's, not a range.
			if (pfx.Addr().Is4() && pfx.Bits() < 16) || (pfx.Addr().Is6() && pfx.Bits() < 48) {
				return errors.New("a network wider than /16 (or /48) is blocked by its provider instead")
			}
			for _, in := range clientip.Inside() {
				if pfx.Overlaps(in) {
					return fmt.Errorf("%s is on the inside (%s): this machine, its network and the proxy in front are never blocked", pfx, in)
				}
			}
		case "asn":
			if n, err := strconv.ParseUint(value, 10, 32); err != nil || n == 0 {
				return fmt.Errorf("%q is not a provider's number", value)
			}
		default:
			return errors.New("a block names a source, a network or a provider")
		}
	case Feature:
		name, one, _ := strings.Cut(p.Target, ":")
		if _, ok := Features[name]; !ok {
			return fmt.Errorf("%q is not a feature the shield can turn down", name)
		}
		if (name == "chatbot" || name == "form") != (one != "") {
			return errors.New("a chatbot or form is named; the others are not")
		}
		if one != "" && !reName.MatchString(one) {
			return fmt.Errorf("%q is not a name", one)
		}
		if p.Level != Off && !(p.Level == Limited && (name == "chatbot" || name == "chatbots")) {
			return errors.New("a feature is turned off, or a chatbot limited to quoting pages")
		}
	case Lockdown, Freeze:
		if p.Target != "" {
			return errors.New("lockdown and freeze apply to everything")
		}
	case Agent:
		if !reName.MatchString(p.Target) {
			return fmt.Errorf("%q is not an agent", p.Target)
		}
	default:
		return fmt.Errorf("%q is not a kind of protection", p.Kind)
	}
	return nil
}

// Apply puts a protection in force. One already in force on the same thing
// is lengthened, not doubled, so a signal that keeps coming keeps the
// block in place rather than filling the list.
func Apply(root string, p Protection, now time.Time) (Protection, bool, error) {
	if err := p.Validate(now); err != nil {
		return p, false, err
	}
	var out Protection
	fresh := false
	err := Change(root, now, func(st *State) error {
		if p.Kind == Block && strings.HasPrefix(p.Target, "net:") {
			pfx, _ := netip.ParsePrefix(strings.TrimPrefix(p.Target, "net:"))
			for _, t := range st.Trusted {
				if tp, err := netip.ParsePrefix(t); err == nil && tp.Overlaps(pfx) {
					return fmt.Errorf("%s overlaps the trusted network %s, which is never blocked", pfx, t)
				}
			}
		}
		replaces := -1
		for i := range st.Protections {
			q := &st.Protections[i]
			if q.Kind != p.Kind || q.Target != p.Target || q.Where != p.Where || q.Level != p.Level {
				continue
			}
			if !p.Until.After(q.Until) {
				out = *q // already covered
				return nil
			}
			// Lengthened in place only within the record's own limit, and
			// only by the same sort of author: a person's protection is a
			// person's, and an automatic one cannot be renewed past a day.
			if q.Auto == p.Auto && !p.Until.After(q.At.Add(q.limit())) {
				q.Until = p.Until
				if p.Stage > q.Stage {
					q.Stage, q.Reason, q.Playbook, q.By = p.Stage, p.Reason, p.Playbook, p.By
				}
				out = *q
				return nil
			}
			replaces = i
			break
		}
		if replaces < 0 && len(st.Protections) >= MaxActive {
			return fmt.Errorf("%d protections are already in force; that is the limit", MaxActive)
		}
		p.ID, p.At, fresh = newID(), now, true
		if replaces >= 0 {
			q := &st.Protections[replaces]
			q.Until, q.ReplacedBy = now, p.ID
		}
		st.Protections = append(st.Protections, p)
		out = p
		return nil
	})
	return out, fresh, err
}

// Lift ends a protection early: one by its id, or every one with "all".
func Lift(root, id, by string, now time.Time) ([]Protection, error) {
	var lifted []Protection
	err := Change(root, now, func(st *State) error {
		for i := range st.Protections {
			p := &st.Protections[i]
			if id == "all" || p.ID == id {
				p.Lifted, p.LiftedBy = now, by
				lifted = append(lifted, *p)
			}
		}
		if len(lifted) == 0 && id != "all" {
			return fmt.Errorf("no protection %s is in force", id)
		}
		return nil
	})
	return lifted, err
}

// Judge records a person's verdict on a protection, in force or ended: a
// Mistake (it should not have been applied) or Right. It is what each
// playbook's precision is counted from.
func Judge(root, id, verdict, by string, now time.Time) (Protection, error) {
	if verdict != Mistake && verdict != Right {
		return Protection{}, errors.New("a protection was a mistake, or right")
	}
	var out Protection
	err := Change(root, now, func(st *State) error {
		for _, list := range [][]Protection{st.Protections, st.Ended} {
			for i := range list {
				if list[i].ID == id {
					list[i].Verdict, list[i].VerdictBy = verdict, by
					out = list[i]
					return nil
				}
			}
		}
		return fmt.Errorf("there is no protection %s", id)
	})
	return out, err
}

// Vouch records that an administrator signed in from these source handles
// with a passkey or single sign-on.
func Vouch(root string, handles []string, now time.Time) error {
	return Change(root, now, func(st *State) error {
		for _, h := range handles {
			if !reHandle.MatchString(h) {
				continue
			}
			kept := st.Vouched[:0]
			for _, v := range st.Vouched {
				if v.Handle != h {
					kept = append(kept, v)
				}
			}
			st.Vouched = append(kept, Vouched{Handle: h, At: now})
		}
		return nil
	})
}

// HoldAll holds every playbook to watching, at once and by one person: the
// way to stop the shield acting while somebody works out why it did.
func HoldAll(root, by, reason string, now time.Time) error {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 300 {
		return errors.New("say why, in at most 300 characters")
	}
	return Change(root, now, func(st *State) error {
		if st.Watching != nil {
			return fmt.Errorf("every playbook has been watching since %s, held by %s",
				st.Watching.At.UTC().Format("2 Jan 15:04 UTC"), st.Watching.By)
		}
		st.Watching = &Hold{By: by, At: now, Reason: reason}
		return nil
	})
}

// release lets the playbooks act again; a second person approves it
// (Book), or the machine does it (ReleaseOnMachine).
func release(root string, now time.Time) error {
	return Change(root, now, func(st *State) error {
		if st.Watching == nil {
			return errors.New("the playbooks are not being held")
		}
		st.Watching = nil
		return nil
	})
}

// Trust adds or removes a network that is never blocked.
func Trust(root, network string, add bool, now time.Time) error {
	pfx, err := netip.ParsePrefix(network)
	if err != nil {
		return fmt.Errorf("%q is not a network", network)
	}
	return Change(root, now, func(st *State) error {
		var keep []string
		for _, t := range st.Trusted {
			if t != pfx.String() {
				keep = append(keep, t)
			}
		}
		if add {
			keep = append(keep, pfx.String())
		}
		sort.Strings(keep)
		st.Trusted = keep
		return nil
	})
}

// Frozen reports whether publishing is frozen, read straight from the
// store: for the one place that publishes, which has no guard of its own.
func Frozen(root string, now time.Time) (Protection, bool) { return Find(root, Freeze, "", now) }
