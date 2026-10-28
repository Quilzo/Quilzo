// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package booking

import (
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

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Book is where bookings are kept: calendar/ the busy times, a file a
// month, and details/ who booked each, a file a booking.
//
//	bookings/calendar/2026-11.json   []Busy, by start
//	bookings/calendar.lock           held while the calendar changes
//	bookings/details/ID.json         Details, written once
type Book struct{ dir string }

// Open opens, and makes, a book.
func Open(dir string) (*Book, error) {
	for _, d := range []string{filepath.Join(dir, "calendar"), filepath.Join(dir, "details")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &Book{dir: dir}, nil
}

// Details is who booked: what the admin reads and nothing else does.
type Details struct {
	ID      string    `json:"id"`
	Service string    `json:"service"`
	Start   time.Time `json:"start"`
	Name    string    `json:"name"`
	Email   string    `json:"email"`
	Phone   string    `json:"phone,omitempty"`
	Note    string    `json:"note,omitempty"`
	At      time.Time `json:"at"`
	// Source is where it was made: "web", or an agent's tool on the page.
	Source string `json:"source,omitempty"`
}

// Booking is a booking as the admin sees it: when, and who.
type Booking struct {
	When Busy    `json:"when"`
	Who  Details `json:"who"`
}

// Errors a visitor is told.
var (
	ErrTaken    = errors.New("that time has just been taken, or is no longer offered; choose another")
	ErrNotFound = errors.New("there is no such booking")
	ErrPast     = errors.New("that booking has already started")
	ErrPaused   = errors.New("bookings are not being taken just now")
	// ErrDetails is what a visitor sent that is not enough to book with;
	// the error wrapping it says what.
	ErrDetails = errors.New("not enough to book with")
)

var (
	reID    = regexp.MustCompile(`^\d{8}-[0-9a-f]{12}$`)
	reEmail = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$`)
	rePhone = regexp.MustCompile(`^[0-9+()\-. ]{5,30}$`)
)

// ValidID says whether a string is a booking's id.
func ValidID(id string) bool { return reID.MatchString(id) }

// Clean checks and tidies what a visitor sent.
func (d *Details) Clean() error {
	d.Name = strings.TrimSpace(oneLine(d.Name))
	d.Email = strings.TrimSpace(oneLine(d.Email))
	d.Phone = strings.TrimSpace(oneLine(d.Phone))
	d.Note = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || !unicode.IsControl(r) {
			return r
		}
		return -1
	}, d.Note))
	switch {
	case d.Name == "" || utf8.RuneCountInString(d.Name) > 100:
		return errors.New("say your name, in at most 100 characters")
	case len(d.Email) > 254 || !reEmail.MatchString(d.Email):
		return errors.New("give an email address, such as you@example.com")
	case d.Phone != "" && !rePhone.MatchString(d.Phone):
		return errors.New("a telephone number is digits, spaces and + ( ) -")
	case utf8.RuneCountInString(d.Note) > 1000:
		return errors.New("a note is at most 1000 characters")
	}
	return nil
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// month is the calendar file a time falls in, by its UTC date.
func (b *Book) month(t time.Time) string {
	return filepath.Join(b.dir, "calendar", t.UTC().Format("2006-01")+".json")
}

func (b *Book) lock() (func(), error) { return atomicfile.Lock(filepath.Join(b.dir, "calendar.lock")) }

func (b *Book) readMonth(path string) ([]Busy, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Busy
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return out, nil
}

func (b *Book) writeMonth(path string, busy []Busy) error {
	if len(busy) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	sort.Slice(busy, func(i, j int) bool { return busy[i].Start.Before(busy[j].Start) })
	body, err := json.Marshal(busy)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, body, 0o600)
}

// Busy is every booking, standing or cancelled, that starts from a day
// before from to a day after to.
func (b *Book) Busy(from, to time.Time) ([]Busy, error) {
	var out []Busy
	for m := firstOfMonth(from.Add(-24 * time.Hour)); !m.After(to.Add(24 * time.Hour)); m = m.AddDate(0, 1, 0) {
		busy, err := b.readMonth(b.month(m))
		if err != nil {
			return nil, err
		}
		for _, x := range busy {
			if !x.Start.Before(from.Add(-24*time.Hour)) && !x.Start.After(to.Add(24*time.Hour)) {
				out = append(out, x)
			}
		}
	}
	return out, nil
}

func firstOfMonth(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// Window is the bookings Free needs: from now to as far ahead as bookings
// are taken.
func (b *Book) Window(s *Setup, now time.Time) ([]Busy, error) {
	return b.Busy(now, now.AddDate(0, 0, s.Ahead()+1))
}

// Reserve books a service at a time, if that time is still offered, and
// keeps who booked it apart from the calendar. It answers the booking and
// the token the visitor holds to see and cancel it, which is kept only as
// a hash.
func (b *Book) Reserve(s *Setup, svc Service, start, now time.Time, d Details) (Busy, string, error) {
	if s.Paused {
		return Busy{}, "", ErrPaused
	}
	if err := d.Clean(); err != nil {
		return Busy{}, "", fmt.Errorf("%w: %v", ErrDetails, err)
	}
	unlock, err := b.lock()
	if err != nil {
		return Busy{}, "", err
	}
	defer unlock()
	// Checked again under the lock, against the calendar as it is now: two
	// visitors who read the same free time do not both get it.
	busy, err := b.Window(s, now)
	if err != nil {
		return Busy{}, "", err
	}
	if !Offered(s, svc, busy, now, start) {
		return Busy{}, "", ErrTaken
	}
	raw := make([]byte, 6)
	tok := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return Busy{}, "", err
	}
	if _, err := rand.Read(tok); err != nil {
		return Busy{}, "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tok)
	start = start.UTC()
	x := Busy{ID: start.Format("20060102") + "-" + hex.EncodeToString(raw), Service: svc.Name, Start: start,
		Minutes: svc.Minutes, Until: start.Add(time.Duration(svc.Minutes+svc.Buffer) * time.Minute),
		Token: tokenHash(token)}
	d.ID, d.Service, d.Start, d.At = x.ID, svc.Name, start, now.UTC()
	// Who first, then when: a calendar entry with nobody behind it would be
	// a time nobody can be told about, and details with no entry are swept
	// up as stale.
	if err := b.writeDetails(d); err != nil {
		return Busy{}, "", err
	}
	month, err := b.readMonth(b.month(start))
	if err != nil {
		return Busy{}, "", err
	}
	if err := b.writeMonth(b.month(start), append(month, x)); err != nil {
		_ = os.Remove(b.detailsPath(x.ID))
		return Busy{}, "", err
	}
	return x, token, nil
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte("quilzo booking " + token))
	return hex.EncodeToString(sum[:])
}

// FeedHash is how the owner's calendar feed token is kept.
func FeedHash(token string) string {
	sum := sha256.Sum256([]byte("quilzo booking feed " + token))
	return hex.EncodeToString(sum[:])
}

// Matches says, in constant time, whether a token is a booking's.
func (x Busy) Matches(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(tokenHash(token)), []byte(x.Token)) == 1
}

// Find is a booking as the calendar holds it.
func (b *Book) Find(id string) (Busy, error) {
	if !ValidID(id) {
		return Busy{}, ErrNotFound
	}
	day, err := time.Parse("20060102", id[:8])
	if err != nil {
		return Busy{}, ErrNotFound
	}
	month, err := b.readMonth(b.month(day))
	if err != nil {
		return Busy{}, err
	}
	for _, x := range month {
		if x.ID == id {
			return x, nil
		}
	}
	return Busy{}, ErrNotFound
}

// Cancel cancels a booking for whoever holds its token, or, with an empty
// token, for the site: by names who. A booking already cancelled answers
// as it is.
func (b *Book) Cancel(id, token, by string, now time.Time) (Busy, error) {
	if !ValidID(id) {
		return Busy{}, ErrNotFound
	}
	unlock, err := b.lock()
	if err != nil {
		return Busy{}, err
	}
	defer unlock()
	day, _ := time.Parse("20060102", id[:8])
	path := b.month(day)
	month, err := b.readMonth(path)
	if err != nil {
		return Busy{}, err
	}
	for i, x := range month {
		if x.ID != id {
			continue
		}
		if by == "visitor" && !x.Matches(token) {
			return Busy{}, ErrNotFound
		}
		if !x.Live() {
			return x, nil
		}
		if by == "visitor" && !now.Before(x.Start) {
			return Busy{}, ErrPast
		}
		at := now.UTC()
		month[i].Cancelled, month[i].By = &at, by
		return month[i], b.writeMonth(path, month)
	}
	return Busy{}, ErrNotFound
}

func (b *Book) detailsPath(id string) string { return filepath.Join(b.dir, "details", id+".json") }

// writeDetails writes who booked, once: an existing file is never
// overwritten, so the site can add a booking and not change one.
func (b *Book) writeDetails(d Details) error {
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(b.detailsPath(d.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadDetails is who booked. For the admin: the site never calls it.
func (b *Book) ReadDetails(id string) (Details, error) {
	var d Details
	if !ValidID(id) {
		return d, ErrNotFound
	}
	body, err := os.ReadFile(b.detailsPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	return d, json.Unmarshal(body, &d)
}

// List is every booking from a time to another, with who made it, by
// start. For the admin.
func (b *Book) List(from, to time.Time) ([]Booking, error) {
	busy, err := b.Busy(from, to)
	if err != nil {
		return nil, err
	}
	var out []Booking
	for _, x := range busy {
		if x.End().Before(from) || x.Start.After(to) {
			continue
		}
		d, err := b.ReadDetails(x.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		out = append(out, Booking{When: x, Who: d})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.Start.Before(out[j].When.Start) })
	return out, nil
}

// Erase removes who made a booking, and cancels it if it stands: what a
// visitor asking to be forgotten is owed.
func (b *Book) Erase(id, by string, now time.Time) error {
	if _, err := b.Cancel(id, "", by, now); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := os.Remove(b.detailsPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Expire forgets bookings whose appointment ended longer ago than keep:
// who made them, and then the time itself. It answers how many.
func (b *Book) Expire(keep time.Duration, now time.Time) (int, error) {
	unlock, err := b.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	cutoff := now.Add(-keep)
	files, err := filepath.Glob(filepath.Join(b.dir, "calendar", "*.json"))
	if err != nil {
		return 0, err
	}
	gone := 0
	for _, path := range files {
		month, err := b.readMonth(path)
		if err != nil {
			return gone, err
		}
		kept := month[:0]
		for _, x := range month {
			if x.End().Before(cutoff) {
				if err := os.Remove(b.detailsPath(x.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return gone, err
				}
				gone++
				continue
			}
			kept = append(kept, x)
		}
		if len(kept) != len(month) {
			if err := b.writeMonth(path, kept); err != nil {
				return gone, err
			}
		}
	}
	// Details with no calendar entry: a booking whose entry was never
	// written, a day old or more.
	orphans, err := filepath.Glob(filepath.Join(b.dir, "details", "*.json"))
	if err != nil {
		return gone, err
	}
	for _, path := range orphans {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		if _, err := b.Find(id); errors.Is(err, ErrNotFound) {
			if fi, err := os.Stat(path); err == nil && now.Sub(fi.ModTime()) > 24*time.Hour {
				_ = os.Remove(path)
			}
		}
	}
	return gone, nil
}
