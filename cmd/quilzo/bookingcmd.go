// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/booking"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Bookings (internal/booking): how the site takes them, kept at the
// store's root where the site reads it and cannot write it, and the
// bookings themselves, in bookings/, which the site writes.

func bookingSetupPath(root string) string { return filepath.Join(root, "bookings.json") }

func bookingsDir(root string) string { return filepath.Join(root, "bookings") }

func openBookings(root string) (*booking.Book, error) { return booking.Open(bookingsDir(root)) }

// loadBookingSetup is how the site takes bookings; nil when it takes none.
func loadBookingSetup(root string) (*booking.Setup, error) {
	body, err := os.ReadFile(bookingSetupPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s booking.Setup
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("bookings.json: %w", err)
	}
	return &s, nil
}

// saveBookingSetup checks a setup and keeps it, on the record. The feed's
// hash is carried over unless the change is to the feed.
func saveBookingSetup(root string, s *booking.Setup, caller *Caller, what string) error {
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return fmt.Errorf("how the site takes bookings changes what it offers at once, as publishing does: %w", err)
	}
	if err := s.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(bookingSetupPath(root), append(body, '\n'), 0o600); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("booking.setup", "/", audit.Success, map[string]string{
		"change": what, "services": fmt.Sprint(len(s.Services)), "paused": fmt.Sprint(s.Paused)}))
}

// publicBookings is what the site is given: the setup, read per request so
// a change takes effect without a restart, and the book.
func publicBookings(root string) *public.Bookings {
	book, err := openBookings(root)
	if err != nil {
		return nil
	}
	return &public.Bookings{
		Setup: func() (*booking.Setup, error) { return loadBookingSetup(root) },
		Book:  book,
		Limit: throttle.New(throttlePolicy(mustConfig(root))),
		Audit: func(action, service, source string, ok bool) {
			outcome := audit.Success
			if !ok {
				outcome = audit.Denied
			}
			// The service and the source, never who booked: the log outlives
			// the bookings it would otherwise keep a copy of.
			record(root, audit.Record{Action: action, Resource: "/book/" + service, Outcome: outcome,
				Principal: source, Kind: audit.KindUnknown})
		},
		Notify: func(action, service string) {
			if action == "booking.cancelled" {
				go fireBookingWebhooks(root, "booking-cancelled", service)
				return
			}
			go fireBookingWebhooks(root, "booked", service)
		},
	}
}

// cmdBooking is `quilzo booking …`.
func cmdBooking(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "list":
		return bookingList(root, args[1:], caller)
	case "setup":
		return bookingSetupCmd(root, args[1:], caller)
	case "example":
		body, _ := json.MarshalIndent(bookingExample(), "", "  ")
		_, err := os.Stdout.Write(append(body, '\n'))
		return err
	case "cancel":
		return bookingCancelCmd(root, args[1:], caller)
	case "pause", "resume":
		return bookingPause(root, args[0] == "pause", caller)
	case "feed":
		return bookingFeedCmd(root, args[1:], caller)
	default:
		return fmt.Errorf("unknown booking command %q; try list, setup, example, cancel, pause, resume or feed", args[0])
	}
}

// bookingExample is a setup to start from.
func bookingExample() *booking.Setup {
	return &booking.Setup{Zone: "Europe/London", NoticeHours: 2, AheadDays: 60, KeepDays: 30,
		Week: map[string][]booking.Span{
			"mon": {{From: "09:00", To: "12:30"}, {From: "13:30", To: "17:00"}},
			"tue": {{From: "09:00", To: "12:30"}, {From: "13:30", To: "17:00"}},
			"wed": {{From: "09:00", To: "12:30"}, {From: "13:30", To: "17:00"}},
			"thu": {{From: "09:00", To: "12:30"}, {From: "13:30", To: "17:00"}},
			"fri": {{From: "09:00", To: "12:30"}, {From: "13:30", To: "16:00"}},
		},
		Closed: []string{"2026-12-25", "2026-12-26"},
		Services: []booking.Service{
			{Name: "consultation", Title: "Consultation", Minutes: 30, Buffer: 10, About: "A first conversation about what you need."},
			{Name: "visit", Title: "Home visit", Minutes: 60, Buffer: 30, Price: "£60"},
		}}
}

func bookingList(root string, args []string, caller *Caller) error {
	fs := flag.NewFlagSet("booking list", flag.ContinueOnError)
	days := fs.Int("days", 14, "how many days ahead")
	past := fs.Int("past", 0, "how many days back as well")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return fmt.Errorf("who booked is read by whoever reads what forms collect: %w", err)
	}
	setup, err := loadBookingSetup(root)
	if err != nil {
		return err
	}
	book, err := openBookings(root)
	if err != nil {
		return err
	}
	now := time.Now()
	list, err := book.List(now.AddDate(0, 0, -*past), now.AddDate(0, 0, *days))
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"bookings": list}) {
		return nil
	}
	if setup == nil {
		w.Human("%sthis site takes no bookings: quilzo booking setup FILE (quilzo booking example to start)%s\n", dim, reset)
	} else if setup.Paused {
		w.Human("%sbookings are paused: quilzo booking resume%s\n", yellow, reset)
	}
	if len(list) == 0 {
		w.Human("nothing booked in the next %d days\n", *days)
		return nil
	}
	loc := time.Local
	if setup != nil {
		if l, err := setup.Location(); err == nil {
			loc = l
		}
	}
	for _, b := range list {
		state := ""
		if !b.When.Live() {
			state = fmt.Sprintf(" %scancelled by the %s%s", dim, b.When.By, reset)
		}
		w.Human("%s  %s  %s, %d min  %s <%s>%s%s\n", b.When.Start.In(loc).Format("Mon 2 Jan 15:04"), b.When.ID,
			b.When.Service, b.When.Minutes, b.Who.Name, b.Who.Email, phoneSuffix(b.Who.Phone), state)
		if b.Who.Note != "" {
			w.Human("      %s%s%s\n", dim, strings.ReplaceAll(b.Who.Note, "\n", " / "), reset)
		}
	}
	return nil
}

func phoneSuffix(p string) string {
	if p == "" {
		return ""
	}
	return ", " + p
}

func bookingSetupCmd(root string, args []string, caller *Caller) error {
	if len(args) == 0 {
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return err
		}
		s, err := loadBookingSetup(root)
		if err != nil {
			return err
		}
		if s == nil {
			w.Human("this site takes no bookings; start from: quilzo booking example > bookings.json\n")
			return nil
		}
		shown := *s
		shown.Feed = map[bool]string{true: "(on)", false: ""}[s.Feed != ""]
		body, _ := json.MarshalIndent(shown, "", "  ")
		_, err = os.Stdout.Write(append(body, '\n'))
		return err
	}
	body, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var s booking.Setup
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	// The feed is set by `quilzo booking feed`, never by a file.
	if prior, err := loadBookingSetup(root); err == nil && prior != nil {
		s.Feed = prior.Feed
	} else {
		s.Feed = ""
	}
	if err := saveBookingSetup(root, &s, caller, "setup"); err != nil {
		return err
	}
	w.Human("the site takes bookings for %d service(s); a page shows them with a booking section naming one\n",
		len(s.Services))
	return nil
}

func bookingCancelCmd(root string, args []string, caller *Caller) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("booking cancel", flag.ContinueOnError)
	erase := fs.Bool("erase", false, "forget who booked as well, as somebody asking to be forgotten is owed")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo booking cancel ID [--erase]")
	}
	return cancelBooking(root, pos[0], *erase, caller)
}

// cancelBooking cancels a booking for the site, and forgets who made it
// when asked to.
func cancelBooking(root, id string, erase bool, caller *Caller) error {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return fmt.Errorf("a booking is cancelled by whoever reads who booked: %w", err)
	}
	book, err := openBookings(root)
	if err != nil {
		return err
	}
	x, err := book.Find(id)
	if err != nil {
		return fmt.Errorf("%s: %w", id, err)
	}
	if erase {
		err = book.Erase(id, "site", time.Now())
	} else {
		_, err = book.Cancel(id, "", "site", time.Now())
	}
	if err != nil {
		return err
	}
	action := "booking.cancelled"
	if erase {
		action = "booking.erased"
	}
	if err := recordE(root, caller.auditRecord(action, "/book/"+x.Service, audit.Success,
		map[string]string{"booking": id})); err != nil {
		return err
	}
	go fireBookingWebhooks(root, "booking-cancelled", x.Service)
	w.Human("cancelled %s%s\n", id, map[bool]string{true: ", and forgot who booked it", false: ""}[erase])
	return nil
}

func bookingPause(root string, pause bool, caller *Caller) error {
	s, err := loadBookingSetup(root)
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("this site takes no bookings to pause")
	}
	s.Paused = pause
	what := map[bool]string{true: "pause", false: "resume"}[pause]
	if err := saveBookingSetup(root, s, caller, what); err != nil {
		return err
	}
	if pause {
		w.Human("no new bookings are taken; those made stand. quilzo booking resume takes them again\n")
	} else {
		w.Human("bookings are taken again\n")
	}
	return nil
}

// bookingFeedCmd makes the owner's calendar feed, or turns it off. The
// token is shown once and kept only as a hash; making a new one ends the
// old.
func bookingFeedCmd(root string, args []string, caller *Caller) error {
	fs := flag.NewFlagSet("booking feed", flag.ContinueOnError)
	off := fs.Bool("off", false, "turn the feed off")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := loadBookingSetup(root)
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("this site takes no bookings to make a feed of")
	}
	url, err := makeBookingFeed(root, s, *off, caller)
	if err != nil {
		return err
	}
	if *off {
		w.Human("the calendar feed is off; its address answers nothing now\n")
		return nil
	}
	if w.JSON(map[string]string{"url": url}) {
		return nil
	}
	w.Human("subscribe to this in your calendar; it is shown once, and making another ends it:\n  %s\n", url)
	w.Human("  %sit shows when each booking is and for what, never who: that is here and in the admin%s\n", dim, reset)
	return nil
}

// makeBookingFeed makes a new feed token, or turns the feed off, and
// answers its address.
func makeBookingFeed(root string, s *booking.Setup, off bool, caller *Caller) (string, error) {
	if off {
		s.Feed = ""
		return "", saveBookingSetup(root, s, caller, "feed off")
	}
	tok := make([]byte, 24)
	if _, err := rand.Read(tok); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tok)
	s.Feed = booking.FeedHash(token)
	if err := saveBookingSetup(root, s, caller, "feed"); err != nil {
		return "", err
	}
	base := ""
	if cfg, err := loadConfig(root); err == nil {
		base = strings.TrimSuffix(strings.TrimSpace(cfg.Raw("site.base_url")), "/")
	}
	if base == "" {
		base = "https://your-site.example"
	}
	return base + "/book/feed/" + token + ".ics", nil
}

// bookingHooks are the admin's way to the bookings.
func bookingHooks(root string, signedIn func(admin.Actor) *Caller) *admin.BookingHooks {
	return &admin.BookingHooks{
		Setup: func() (*booking.Setup, error) { return loadBookingSetup(root) },
		List: func(back, ahead int) ([]booking.Booking, error) {
			book, err := openBookings(root)
			if err != nil {
				return nil, err
			}
			now := time.Now()
			return book.List(now.AddDate(0, 0, -back), now.AddDate(0, 0, ahead))
		},
		Cancel: func(id string, erase bool, by admin.Actor) error {
			return cancelBooking(root, id, erase, signedIn(by))
		},
		Save: func(s *booking.Setup, what string, by admin.Actor) error {
			return saveBookingSetup(root, s, signedIn(by), what)
		},
		Feed: func(off bool, by admin.Actor) (string, error) {
			s, err := loadBookingSetup(root)
			if err != nil {
				return "", err
			}
			if s == nil {
				return "", errors.New("this site takes no bookings to make a feed of")
			}
			return makeBookingFeed(root, s, off, signedIn(by))
		},
		Calendar: func() ([]byte, error) { return bookingCalendar(root) },
	}
}

// bookingCalendar is the bookings ahead as a calendar file, who booked
// included: for the person signed in, to take into their own calendar.
func bookingCalendar(root string) ([]byte, error) {
	setup, err := loadBookingSetup(root)
	if err != nil {
		return nil, err
	}
	book, err := openBookings(root)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ahead := booking.DefaultAhead
	if setup != nil {
		ahead = setup.Ahead()
	}
	list, err := book.List(now.AddDate(0, 0, -1), now.AddDate(0, 0, ahead+1))
	if err != nil {
		return nil, err
	}
	var events []booking.Event
	for _, b := range list {
		title := b.When.Service
		if setup != nil {
			if svc, ok := setup.Service(b.When.Service); ok {
				title = svc.Title
			}
		}
		about := strings.TrimSpace(b.Who.Email + " " + b.Who.Phone)
		if b.Who.Note != "" {
			about += "\n" + b.Who.Note
		}
		events = append(events, booking.Event{UID: b.When.ID + "@quilzo", Start: b.When.Start, End: b.When.End(),
			Summary: title + ": " + b.Who.Name, Description: about, Cancelled: !b.When.Live()})
	}
	return booking.ICS(siteName(root)+" bookings", events, now), nil
}
