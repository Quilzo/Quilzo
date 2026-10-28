// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package newsletter

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// A list taken from another platform, and taken to one.
//
// Every newsletter service exports its list as CSV and imports one, and no
// two agree on the columns: Mailchimp says "Email Address", Substack and
// Ghost "email", MailPoet "status", Buttondown "subscriber_type". What
// matters in each is the same three things — the address, when it joined,
// and whether it still wants mail — so the columns are found by name, and a
// row that says it unsubscribed, bounced or complained is not imported as
// somebody to send to. It is kept as one that left, because that is what
// they said, wherever they said it.
//
// The export is the plainest file every one of those services takes: an
// email column first, then a name, when it joined, and where it agreed.

// Row is one address read from a file.
type Row struct {
	Email, Name string
	At          time.Time
	// Left is a row the other platform says asked to stop, bounced or
	// complained.
	Left bool
	// Skip is a row the other platform says never confirmed: not imported,
	// and not marked as having left either.
	Skip bool
}

// MaxRows bounds an import.
const MaxRows = 200000

var (
	emailCols = []string{"email", "email address", "e-mail", "e-mail address", "emailaddress",
		"email_address", "subscriber email", "subscriber_email", "mail"}
	nameCols  = []string{"name", "full name", "full_name", "fullname", "display name"}
	firstCols = []string{"first name", "first_name", "fname", "firstname", "given name"}
	lastCols  = []string{"last name", "last_name", "lname", "lastname", "surname", "family name"}
	dateCols  = []string{"subscribed_at", "created_at", "optin_time", "confirm_time", "created", "date",
		"date added", "signup date", "subscription date", "subscribed", "joined"}
	statusCols = []string{"status", "subscriber_type", "subscription_status", "state", "type"}
)

// statusLeft and statusSkip are what a status column says, in the words
// the services use.
var (
	statusLeft = map[string]bool{"unsubscribed": true, "cleaned": true, "bounced": true, "complained": true,
		"spam": true, "removed": true, "blocked": true, "inactive": true, "disabled": true}
	statusSkip = map[string]bool{"unconfirmed": true, "pending": true, "unactivated": true}
)

// ReadCSV reads addresses from a list exported by another platform.
func ReadCSV(r io.Reader) ([]Row, error) {
	br := bufio.NewReader(r)
	// A byte-order mark, which spreadsheet programs put first.
	if b, err := br.Peek(3); err == nil && string(b) == "\xef\xbb\xbf" {
		_, _ = br.Discard(3)
	}
	peek, _ := br.Peek(4096)
	line := string(peek)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	// Separated by what the first line is separated by: a semicolon where
	// a spreadsheet's locale writes decimals with a comma, or a tab.
	switch {
	case strings.Count(line, "\t") > strings.Count(line, ","):
		cr.Comma = '\t'
	case strings.Count(line, ";") > strings.Count(line, ","):
		cr.Comma = ';'
	}
	head, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("the file is empty")
	}
	if err != nil {
		return nil, err
	}
	cols := map[string]int{}
	for i, h := range head {
		cols[strings.ToLower(strings.TrimSpace(h))] = i
	}
	find := func(names []string) int {
		for _, n := range names {
			if i, ok := cols[n]; ok {
				return i
			}
		}
		return -1
	}
	email := find(emailCols)
	var rows []Row
	if email < 0 {
		// No header: the first cell with an @ in it, in every row.
		if row, ok := headless(head); ok {
			rows = append(rows, row)
		} else {
			return nil, errors.New("no column is an email address; name one email, or Email Address")
		}
	}
	name, first, last := find(nameCols), find(firstCols), find(lastCols)
	date, status := find(dateCols), find(statusCols)
	subscribed := find([]string{"subscribed_to_emails", "subscribed_to_newsletter", "newsletter", "opted_in", "opt_in"})
	disabled := find([]string{"email_disabled", "unsubscribed"})
	cell := func(rec []string, i int) string {
		if i < 0 || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rows) >= MaxRows {
			return nil, fmt.Errorf("the file has more than %d addresses; split it", MaxRows)
		}
		if email < 0 {
			if row, ok := headless(rec); ok {
				rows = append(rows, row)
			}
			continue
		}
		row := Row{Email: cell(rec, email), Name: cell(rec, name)}
		if row.Email == "" {
			continue
		}
		if row.Name == "" {
			row.Name = strings.TrimSpace(cell(rec, first) + " " + cell(rec, last))
		}
		row.At = parseWhen(cell(rec, date))
		st := strings.ToLower(cell(rec, status))
		row.Left = statusLeft[st] || isFalse(cell(rec, subscribed)) || isTrue(cell(rec, disabled))
		row.Skip = !row.Left && statusSkip[st]
		rows = append(rows, row)
	}
	return rows, nil
}

func headless(rec []string) (Row, bool) {
	for _, c := range rec {
		if c = strings.TrimSpace(c); strings.Contains(c, "@") {
			return Row{Email: c}, true
		}
	}
	return Row{}, false
}

func isFalse(s string) bool {
	switch strings.ToLower(s) {
	case "false", "no", "0", "n":
		return true
	}
	return false
}

func isTrue(s string) bool {
	switch strings.ToLower(s) {
	case "true", "yes", "1", "y":
		return true
	}
	return false
}

func parseWhen(s string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05",
		"2006-01-02 15:04", "2006-01-02", "01/02/2006 15:04", "01/02/2006"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// WriteCSV writes the confirmed addresses as a file other platforms import.
func WriteCSV(w io.Writer, list []Subscriber) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"email", "name", "subscribed_at", "confirmed_at", "source", "consent"}); err != nil {
		return err
	}
	for _, s := range list {
		if s.Confirmed.IsZero() {
			continue
		}
		if err := cw.Write([]string{s.Email, csvSafe(s.Name), s.At.UTC().Format(time.RFC3339),
			s.Confirmed.UTC().Format(time.RFC3339), s.Source, csvSafe(s.Consent)}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe keeps a cell a spreadsheet would read as a formula from being
// one: a name typed as =HYPERLINK(...) is text in this file, and has to
// stay text in whatever opens it.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// Imported is what an import did.
type Imported struct {
	Added, Already, Left, Skipped, Bad int
}

// Import puts rows on the list as confirmed, with consent saying where
// they agreed; rows that left are kept as having left.
func (l *List) Import(rows []Row, consent string, now time.Time) (Imported, error) {
	var out Imported
	for _, r := range rows {
		addr, err := Normalize(r.Email)
		if err != nil {
			out.Bad++
			continue
		}
		switch {
		case r.Left:
			id := l.ID(addr)
			if exists(l.subscriberPath(id)) {
				// On this list already: whatever they said elsewhere, what
				// they said here is the one to keep.
				out.Already++
				continue
			}
			if !l.Left(id) {
				if _, err := l.Remove(id, now); err != nil {
					return out, err
				}
			}
			out.Left++
			continue
		case r.Skip:
			out.Skipped++
			continue
		}
		added, err := l.Add(Subscriber{Email: addr, Name: r.Name, At: r.At, Source: "import",
			Consent: consent, Confirmed: now}, now)
		if err != nil {
			return out, err
		}
		switch {
		case added:
			out.Added++
		case l.Left(l.ID(addr)):
			out.Left++
		default:
			out.Already++
		}
	}
	return out, nil
}
