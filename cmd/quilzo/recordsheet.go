// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/sheet"
)

// Spreadsheets and calendars in and out of a collection (internal/sheet):
// `quilzo records import` and `export`, `quilzo events import`, and the
// Data screen's upload and download, which call the same functions, so
// what one brings in the others would too.

// bringOptions says how a file is brought into a collection.
type bringOptions struct {
	// key is the field matching rows to records already there: a field,
	// "none" for none, or "" for the type's page link when it has one.
	key     string
	dates   string
	mapping map[string]string
	skipBad bool
	dryRun  bool
	// pictures fetches the pictures rows name by address into the library.
	pictures bool
}

// broughtRows is what bringing a file in did, or would do.
type broughtRows struct {
	Collection string `json:"collection"`
	From       string `json:"from"`
	Rows       int    `json:"rows"`
	New        int    `json:"new"`
	Updated    int    `json:"updated"`
	// Unchanged counts the rows that matched a record and would change none
	// of its fields, which are not written again.
	Unchanged int             `json:"unchanged"`
	Columns   []sheet.Column  `json:"columns,omitempty"`
	Problems  []sheet.Problem `json:"problems,omitempty"`
	Notes     []string        `json:"notes,omitempty"`
	DryRun    bool            `json:"dry_run,omitempty"`
}

// Kinds of file a collection takes.
const (
	fromSheet    = "sheet"
	fromJSON     = "json"
	fromCalendar = "calendar"
)

// fileKind is what a file is, by what it holds rather than its name.
func fileKind(body []byte) string {
	head := bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	switch {
	case bytes.HasPrefix(bytes.ToUpper(head[:min(len(head), 15)]), []byte("BEGIN:VCALENDAR")):
		return fromCalendar
	case bytes.HasPrefix(head, []byte("[")):
		return fromJSON
	}
	return fromSheet
}

// collectionType is the type bound to a collection, and the types, read
// once for every row's check.
func collectionType(root, coll string) (*schema.Type, *schema.Store, error) {
	st, err := schema.Load(root)
	if err != nil {
		return nil, nil, err
	}
	if name, bound := st.Collections[coll]; bound {
		if t, ok := st.Registry.Get(name); ok {
			return &t, st, nil
		}
		return nil, nil, fmt.Errorf("%s is bound to the type %s, which no longer exists", coll, name)
	}
	return nil, st, nil
}

// slugAndTitle are a type's page link field and the field it is made
// from, when it has them.
func slugAndTitle(t *schema.Type) (string, string) {
	if t == nil {
		return "", ""
	}
	slug, title, firstText := "", "", ""
	for _, f := range t.Fields {
		switch {
		case f.Kind == schema.Slug && slug == "":
			slug = f.Name
		case f.Kind == schema.Text && (f.Name == "title" || f.Name == "name" || f.Name == "heading") && title == "":
			title = f.Name
		case f.Kind == schema.Text && firstText == "" && f.AltFor == "":
			firstText = f.Name
		}
	}
	if title == "" {
		title = firstText
	}
	return slug, title
}

// keyField is the field rows are matched by.
func keyField(t *schema.Type, asked string) (string, error) {
	switch asked {
	case "none":
		return "", nil
	case "":
		slug, _ := slugAndTitle(t)
		return slug, nil
	}
	if t != nil {
		for _, f := range t.Fields {
			if f.Name == asked {
				return asked, nil
			}
		}
		return "", fmt.Errorf("%s has no field %s to match rows by", t.Name, asked)
	}
	return asked, nil
}

// fileRows reads a file as rows for a collection of type t.
func fileRows(root, coll string, body []byte, t *schema.Type, opts bringOptions) (string, []sheet.Row,
	[]sheet.Column, []string, error) {

	switch kind := fileKind(body); kind {
	case fromCalendar:
		if t == nil || !declares(t, "title") || !declares(t, "date") {
			return kind, nil, nil, nil, fmt.Errorf("a calendar is brought into events: %s has no title and "+
				"date to put them in (quilzo events setup makes a collection that has)", coll)
		}
		rows, notes, err := sheet.FromCalendar(body, sheet.CalendarOptions{Collection: coll, Type: t,
			Zone: siteZone(root)(), Now: time.Now()})
		return kind, rows, nil, notes, err
	case fromJSON:
		rows, err := jsonRows(body, t)
		return kind, rows, nil, nil, err
	default:
		sh, err := sheet.Read(body, sheet.Options{Type: t, Map: opts.mapping, Dates: opts.dates})
		if err != nil {
			return kind, nil, nil, nil, err
		}
		return kind, sh.Rows, sh.Columns, sh.Notes, nil
	}
}

func declares(t *schema.Type, field string) bool {
	for _, f := range t.Fields {
		if f.Name == field {
			return true
		}
	}
	return false
}

// jsonRows reads a JSON list of records. An "id" the type does not declare
// is the record's id, as a JSON export writes it; and so is any "id" of a
// record that gives its own id as well, under "fields" (an object holding
// id alone) or under sheet.OwnID, as an export writes that. Its own id
// given as null is a record that has none.
func jsonRows(body []byte, t *schema.Type) ([]sheet.Row, error) {
	var list []map[string]any
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("it must be a JSON list of records: %w", err)
	}
	if len(list) > sheet.MaxRows {
		return nil, fmt.Errorf("it has more than %d records: bring it in parts", sheet.MaxRows)
	}
	idIsField := t != nil && declares(t, "id")
	rows := make([]sheet.Row, 0, len(list))
	for i, f := range list {
		row := sheet.Row{Where: fmt.Sprintf("record %d", i+1), Fields: f}
		own, hasOwn := ownID(f)
		if id, ok := f["id"].(string); ok && (!idIsField || hasOwn) {
			row.ID = id
			delete(f, "id")
		}
		switch {
		case hasOwn && own == nil:
			// It says it has none: the id beside it is the store's, and
			// the record's own is cleared, as an emptied cell clears one.
			row.Clear = append(row.Clear, "id")
		case hasOwn:
			f["id"] = own
		}
		if f == nil {
			row.Problems = []string{"it is not a record"}
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, errors.New("it holds no records")
	}
	return rows, nil
}

// ownID takes out of a JSON record the record's own field named id, as an
// export writes it beside the store's id: under "fields", an object that
// holds id alone, or under sheet.OwnID when the record has a field of its
// own called fields.
func ownID(f map[string]any) (any, bool) {
	if v, ok := f[sheet.OwnID]; ok {
		delete(f, sheet.OwnID)
		return v, true
	}
	if nest, ok := f["fields"].(map[string]any); ok && len(nest) == 1 {
		if v, ok := nest["id"]; ok {
			delete(f, "fields")
			return v, true
		}
	}
	return nil, false
}

// bringFile brings a spreadsheet, a JSON list or a calendar into a
// collection: each row matched to the record it is, checked by the
// collection's type, and written in one commit; or, dry, says what would
// be.
func bringFile(ctx context.Context, root, coll, name string, body []byte, opts bringOptions,
	caller *Caller) (*broughtRows, error) {

	if err := collection.ValidName(coll); err != nil {
		return nil, err
	}
	t, st, err := collectionType(root, coll)
	if err != nil {
		return nil, err
	}
	kind, rows, cols, notes, err := fileRows(root, coll, body, t, opts)
	if err != nil {
		return &broughtRows{Collection: coll, From: kind, Notes: notes}, fmt.Errorf("%s: %w", name, err)
	}
	key := ""
	if kind != fromCalendar {
		if key, err = keyField(t, opts.key); err != nil {
			return nil, err
		}
	}
	ownPictures(root, t, rows)
	s, err := open(root)
	if err != nil {
		return nil, err
	}
	tree, err := draftTree(s)
	if err != nil {
		return nil, err
	}
	idx, err := collection.Build(s, tree, coll, nil)
	if err != nil {
		return nil, err
	}
	slug, title := slugAndTitle(t)
	plan := sheet.Merge{Collection: coll, Key: key, Existing: idx.Records, Slug: slug, Title: title,
		SkipBad: opts.skipBad, Check: func(f map[string]any) error {
			if p := st.CheckRecord(coll, f); len(p) > 0 {
				return &schema.Invalid{Where: coll, Problems: p}
			}
			return nil
		}}.Plan(rows)
	out := &broughtRows{Collection: coll, From: kind, Rows: len(rows), New: plan.New, Updated: plan.Updated,
		Unchanged: plan.Unchanged, Columns: cols, Problems: plan.Problems, Notes: notes, DryRun: opts.dryRun}
	if plan.Refused() {
		what := "nothing was brought in"
		if opts.dryRun {
			what = "nothing would be brought in"
		}
		return out, fmt.Errorf("%s: %s, because %s", name, what, plan.Summary())
	}
	if opts.dryRun || len(plan.Records) == 0 {
		return out, nil
	}
	if opts.pictures {
		out.Problems = append(out.Problems, plan.Fetch(sheet.Pictures(t), pictureFetcher(ctx, root))...)
	} else {
		left := 0
		for field, alt := range sheet.Pictures(t) {
			for _, r := range plan.Records {
				if v, _ := r.Fields[field].(string); v != "" && !sheet.IsMediaID(v) {
					delete(r.Fields, field)
					delete(r.Fields, alt)
					left++
				}
			}
		}
		if left > 0 {
			out.Notes = append(out.Notes, fmt.Sprintf("%d picture(s) named by address were left out, as asked", left))
		}
	}
	err = s.WithRefLock(func() error {
		// Against the draft as it is now, which another hand may have
		// changed while the pictures were fetched.
		tree, err := draftTree(s)
		if err != nil {
			return err
		}
		next, _, err := collection.PutMany(s, tree, coll, plan.Records, time.Now())
		if err != nil {
			return err
		}
		return commitTreeNoLock(s, next, fmt.Sprintf("records: bring %d into %s", len(plan.Records), coll),
			caller.Name)
	})
	if err != nil {
		return out, err
	}
	record(root, caller.auditRecord("records.import", "/"+coll, audit.Success, map[string]string{
		"collection": coll, "from": kind, "new": fmt.Sprint(plan.New), "updated": fmt.Sprint(plan.Updated)}))
	emitEvent(root, event.Event{Type: event.RecordChanged, Subject: coll}, caller)
	return out, nil
}

// ownPictures reads a picture a row names by the address the library serves
// it at as the file it is, before the rows are weighed against the records
// they are.
//
// An export names a picture by where it can be fetched from, when the site
// has an address of its own, and that was read back as the file only when
// pictures were fetched, after the rows had been weighed: every record with
// a picture was "changed" by a sheet that changed none of them, written
// again and its updated time moved. Brought in without fetching pictures,
// as the Data screen does unless asked, the address was "left out, as
// asked", and the record lost the picture it had.
func ownPictures(root string, t *schema.Type, rows []sheet.Row) {
	pictures := sheet.Pictures(t)
	if len(pictures) == 0 {
		return
	}
	lib, err := openMedia(root)
	if err != nil {
		return
	}
	for _, row := range rows {
		for field := range pictures {
			if raw, _ := row.Fields[field].(string); raw != "" {
				if id := libraryPicture(lib, raw); id != "" {
					row.Fields[field] = id
				}
			}
		}
	}
}

// libraryPicture is the file in the library that raw names by the address
// it is served at (…/media/<its id>), or "" when raw is no such address or
// the library has no such file.
func libraryPicture(lib *medialib.Library, raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || lib == nil {
		return ""
	}
	if dir, id := path.Split(u.Path); strings.HasSuffix(dir, "/media/") && sheet.IsMediaID(id) {
		if _, err := lib.Stat(id); err == nil {
			return id
		}
	}
	return ""
}

// pictureFetcher keeps a picture a row names: one already in the library,
// by its id or the address it is served at, as it is; one on the web,
// fetched into the library as `media get` would.
func pictureFetcher(ctx context.Context, root string) func(raw, alt string) (string, error) {
	client := fetch.For("import")
	lib, _ := openMedia(root)
	return func(raw, alt string) (string, error) {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return "", fmt.Errorf("%q is not an address", raw)
		}
		if id := libraryPicture(lib, raw); id != "" {
			return id, nil
		}
		if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
			return "", fmt.Errorf("%q is not an address on the web", raw)
		}
		if strings.TrimSpace(alt) == "" {
			return "", errors.New("it needs words for what it shows, in the column for them")
		}
		res, err := client.Get(ctx, u.String())
		if err != nil {
			return "", err
		}
		f, err := keepFetched(root, res, alt)
		if err != nil {
			return "", err
		}
		return f.ID, nil
	}
}

// sheetOf is a collection's records, in its draft, as a spreadsheet or a
// JSON list, and how many.
func sheetOf(root, coll, format string, bom bool) ([]byte, int, error) {
	if err := collection.ValidName(coll); err != nil {
		return nil, 0, err
	}
	t, _, err := collectionType(root, coll)
	if err != nil {
		return nil, 0, err
	}
	s, err := open(root)
	if err != nil {
		return nil, 0, err
	}
	tree, err := draftTree(s)
	if err != nil {
		return nil, 0, err
	}
	idx, err := collection.Build(s, tree, coll, nil)
	if err != nil {
		return nil, 0, err
	}
	if len(idx.Records) == 0 && t == nil {
		return nil, 0, fmt.Errorf("there is no collection %s: quilzo records collections lists them", coll)
	}
	if format == "json" {
		declaresID := t != nil && declares(t, "id")
		list := make([]map[string]any, 0, len(idx.Records))
		for _, r := range idx.Records {
			row := map[string]any{"id": r.ID}
			for k, v := range r.Fields {
				if k != "id" {
					row[k] = v
				}
			}
			// The record's own id, which the store's took the place of:
			// it was left out, and an export brought back lost it. Said
			// for every record of a type that declares id, as null for
			// one that has none: an id with nothing beside it is read as
			// that type's field, so such a record came back in as a new
			// one with the store's id for its own. And said, beside it, for
			// every record with a field of its own called fields: one that
			// was an object holding id alone, in a record with no id of
			// its own, was read coming back as the record's own id.
			own, has := r.Fields["id"]
			_, taken := row["fields"]
			switch {
			case taken:
				row[sheet.OwnID] = own
			case has || declaresID:
				row["fields"] = map[string]any{"id": own}
			}
			list = append(list, row)
		}
		body, err := json.MarshalIndent(list, "", "  ")
		return append(body, '\n'), len(list), err
	}
	opts := sheet.WriteOptions{BOM: bom}
	if base := siteBaseURL(root); base != "" {
		opts.Picture = func(id string) string { return base + "/media/" + id }
	}
	return sheet.Write(t, idx.Records, opts), len(idx.Records), nil
}

// broughtForAdmin is what bringing a file in did, as the Data screen
// says it.
func broughtForAdmin(b *broughtRows) *admin.BringResult {
	if b == nil {
		return nil
	}
	out := &admin.BringResult{New: b.New, Updated: b.Updated, Unchanged: b.Unchanged, Notes: b.Notes}
	for _, c := range b.Columns {
		if c.Field == "" && !c.ID {
			out.Columns = append(out.Columns, fmt.Sprintf("%q %s", c.Header, c.Note))
		}
	}
	for _, p := range b.Problems {
		out.Problems = append(out.Problems, p.String())
	}
	return out
}

// sayBrought tells a person what bringing a file in did.
func sayBrought(b *broughtRows, name string) {
	if b == nil {
		return
	}
	for _, c := range b.Columns {
		switch {
		case c.ID:
			w.Human("  %-24s %s\n", c.Header, "the record's id")
		case c.Field == "":
			w.Human("  %-24s %s%s%s\n", c.Header, dim, c.Note, reset)
		case c.Note != "":
			w.Human("  %-24s → %s %s(%s)%s\n", c.Header, c.Field, dim, c.Note, reset)
		default:
			w.Human("  %-24s → %s\n", c.Header, c.Field)
		}
	}
	for _, n := range b.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	verb := "brought"
	if b.DryRun {
		verb = "would bring"
	}
	if b.New+b.Updated > 0 {
		w.Human("%s %d record(s) into %s from %s: %d new, %d changed", verb, b.New+b.Updated, b.Collection, name,
			b.New, b.Updated)
		if b.Unchanged > 0 {
			w.Human(", %d as they were", b.Unchanged)
		}
		w.Human("\n")
	} else if b.Unchanged > 0 {
		w.Human("%d record(s) in %s are as %s has them already: nothing to bring in\n", b.Unchanged, b.Collection, name)
	}
	for i, p := range b.Problems {
		if i == 20 {
			w.Human("  %sand %d more%s\n", dim, len(b.Problems)-20, reset)
			break
		}
		w.Human("  %s%s%s\n", yellow, p, reset)
	}
	switch {
	case b.DryRun:
		w.Human("%snothing was written: run it again without --dry-run to bring them in%s\n", dim, reset)
	case b.New+b.Updated > 0:
		w.Human("%sthey are in the draft: look them over on the Data screen, and publish to put them on the site%s\n",
			dim, reset)
	}
}
