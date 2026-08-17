package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Records on the command line.
//
// The same operations the API and the admin offer, because a feature that
// exists on one surface and not the others is a feature somebody cannot
// automate, or cannot see, depending on which one they are standing on.

func cmdRecords(root string, args []string) error {
	if len(args) == 0 {
		return recordsCollections(root)
	}
	switch args[0] {
	case "collections":
		return recordsCollections(root)
	case "list":
		return recordsList(root, args[1:])
	case "get":
		return recordsGet(root, args[1:])
	case "add":
		return recordsAdd(root, args[1:])
	case "delete":
		return recordsDelete(root, args[1:])
	case "import":
		return recordsImport(root, args[1:])
	default:
		return fmt.Errorf("unknown records command %q; try collections, "+
			"list, get, add, delete or import", args[0])
	}
}

// draftTree resolves the tree records are read from and written against.
func draftTree(s *store.Store) (string, error) {
	cid := s.GetRef(site.RefDraft)
	if cid == "" {
		cid = s.GetRef(site.RefLive)
	}
	if cid == "" {
		return "", nil
	}
	c, err := s.GetCommit(cid)
	if err != nil {
		return "", err
	}
	return c.Tree, nil
}

// commitTree makes a tree the new draft.
//
// Under the ref lock and against the draft the caller read, so two people
// writing records at once cannot silently lose one of the writes — the same
// compare-and-swap every other write in this program goes through.
func commitTree(root string, s *store.Store, tree, message, author string) error {
	return s.WithRefLock(func() error {
		parent := s.GetRef(site.RefDraft)
		if parent == "" {
			parent = s.GetRef(site.RefLive)
		}
		var parents []string
		if parent != "" {
			parents = []string{parent}
		}
		cid, err := s.PutCommit(store.Commit{
			Tree: tree, Parents: parents, Message: message,
			Author: author, At: time.Now().Unix(),
		})
		if err != nil {
			return err
		}
		return s.SetRef(site.RefDraft, cid)
	})
}

func recordsCollections(root string) error {
	s, err := open(root)
	if err != nil {
		return err
	}
	tree, err := draftTree(s)
	if err != nil {
		return err
	}
	names, err := collection.Names(s, tree)
	if err != nil {
		return err
	}
	type row struct {
		Name  string `json:"name"`
		Count int    `json:"records"`
	}
	var rows []row
	for _, n := range names {
		c, _ := collection.Count(s, tree, n)
		rows = append(rows, row{n, c})
	}
	if w.JSON(rows) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("no collections\n")
		w.Human("  %sa collection is many records of one shape, which is what "+
			"an application holds%s\n", dim, reset)
		w.Human("  %squilzo records add devices hostname=laptop-14%s\n", dim, reset)
		return nil
	}
	for _, r := range rows {
		w.Human("  %-24s %d record(s)\n", r.Name, r.Count)
	}
	return nil
}

func recordsList(root string, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	where := fs.String("where", "", "field=value filters, comma separated")
	contains := fs.String("contains", "", "field=substring filters")
	sortBy := fs.String("sort", "", "field to order by")
	desc := fs.Bool("desc", false, "reverse the order")
	limit := fs.Int("limit", collection.DefaultLimit, "how many")
	offset := fs.Int("offset", 0, "where to start")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: quilzo records list <collection> [--where field=value]")
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	tree, err := draftTree(s)
	if err != nil {
		return err
	}
	q := collection.Query{
		Equals: pairs(*where), Contains: stringPairs(*contains),
		Sort: *sortBy, Descending: *desc, Limit: *limit, Offset: *offset,
	}
	recs, total, err := collection.List(s, tree, rest[0], q)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"total": total, "records": recs}) {
		return nil
	}
	if total == 0 {
		w.Human("no records match\n")
		return nil
	}
	for _, r := range recs {
		w.Human("  %s%s%s\n", bold, r.ID[:12], reset)
		for _, k := range sortedKeys(r.Fields) {
			w.Human("    %-16s %v\n", k, r.Fields[k])
		}
	}
	w.Human("\n  %d of %d\n", len(recs), total)
	return nil
}

func recordsGet(root string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: quilzo records get <collection> <id>")
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	tree, err := draftTree(s)
	if err != nil {
		return err
	}
	r, err := collection.Get(s, tree, args[0], args[1])
	if err != nil {
		return err
	}
	if w.JSON(r) {
		return nil
	}
	w.Human("%s%s%s\n", bold, r.ID, reset)
	for _, k := range sortedKeys(r.Fields) {
		w.Human("  %-16s %v\n", k, r.Fields[k])
	}
	w.Human("  %screated %s · updated %s%s\n", dim,
		time.Unix(r.Created, 0).Format("2 Jan 2006 15:04"),
		time.Unix(r.Updated, 0).Format("2 Jan 2006 15:04"), reset)
	return nil
}

func recordsAdd(root string, args []string) error {
	// Split by shape rather than by position. leadingArgs takes a fixed number
	// of positional arguments, and this command has a variable number of them:
	// with it, every field=value pair after the collection name was handed to
	// the flag parser, which ignored them — so the command reported "a record
	// with no fields" while looking at four of them.
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	id := fs.String("id", "", "update this record instead of creating one")
	fromFile := fs.String("from", "", "read fields from a JSON file")
	var rest, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// A flag that takes a value consumes the next argument, unless it
			// was written as --flag=value.
			if !strings.Contains(a, "=") && i+1 < len(args) &&
				!strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		rest = append(rest, a)
	}
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) < 1 {
		return fmt.Errorf(
			"usage: quilzo records add <collection> field=value [...]\n" +
				"   or: quilzo records add <collection> --from record.json")
	}
	coll := rest[0]

	fields := map[string]any{}
	if *fromFile != "" {
		body, err := os.ReadFile(*fromFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(body, &fields); err != nil {
			return fmt.Errorf("%s: %w", *fromFile, err)
		}
	}
	for _, kv := range rest[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("%q is not field=value", kv)
		}
		fields[k] = typed(v)
	}
	if len(fields) == 0 {
		return fmt.Errorf("a record with no fields is not a record")
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	tree, err := draftTree(s)
	if err != nil {
		return err
	}
	next, rec, err := collection.Put(s, tree, coll,
		collection.Record{ID: *id, Fields: fields}, time.Now())
	if err != nil {
		return err
	}
	if err := commitTree(root, s, next, "records: write "+coll, caller.Name); err != nil {
		return err
	}
	record(root, caller.auditRecord("records.write", "/"+coll, audit.Success,
		map[string]string{"collection": coll, "record": rec.ID[:12]}))

	if w.JSON(rec) {
		return nil
	}
	w.Human("%s  %s\n", rec.ID, coll)
	return nil
}

func recordsDelete(root string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: quilzo records delete <collection> <id>")
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	tree, err := draftTree(s)
	if err != nil {
		return err
	}
	next, err := collection.Delete(s, tree, args[0], args[1])
	if err != nil {
		return err
	}
	if err := commitTree(root, s, next, "records: delete "+args[0],
		caller.Name); err != nil {
		return err
	}
	record(root, caller.auditRecord("records.delete", "/"+args[0],
		audit.Success, map[string]string{
			"collection": args[0], "record": args[1][:12]}))
	w.Human("deleted\n")
	return nil
}

// recordsImport loads a JSON array in one write.
//
// One commit for the whole file rather than one per record: the cost of a
// commit is paid per commit, so importing ten thousand records one at a time
// pays for ten thousand tree rebuilds and ten thousand ref moves.
func recordsImport(root string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: quilzo records import <collection> <file.json>")
	}
	body, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		return fmt.Errorf("%s must be a JSON array of objects: %w", args[1], err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("%s holds no records", args[1])
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	tree, err := draftTree(s)
	if err != nil {
		return err
	}
	batch := make([]collection.Record, 0, len(rows))
	for _, f := range rows {
		batch = append(batch, collection.Record{Fields: f})
	}
	next, out, err := collection.PutMany(s, tree, args[0], batch, time.Now())
	if err != nil {
		return err
	}
	if err := commitTree(root, s, next,
		fmt.Sprintf("records: import %d into %s", len(out), args[0]),
		caller.Name); err != nil {
		return err
	}
	record(root, caller.auditRecord("records.import", "/"+args[0],
		audit.Success, map[string]string{
			"collection": args[0], "count": fmt.Sprintf("%d", len(out))}))
	w.Human("imported %d record(s) into %s\n", len(out), args[0])
	return nil
}

// typed turns a command-line value into the type it looks like.
//
// A field typed as 443 should compare equal to a stored 443, and one typed as
// "true" should be a boolean. Without this every value is a string, every
// numeric filter silently matches nothing, and the store looks broken rather
// than the input being untyped.
func typed(v string) any {
	switch v {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	var n float64
	if err := json.Unmarshal([]byte(v), &n); err == nil {
		return n
	}
	return v
}

func pairs(s string) map[string]any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]any{}
	for _, kv := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[strings.TrimSpace(k)] = typed(strings.TrimSpace(v))
		}
	}
	return out
}

func stringPairs(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStringsInPlace(out)
	return out
}

func sortStringsInPlace(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// commitTreeNoLock makes a tree the draft for a caller already inside the ref
// lock.
//
// The API holds the lock across its own read, its If-Match comparison and this
// write, so taking it again here would deadlock — the same reentrancy the
// store's own locking was bitten by twice.
func commitTreeNoLock(s *store.Store, tree, message, author string) error {
	parent := s.GetRef(site.RefDraft)
	if parent == "" {
		parent = s.GetRef(site.RefLive)
	}
	var parents []string
	if parent != "" {
		parents = []string{parent}
	}
	cid, err := s.PutCommit(store.Commit{
		Tree: tree, Parents: parents, Message: message,
		Author: author, At: time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	return s.SetRef(site.RefDraft, cid)
}
