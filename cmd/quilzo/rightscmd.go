package main

import (
	"flag"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The rights gate: what is about to be published, and may it be.
//
// Runs with the other content gates at publish, and answers early through
// `quilzo rights`. See internal/media/rights.go for why an image licence is a
// publish window rather than a text box.

// LapseWindow is how far ahead a licence is reported before it ends.
//
// Sixty days, chosen so that a renewal involving somebody else's legal
// department has time to happen. Too short and the report arrives as an
// emergency; too long and every asset is permanently "lapsing" and the report
// means nothing.
const LapseWindow = 60 * 24 * time.Hour

// reAssetID matches a stored file's address.
//
// A media reference is not a typed field — content says whatever it says, and
// an image lives in "image" on one type and "avatar" on another. What is
// invariant is the value: a file is addressed by the SHA-256 of its bytes, so
// any field holding 64 hex characters that the library also holds is a
// reference to that file. Matching on the value rather than the field name is
// what makes this work on content types nobody has written yet.
var reAssetID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Use is one asset, and everything that points at it.
type Use struct {
	File  media.File
	Where []string
}

// assetUses finds every asset referenced by a commit, and by what.
func assetUses(s *store.Store, lib *medialib.Library, ref string) (
	map[string]*Use, error) {

	commit := s.GetRef(ref)
	if commit == "" {
		commit = ref
	}
	content := map[string]map[string]any{}

	pages, err := site.PagesAt(s, ref)
	if err != nil {
		return nil, err
	}
	for name, body := range pages {
		if m, ok := body.(map[string]any); ok {
			content[name] = m
		}
	}
	// Records too. In a shop the product photograph is on a record, and a
	// gate that read only pages would clear a catalogue full of expired
	// licences — the same shape of miss the claim gate had.
	c, cerr := s.GetCommit(commit)
	if cerr != nil {
		return nil, cerr
	}
	if c.Tree != "" {
		cache := collection.NewCache()
		names, nerr := cache.Names(s, c.Tree)
		if nerr != nil {
			return nil, fmt.Errorf(
				"the collections could not be listed, so no record's images "+
					"were checked: %w", nerr)
		}
		for _, name := range names {
			idx, ierr := cache.For(s, c.Tree, name)
			if ierr != nil {
				return nil, fmt.Errorf(
					"collection %s could not be read, so nothing in it was "+
						"checked: %w", name, ierr)
			}
			recs, _ := idx.Query(collection.Query{})
			for _, rec := range recs {
				content[name+"/"+rec.ID] = rec.Fields
			}
		}
	}

	uses := map[string]*Use{}
	for where, fields := range content {
		for _, id := range assetIDsIn(fields) {
			u, seen := uses[id]
			if !seen {
				f, ferr := lib.Stat(id)
				if ferr != nil {
					// A value shaped like an address that the library does not
					// hold is not a media reference — it is a hash of
					// something else, and treating it as a missing asset would
					//report a false alarm on every content hash somebody stores.
					continue
				}
				u = &Use{File: f}
				uses[id] = u
			}
			u.Where = append(u.Where, where)
		}
	}
	for _, u := range uses {
		sort.Strings(u.Where)
	}
	return uses, nil
}

// assetIDsIn collects every value in one piece of content that could be an
// address, including inside lists.
func assetIDsIn(fields map[string]any) []string {
	var out []string
	add := func(v any) {
		if s, ok := v.(string); ok && reAssetID.MatchString(s) {
			out = append(out, s)
		}
	}
	for _, v := range fields {
		switch t := v.(type) {
		case []any:
			for _, item := range t {
				add(item)
			}
		default:
			add(v)
		}
	}
	sort.Strings(out)
	return out
}

// RightsReport is what the gate found.
type RightsReport struct {
	Expired    []*Use
	Lapsing    []*Use
	Undeclared []*Use
	Checked    int
}

// Blocking reports whether anything here must stop a publication.
func (r RightsReport) Blocking() int { return len(r.Expired) }

func checkRights(s *store.Store, lib *medialib.Library, ref string,
	at time.Time) (RightsReport, error) {

	uses, err := assetUses(s, lib, ref)
	if err != nil {
		return RightsReport{}, err
	}
	var rep RightsReport
	rep.Checked = len(uses)
	ids := make([]string, 0, len(uses))
	for id := range uses {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := uses[id]
		switch {
		case u.File.Rights.Expired(at):
			rep.Expired = append(rep.Expired, u)
		case u.File.Rights.Lapsing(at, LapseWindow):
			rep.Lapsing = append(rep.Lapsing, u)
		case !u.File.Rights.Declared():
			rep.Undeclared = append(rep.Undeclared, u)
		}
	}
	return rep, nil
}

func describeUse(u *Use) string {
	name := u.File.Name
	if name == "" {
		name = shortID(u.File.ID)
	}
	where := strings.Join(u.Where, ", ")
	if len(u.Where) > 3 {
		where = strings.Join(u.Where[:3], ", ") +
			fmt.Sprintf(" and %d more", len(u.Where)-3)
	}
	return fmt.Sprintf("%s — used by %s", name, where)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func printRights(rep RightsReport, at time.Time) {
	for _, u := range rep.Expired {
		until, _ := u.File.Rights.UntilTime()
		fmt.Printf("  %s%s%s\n", red, describeUse(u), reset)
		fmt.Printf("      %spermission ended %s%s\n", dim,
			until.Format("2 January 2006"), reset)
	}
	for _, u := range rep.Lapsing {
		until, _ := u.File.Rights.UntilTime()
		days := int(until.Sub(at).Hours() / 24)
		fmt.Printf("  %s%s%s\n", yellow, describeUse(u), reset)
		fmt.Printf("      %spermission ends %s, in %d day(s) — renewable now, "+
			"and not afterwards%s\n", dim, until.Format("2 January 2006"),
			days, reset)
	}
	for _, u := range rep.Undeclared {
		fmt.Printf("  %s%s%s\n", dim, describeUse(u), reset)
		fmt.Printf("      %snobody has said what permits publishing this%s\n",
			dim, reset)
	}
}

// rightsSet records permission for one file.
//
// A separate verb from the report, because they are different privileges: a
// person who may see that a licence is lapsing is not thereby a person who may
// change the date it lapses on.
func rightsSet(root string, args []string) error {
	// The id comes off the front before the flags are parsed.
	//
	// Go's flag package stops at the first non-flag argument, so
	// `rights set ID --until ...` parses zero flags and hands back three
	// positionals — silently, with every flag left at its default. That is
	// how the first live run of this recorded nothing and reported success.
	var id string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("rights set", flag.ContinueOnError)
	licence := fs.String("licence", "", "what permits publishing this")
	holder := fs.String("holder", "", "who owns the underlying work")
	until := fs.String("until", "", "when permission ends (YYYY-MM-DD; \"never\" clears it)")
	note := fs.String("note", "", "restrictions that do not fit a field")
	token := fs.String("token", "", "authenticate as the holder of this token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Anything left over is a second id, or a typo. Refused rather than
	// ignored: "rights set A B --until X" silently recording against only A
	// is the kind of half-done write nobody notices.
	if id == "" || len(fs.Args()) > 0 {
		return fmt.Errorf(
			"quilzo rights set ID --licence NAME --holder WHO " +
				"--until YYYY-MM-DD\n  one id, and the flags after it")
	}
	caller := resolveCaller(root, *token)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		record(root, caller.auditRecord("rights.set", id, audit.Denied,
			map[string]string{"reason": "authorisation"}))
		return err
	}

	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	f, body, err := lib.Get(id)
	if err != nil {
		return err
	}
	r := f.Rights
	if *licence != "" {
		r.Licence = *licence
	}
	if *holder != "" {
		r.Holder = *holder
	}
	if *note != "" {
		r.Note = *note
	}
	switch {
	case *until == "never":
		r.Until = 0
	case *until != "":
		// Parsed as UTC and kept there. A licence date comes off a contract
		// and is a calendar date, not an instant where the server is standing.
		when, perr := time.ParseInLocation("2006-01-02", *until, time.UTC)
		if perr != nil {
			return fmt.Errorf("--until wants YYYY-MM-DD: %w", perr)
		}
		// End of that day, because a licence "until 31 December" runs through
		// the 31st. Reading it as midnight on the 31st takes a day off every
		// term somebody types.
		r.Until = when.Add(24*time.Hour - time.Second).Unix()
	}
	if verr := r.Validate(time.Now()); verr != nil {
		return verr
	}
	f.Rights = r
	if perr := lib.Put(f, body); perr != nil {
		return perr
	}
	record(root, caller.auditRecord("rights.set", f.ID, audit.Success,
		map[string]string{"licence": r.Licence, "holder": r.Holder,
			"state": r.State(time.Now(), LapseWindow)}))
	fmt.Printf("%s: %s\n", shortID(f.ID), r.State(time.Now(), LapseWindow))
	if until, ok := r.UntilTime(); ok {
		fmt.Printf("  %spermission ends %s%s\n", dim,
			until.Format("2 January 2006"), reset)
	}
	return nil
}

func cmdRights(root string, args []string) error {
	if len(args) > 0 && args[0] == "set" {
		return rightsSet(root, args[1:])
	}
	ref := site.RefDraft
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		ref = args[0]
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	at := time.Now()
	rep, err := checkRights(s, lib, ref, at)
	if err != nil {
		return err
	}
	if rep.Checked == 0 {
		fmt.Printf("  %sno images are used by this content%s\n", dim, reset)
		return nil
	}
	if len(rep.Expired)+len(rep.Lapsing)+len(rep.Undeclared) == 0 {
		fmt.Printf("%s%d image(s) in use, every one of them cleared%s\n",
			green, rep.Checked, reset)
		return nil
	}
	printRights(rep, at)
	fmt.Printf("\n  %s%d image(s) in use: %d expired, %d lapsing within %d "+
		"days, %d undeclared%s\n", dim, rep.Checked, len(rep.Expired),
		len(rep.Lapsing), int(LapseWindow.Hours()/24), len(rep.Undeclared), reset)
	if rep.Blocking() > 0 {
		return fmt.Errorf(
			"%d image(s) are published under permission that has ended",
			rep.Blocking())
	}
	return nil
}
