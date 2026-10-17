// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/demo"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/research"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// Installing a whole application, so somebody can see one.
//
// A starter template shows what a page looks like. It cannot show what this
// tool is for, because that only appears with several features working at once
// — a query over records, a page embedding it, a navigation that will not point
// at nothing, content with a date after which it stops being served, and a form
// the public process can write to and cannot read.
//
// So this installs Marginalia: the demonstration in internal/demo, which was
// built through the admin interface before it was written down.
//
// # It refuses to run over anything
//
// Not a flag, not a confirmation prompt — a refusal. This writes content types,
// listings, menus, vocabularies, forms, a media library and a draft, and
// running it into somebody's site would overwrite the parts of their setup that
// share a name with the parts of this one. The store it wants is an empty one.
//
// # It can be taken back out
//
// The install writes down what it wrote, and `quilzo demo remove` takes back
// exactly that, keeping anything somebody changed since. See demoremove.go.

// demoSiteURL is where the demonstration tells its reader to run the site,
// and so the address it is configured with when it has none.
const demoSiteURL = "http://127.0.0.1:8081"

func cmdDemo(root string, args []string) (err error) {
	if len(args) > 0 && args[0] == "remove" {
		return demoRemove(root, args[1:])
	}
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	// The name, so the demonstration can be the starting point for a real site
	// rather than something to find and rename afterwards.
	//
	// It must never be empty. The template prints site.name in the header link
	// and the <title>, and the accessibility gate renders with the same context
	// the server does — so a blank name is an empty link on every page and a
	// blocking failure on all of them. That happened once; the flag defaults to
	// the demonstration's own name and refuses a blank rather than defaulting
	// silently, because a name somebody typed as spaces is a name they meant to
	// type.
	siteName := fs.String("name", "", "what to call the site (default: the demonstration's own name)")
	tplDir := fs.String("templates", "templates",
		"where to write page.html and site.css")
	publish := fs.Bool("publish", true,
		"publish the draft, so the site serves immediately")
	exDir := fs.String("examples", "",
		"where to write the example files features are tried with (default: examples, beside the templates)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Beside the templates unless told otherwise, so the two folders a
	// demonstration writes outside the store are always found together.
	if *exDir == "" {
		*exDir = filepath.Join(filepath.Dir(*tplDir), "examples")
	}
	tplAbs, err := filepath.Abs(*tplDir)
	if err != nil {
		return err
	}
	exAbs, err := filepath.Abs(*exDir)
	if err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	d := demo.Marginalia()
	if err := demoInstallable(root, s, d, tplAbs, exAbs); err != nil {
		return err
	}
	// What this writes, kept as it is written, so `quilzo demo remove` can
	// take back exactly that and nothing anybody added — including when the
	// install stops part of the way.
	m := &demoManifest{At: time.Now().UTC(), By: resolveCaller(root, "").Name,
		Config: map[string]demoSetting{}}
	started := false
	defer func() {
		if err == nil || !started {
			return
		}
		detail := map[string]string{"error": err.Error()}
		if digest, rerr := recordDemo(root, s, d, m); rerr == nil {
			detail["manifest"] = digest
		}
		record(root, resolveCaller(root, "").auditRecord("demo.install", "/", audit.Failure, detail))
	}()
	if given := strings.TrimSpace(*siteName); given != "" {
		// Renamed rather than assigned. The name is the index page's title and
		// the header wordmark as well as a configuration value, and setting
		// the field alone left every page naming the old shop.
		d.Rename(given)
	} else if *siteName != "" {
		return fmt.Errorf(
			"--name was given as whitespace. The site's name is printed in the " +
				"header link and the page title, so a blank one is an empty " +
				"link on every page and fails the accessibility gate")
	}

	// Media first, because everything else refers to it and a file's address is
	// the hash of its bytes — not known until it is stored.
	lib, err := openMedia(root)
	if err != nil {
		return fmt.Errorf("opening the media library: %w", err)
	}
	addresses := map[string]string{}
	started = true
	for _, a := range d.Media {
		f, aerr := media.Accept(a.Name+".png", a.Bytes, time.Now())
		if aerr != nil {
			return fmt.Errorf("%s: %w", a.Name, aerr)
		}
		f.Alt = a.Alt
		// The rights travel with the file. An installer that stored the bytes
		// and dropped the licence would produce a library where every asset is
		// undeclared, which is the state this feature exists to make visible.
		f.Rights = a.Rights
		if perr := lib.Put(f, a.Bytes); perr != nil {
			return fmt.Errorf("storing %s: %w", a.Name, perr)
		}
		addresses[a.Name] = f.ID
		m.Media = append(m.Media, f.ID)
	}
	if rerr := d.Resolve(addresses); rerr != nil {
		return rerr
	}

	// Types, and the pages bound to them. Saved before the content so the
	// content is validated against them on the way in rather than afterwards.
	types, err := schema.Load(root)
	if err != nil {
		return err
	}
	for _, t := range d.Types {
		if aerr := types.Registry.Add(t); aerr != nil {
			return fmt.Errorf("content type %s: %w", t.Name, aerr)
		}
	}
	for page, name := range d.Bind {
		if berr := types.Bind(page, name); berr != nil {
			return fmt.Errorf("binding %s: %w", page, berr)
		}
	}
	// Collections are typed too, so a record missing a required field is
	// refused at the same gate a page is rather than discovered in a listing.
	for coll, name := range d.BindCollection {
		if berr := types.BindCollection(coll, name); berr != nil {
			return fmt.Errorf("binding collection %s: %w", coll, berr)
		}
	}
	if serr := types.Save(); serr != nil {
		return serr
	}

	// The content itself, checked against its own types before it is stored.
	if failures := types.Gate(d.Pages); len(failures) > 0 {
		lines := make([]string, 0, len(failures))
		for _, f := range failures {
			lines = append(lines, f.String())
		}
		sort.Strings(lines)
		return fmt.Errorf("the demonstration does not satisfy its own types, "+
			"which is a bug in it and not in your store:\n  %v", lines)
	}
	// An empty base, stated rather than defaulted. This command has already
	// refused to run unless the draft and the live site are empty, so there is
	// provably nothing to collide with — which is the one case where an empty
	// base is a decision and not an omission.
	if _, serr := site.SaveDraftFrom(s, d.Pages, "the Marginalia demonstration",
		"demo", ""); serr != nil {
		return serr
	}

	// Where these pages came from, recorded now rather than left for the
	// operator to assert about content they have never read.
	//
	// Without this the demonstration could be published once — by the line
	// below — and never again: the publish gate refuses unmarked content, and
	// `provenance backfill` is right to refuse to invent an author for it. See
	// markgenerated.go for why the answer is algorithmicMedia.
	markGeneratedQuietly(root, s, resolveCaller(root, "").Name,
		"written by quilzo demo")

	// Records, written into the draft's tree — through the same gate every
	// other record write goes through.
	//
	// This did not, and the installer was a fourth surface writing records
	// with the rule expressed a fourth way, which is precisely what
	// schema.RecordGate exists to stop. It was found by the demonstration
	// installing twelve products that were missing two fields their own type
	// marks Required: no error, no warning, and the site rendering blank
	// prices. A demonstration that cannot pass the product's own gate is not
	// a demonstration of the product.
	gate := recordGate(root)
	for name, recs := range d.Records {
		for _, rec := range recs {
			if gerr := gate(name, rec.Fields); gerr != nil {
				return fmt.Errorf(
					"the demonstration does not satisfy its own types, which "+
						"is a bug in it and not in your store:\n  %s: %w",
					name, gerr)
			}
		}
	}
	for name, recs := range d.Records {
		c, cerr := s.GetCommit(s.GetRef(site.RefDraft))
		if cerr != nil {
			return cerr
		}
		next, _, perr := collection.PutMany(s, c.Tree, name, recs, time.Now())
		if perr != nil {
			return fmt.Errorf("collection %s: %w", name, perr)
		}
		if cerr := commitTreeNoLock(s, next, "records for "+name,
			"demo"); cerr != nil {
			return cerr
		}
	}

	// Everything that lives beside the store rather than in it.
	set := &listing.Set{}
	for _, l := range d.Listings {
		if aerr := set.Add(l); aerr != nil {
			return fmt.Errorf("listing %s: %w", l.Name, aerr)
		}
	}
	if werr := saveJSON(listingPath(root), set); werr != nil {
		return werr
	}
	if werr := saveJSON(menuPath(root), d.Menus); werr != nil {
		return werr
	}
	if werr := saveJSON(vocabPath(root), d.Vocabularies); werr != nil {
		return werr
	}
	forms := &form.Set{}
	for _, f := range d.Forms {
		if aerr := forms.Add(f); aerr != nil {
			return fmt.Errorf("form %s: %w", f.Name, aerr)
		}
	}
	if werr := saveJSON(formsPath(root), forms); werr != nil {
		return werr
	}

	// The claim rules, if the demonstration has any.
	//
	// Written here rather than left for the operator, because the gate is only
	// demonstrable when there is something for it to gate — and because the
	// rules are the part somebody argues about, so seeing a real set is more
	// useful than being told the feature exists.
	if len(d.ClaimRules.Terms) > 0 {
		if werr := saveJSON(brandPath(root), d.ClaimRules); werr != nil {
			return werr
		}
	}

	// The name, in configuration rather than a flag, so the accessibility gate
	// and the exports render the same page the server does.
	if cfg, cerr := loadConfig(root); cerr == nil {
		changed := false
		set := func(key, value, reason string) {
			was := cfg.Raw(key)
			if cfg.Set(key, value, reason, "demo") == nil {
				changed = true
				m.Config[key] = demoSetting{Was: was, Set: cfg.Raw(key)}
			}
		}
		set("site.name", d.Name, "the demonstration site")
		// The catalogue feed, when the demonstration publishes one. Set here
		// rather than left to the reader, because a shop whose machine-readable
		// catalogue 404s demonstrates the opposite of the point.
		if d.Catalogue != "" {
			set("site.catalogue", d.Catalogue,
				"the demonstration's machine-readable catalogue")
			// And the same catalogue over UCP, the way shopping agents search
			// a shop. UCP builds every URL from the site's own address, so a
			// demonstration without one gets the address it is told to run
			// at below; an operator's own address is never replaced.
			if cfg.Raw("site.base_url") == "" {
				set("site.base_url", demoSiteURL, "where the demonstration site runs")
			}
			set("ucp.catalogue", "true",
				"the demonstration's catalogue, searchable by shopping agents")
		}
		if changed && saveConfig(root, cfg) != nil {
			m.Config = map[string]demoSetting{}
		}
	}

	// The template and the stylesheet, beside the store where `quilzo site`
	// looks for them.
	made, err := madeDirs(tplAbs, tplAbs)
	if err != nil {
		return err
	}
	m.Templates = demoFolder{Dir: tplAbs, Made: made, Files: map[string]string{}}
	for name, body := range map[string]string{"page.html": d.Template, "site.css": d.CSS} {
		if werr := os.WriteFile(filepath.Join(tplAbs, name), []byte(body), 0o600); werr != nil {
			return werr
		}
		m.Templates.Files[name] = demoDigest([]byte(body))
	}

	// The example files, beside the templates. Paths come from the
	// demonstration itself, and each is checked to stay under the folder all
	// the same, since it becomes a path on somebody's disk.
	m.Examples = demoFolder{Dir: exAbs, Files: map[string]string{}}
	for rel, body := range d.Examples {
		path := filepath.Join(exAbs, filepath.FromSlash(rel))
		if r, rerr := filepath.Rel(exAbs, path); rerr != nil || r == ".." ||
			strings.HasPrefix(r, ".."+string(filepath.Separator)) {
			return fmt.Errorf("the example %s is not under %s", rel, *exDir)
		}
		made, merr := madeDirs(exAbs, filepath.Dir(path))
		if merr != nil {
			return merr
		}
		for _, dir := range made {
			if !slices.Contains(m.Examples.Made, dir) {
				m.Examples.Made = append(m.Examples.Made, dir)
			}
		}
		if werr := os.WriteFile(path, []byte(body), 0o600); werr != nil {
			return werr
		}
		m.Examples.Files[rel] = demoDigest([]byte(body))
	}

	// The research projects, each with its files and a plan not yet
	// registered: registering is a person's commitment, made after reading
	// the plan, so the demonstration leaves it for them.
	for _, rp := range d.Research {
		if rerr := demoResearch(root, rp); rerr != nil {
			return fmt.Errorf("the research project %s: %w", rp.Name, rerr)
		}
	}

	if *publish {
		if _, perr := site.Publish(s, ""); perr != nil {
			return fmt.Errorf("publishing: %w", perr)
		}
	}
	digest, rerr := recordDemo(root, s, d, m)
	if rerr != nil {
		return fmt.Errorf("the demonstration is installed, and the record that "+
			"`quilzo demo remove` takes it back with could not be written: %w", rerr)
	}

	// In the log, because this writes more of a store in one command than
	// anything else here does. Somebody reading the history later should not
	// have to infer a whole application from a scatter of commits.
	if aerr := recordE(root, resolveCaller(root, "").auditRecord("demo.install", "/",
		audit.Success, map[string]string{
			"pages":     fmt.Sprint(len(d.Pages)),
			"records":   fmt.Sprint(recordCount(d)),
			"media":     fmt.Sprint(len(d.Media)),
			"published": fmt.Sprint(*publish),
			"manifest":  digest,
		})); aerr != nil {
		return fmt.Errorf("the demonstration is installed, and the audit record "+
			"that `quilzo demo remove` trusts its record by could not be written: %w", aerr)
	}

	w.Human("%s%s is installed.%s %s\n\n", bold, d.Name, reset, d.Summary)
	w.Human("  %d page(s), %d record(s), %d image(s), %d listing(s), %d form(s)\n",
		len(d.Pages), recordCount(d), len(d.Media), len(d.Listings),
		len(d.Forms))
	w.Human("\n  %sto look at it%s\n", bold, reset)
	w.Human("    quilzo site  --addr 127.0.0.1:8081   %sthe site%s\n", dim, reset)
	w.Human("    quilzo serve --addr 127.0.0.1:8080   %sthe admin%s\n", dim, reset)
	w.Human("\n  %sthings worth trying%s\n", bold, reset)
	w.Human("    /catalogue.json          %severything for sale, as a "+
		"shopping agent reads it%s\n", dim, reset)
	w.Human("    /.well-known/ucp         %sthe same catalogue, searchable by "+
		"shopping agents over UCP%s\n", dim, reset)
	w.Human("    /ranges?range=archive    %sa listing with a parameter%s\n",
		dim, reset)
	w.Human("    /available               %sfiltered on the data, not on "+
		"somebody remembering%s\n", dim, reset)
	w.Human("    /sale                    %s404s until 24 November: its "+
		"window has not opened%s\n", dim, reset)
	w.Human("    /wholesale               %sthe one thing the public server "+
		"may write%s\n", dim, reset)
	if len(d.Examples) > 0 {
		w.Human("\n  %sand on files%s\n", bold, reset)
		w.Human("    %s/evolve/  %sa program search, judged where the programs cannot reach (README.txt)%s\n",
			*exDir, dim, reset)
	}
	for _, rp := range d.Research {
		w.Human("\n  %sand a research project%s\n", bold, reset)
		w.Human("    quilzo research run %s analysis.py --input data/orders.csv\n", rp.Name)
		w.Human("    quilzo research ideas %s --count 3   %shypotheses, judged both ways round%s\n", rp.Name, dim, reset)
	}
	w.Human("\n  %sand the gate%s\n", bold, reset)
	w.Human("    quilzo brand check       %severy claim, and what backs it "+
		"up%s\n", dim, reset)
	w.Human("    %stake guarantee_terms off the brass pen and publishing "+
		"stops%s\n", dim, reset)
	w.Human("\n  %sand when you are done with it%s\n", bold, reset)
	w.Human("    quilzo demo remove       %swhat taking it out would remove; "+
		"anything you changed stays%s\n", dim, reset)
	return nil
}

// recordCount is every record the demonstration installs, across collections.
//
// It read len(d.Records["posts"]) — the name of the one collection the
// previous demonstration had. A shop has products, so the count reported was
// zero while twelve records were being written, which is the shape of report
// that makes somebody believe a step was skipped.
func recordCount(d *demo.Site) int {
	var n int
	for _, recs := range d.Records {
		n += len(recs)
	}
	return n
}

// demoResearch starts one of the demonstration's research projects: the
// project, its files in its folder, and its plan.
func demoResearch(root string, rp demo.ResearchProject) error {
	st := researchStore(root)
	now := time.Now().UTC()
	if err := st.Create(research.Project{Name: rp.Name, Question: rp.Question, By: "demo", Created: now}); err != nil {
		return err
	}
	for rel, body := range rp.Files {
		dst := filepath.Join(st.Work(rp.Name), filepath.FromSlash(rel))
		if r, err := filepath.Rel(st.Work(rp.Name), dst); err != nil || strings.HasPrefix(r, "..") {
			return fmt.Errorf("%s is not inside the project", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(body), 0o600); err != nil {
			return err
		}
	}
	_, err := st.Change(rp.Name, func(p *research.Project) error {
		_, err := research.SetPlan(p, rp.Plan, "demo", "", now)
		return err
	})
	return err
}
