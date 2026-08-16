package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/agentwatch"
	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/codescan"
	"github.com/rsh1k/scrivet/internal/collection"
	"github.com/rsh1k/scrivet/internal/compliance"
	"github.com/rsh1k/scrivet/internal/export"
	"github.com/rsh1k/scrivet/internal/i18n"
	"github.com/rsh1k/scrivet/internal/mcp"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
)

// The rest of the machine interface.
//
// Seven operations covered pages, and an agent asked to build an application
// needs the things an application is made of: the records, the types those
// records have to satisfy, the assets, and the state of the pipeline that puts
// any of it in front of anybody.
//
// # What is deliberately not here, and why
//
// Not everything. An agent surface that can grant a role, mint a token,
// register an extension, rotate a key or export the audit log with identifiers
// revealed has a blast radius that has nothing to do with content — and a
// prompt injection in a page this agent is reading is a plausible way to reach
// it. So the administrative controls stay off this surface, and each refusal
// is written down in the coverage table next to the command rather than being
// a thing nobody wrote down.
//
// The line is: anything that reads, and anything that authors content, is
// here. Anything that changes who may do what, what code runs, or what the
// keys are, is not. That is a decision rather than an omission, which is the
// distinction this project keeps having to make explicit.

func registerContentOps(srv *mcp.Server, root string, s *store.Store, caller *Caller) {
	// -- records ------------------------------------------------------------

	srv.Register(mcp.Operation{
		Name:     "list_collections",
		Summary:  "the record collections in this store and how many each holds",
		Keywords: []string{"records", "collections", "data", "rows", "list"},
	}, func(map[string]any) (any, error) {
		tree, err := draftTree(s)
		if err != nil {
			return nil, err
		}
		names, err := collection.Names(s, tree)
		if err != nil {
			return nil, err
		}
		if len(names) == 0 {
			return "no collections; records are created by writing one", nil
		}
		var b strings.Builder
		for _, n := range names {
			count, _ := collection.Count(s, tree, n)
			fmt.Fprintf(&b, "%s %d\n", n, count)
		}
		return strings.TrimSpace(b.String()), nil
	})

	srv.Register(mcp.Operation{
		Name:    "list_records",
		Summary: "read records from a collection, filtered",
		Detail: "This is a scan with a filter, not an index. It is fine for the " +
			"collections one node holds and it is not a query planner, so do " +
			"not build something that runs twenty of these to answer one " +
			"question.",
		Args: map[string]string{
			"collection": "the collection name",
			"where":      "optional object of field to exact value",
			"limit":      "optional, at most 1000, default 50",
		},
		Keywords: []string{"records", "query", "search", "rows", "find", "data"},
	}, func(a map[string]any) (any, error) {
		name, _ := a["collection"].(string)
		tree, err := draftTree(s)
		if err != nil {
			return nil, err
		}
		q := collection.Query{}
		if where, ok := a["where"].(map[string]any); ok && len(where) > 0 {
			q.Equals = where
		}
		if n, ok := a["limit"].(float64); ok {
			q.Limit = int(n)
		}
		records, total, err := collection.List(s, tree, name, q)
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		b, _ := json.MarshalIndent(map[string]any{
			"total": total, "returned": len(records), "records": records,
		}, "", "  ")
		return string(b), nil
	})

	srv.Register(mcp.Operation{
		Name:    "write_record",
		Summary: "create or replace one record in a collection",
		Detail: "The id is assigned by the store and never taken from the " +
			"fields — an identifier that lives in the data is one somebody can " +
			"edit. Leave it out to create.",
		Args: map[string]string{
			"collection": "the collection name",
			"fields":     "object of field names to values",
			"id":         "optional; omit to create a new record",
		},
		Writes: true, NeedsRole: "author",
		Keywords: []string{"record", "write", "create", "update", "data", "row"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		name, _ := a["collection"].(string)
		fields, _ := a["fields"].(map[string]any)
		if len(fields) == 0 {
			return nil, &mcp.Refusal{Reason: "no fields given; nothing to write"}
		}
		id, _ := a["id"].(string)

		var out collection.Record
		err := s.WithRefLock(func() error {
			tree, err := draftTree(s)
			if err != nil {
				return err
			}
			next, rec, err := collection.Put(s, tree, name,
				collection.Record{ID: id, Fields: fields}, time.Now())
			if err != nil {
				return err
			}
			out = rec
			return commitTreeNoLock(s, next, "mcp: write record in "+name,
				caller.Name)
		})
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		record(root, audit.Record{
			Action: "mcp.write_record", Resource: "/" + name,
			Outcome: audit.Success, Principal: "mcp-client", Kind: audit.KindAI,
			Model: "mcp-client", Verified: false,
			Detail: map[string]string{"on_behalf_of": caller.Name, "id": out.ID},
		})
		return fmt.Sprintf("wrote %s in %s", out.ID, name), nil
	})

	// -- what content has to look like --------------------------------------

	srv.Register(mcp.Operation{
		Name:    "list_types",
		Summary: "the content types, their fields, and which pages must satisfy them",
		Detail: "Read this before writing a page. A write that does not satisfy " +
			"a bound type is refused, and the refusal is easier to avoid than " +
			"to interpret.",
		Keywords: []string{"types", "schema", "fields", "shape", "validation"},
	}, func(map[string]any) (any, error) {
		st, err := schema.Load(root)
		if err != nil {
			return nil, err
		}
		if len(st.Registry.Types) == 0 {
			return "no types are defined, so a page may contain anything", nil
		}
		var b strings.Builder
		for _, n := range st.Registry.Names() {
			t, _ := st.Registry.Get(n)
			fmt.Fprintf(&b, "%s\n", n)
			for _, f := range t.Fields {
				req := ""
				if f.Required {
					req = " required"
				}
				fmt.Fprintf(&b, "  %s %s%s\n", f.Name, f.Kind, req)
			}
		}
		var bound []string
		for page, name := range st.Bound {
			bound = append(bound, page+" must be "+name)
		}
		sort.Strings(bound)
		if len(bound) > 0 {
			fmt.Fprintf(&b, "\n%s", strings.Join(bound, "\n"))
		}
		return strings.TrimSpace(b.String()), nil
	})

	srv.Register(mcp.Operation{
		Name:     "list_media",
		Summary:  "the images and files this site can use, with their descriptions",
		Keywords: []string{"media", "images", "files", "assets", "uploads"},
	}, func(map[string]any) (any, error) {
		lib, err := openMedia(root)
		if err != nil {
			return nil, err
		}
		files, err := lib.List()
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return "nothing has been uploaded", nil
		}
		var b strings.Builder
		for _, f := range files {
			fmt.Fprintf(&b, "%s %s %s %dx%d %q\n", f.ID[:12], f.Name, f.Format,
				f.Width, f.Height, f.Alt)
		}
		return strings.TrimSpace(b.String()), nil
	})

	// -- the state of things ------------------------------------------------

	srv.Register(mcp.Operation{
		Name:    "pipeline_status",
		Summary: "each environment, what it is serving, and what is waiting to go out",
		Keywords: []string{"environments", "staging", "production", "promote",
			"pipeline", "deploy", "schedule"},
	}, func(map[string]any) (any, error) {
		envs, err := loadEnvs(root)
		if err != nil {
			return nil, err
		}
		states, err := site.Status(s, envs)
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "draft %s\n", short(s.GetRef(site.RefDraft)))
		for _, st := range states {
			switch {
			case st.Empty:
				fmt.Fprintf(&b, "%s nothing promoted yet\n", st.Env.Name)
			case st.Same:
				fmt.Fprintf(&b, "%s %s up to date\n", st.Env.Name, short(st.Commit))
			default:
				fmt.Fprintf(&b, "%s %s %d change(s) waiting\n", st.Env.Name,
					short(st.Commit), st.Pending)
			}
		}
		if sch, err := loadSchedule(root); err == nil {
			for _, e := range sch.Pending(time.Now()) {
				fmt.Fprintf(&b, "scheduled %s at %s\n", short(e.Commit),
					time.Unix(e.At, 0).UTC().Format(time.RFC3339))
			}
		}
		return strings.TrimSpace(b.String()), nil
	})

	srv.Register(mcp.Operation{
		Name:    "check_translations",
		Summary: "which pages are missing a translation or were translated from content that has since changed",
		Keywords: []string{"languages", "locales", "translation", "stale", "i18n"},
	}, func(map[string]any) (any, error) {
		cfg, err := loadLocales(root)
		if err != nil || cfg == nil {
			return "no languages are configured", nil
		}
		ref := site.RefDraft
		if s.GetRef(ref) == "" {
			ref = site.RefLive
		}
		tree, err := pageHashes(s, ref)
		if err != nil {
			return nil, err
		}
		sources, present := map[string]string{}, map[string]bool{}
		for stored, oid := range tree {
			present[stored] = true
			if l, page := cfg.Split(stored); l == cfg.Default {
				sources[page] = oid
			}
		}
		states := cfg.Check(sources, present)
		counts := i18n.Counts(states)
		var b strings.Builder
		fmt.Fprintf(&b, "%d current, %d stale, %d missing, %d untracked\n",
			counts[i18n.Current], counts[i18n.Stale], counts[i18n.Missing],
			counts[i18n.Untracked])
		for _, st := range states {
			if st.Status != i18n.Current {
				fmt.Fprintf(&b, "%s %s %s\n", st.Status, st.Page, st.Locale)
			}
		}
		return strings.TrimSpace(b.String()), nil
	})

	// -- assurance, read-only -----------------------------------------------

	srv.Register(mcp.Operation{
		Name:    "scan_content",
		Summary: "run the static security scan over the templates and the draft",
		Detail: "Patterns rather than proofs. Nothing matching is not the same " +
			"as being safe, and a scanner only finds what somebody thought to " +
			"look for.",
		Keywords: []string{"scan", "security", "vulnerability", "secrets", "xss"},
	}, func(a map[string]any) (any, error) {
		dir, _ := a["templates"].(string)
		if dir == "" {
			dir = "templates"
		}
		inputs, err := collectInputs(root, dir, site.RefDraft)
		if err != nil {
			return nil, err
		}
		found := codescan.Scan(inputs)
		if len(found) == 0 {
			return fmt.Sprintf("%d input(s) scanned, nothing matched", len(inputs)), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%d input(s) scanned, %d finding(s)\n", len(inputs), len(found))
		for _, f := range found {
			fmt.Fprintf(&b, "%s %s:%d %s\n", f.Severity, f.Where, f.Line, f.Detail)
		}
		return strings.TrimSpace(b.String()), nil
	})

	srv.Register(mcp.Operation{
		Name:    "verify_store",
		Summary: "re-hash every object and report whether each is still what its name says",
		Keywords: []string{"verify", "integrity", "corruption", "check", "hash"},
	}, func(map[string]any) (any, error) {
		n, err := s.Verify()
		if err != nil {
			return nil, err
		}
		return fmt.Sprintf("%d object(s) verified; every one matched its address", n), nil
	})

	srv.Register(mcp.Operation{
		Name:    "inventory",
		Summary: "the bill of materials and the cryptographic algorithms in use",
		Keywords: []string{"sbom", "compliance", "dependencies", "crypto",
			"licences", "quantum"},
	}, func(map[string]any) (any, error) {
		sb, err := compliance.Generate(time.Now())
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s, %d component(s), %d not this project\n",
			sb.Format, sb.SpecVersion, len(sb.Components),
			len(compliance.ThirdParty(sb)))
		fmt.Fprintf(&b, "%s\n", compliance.Posture())
		for _, alg := range compliance.Inventory() {
			fmt.Fprintf(&b, "%s %s %s\n", alg.Name, alg.Purpose, alg.Quantum)
		}
		return strings.TrimSpace(b.String()), nil
	})

	srv.Register(mcp.Operation{
		Name:    "agent_activity",
		Summary: "what agents have been doing in this store, including this one",
		Detail: "Included deliberately. An agent that can see its own record is " +
			"an agent that can notice it is looping, and hiding it would not " +
			"stop anybody determined from reading the log another way.",
		Keywords: []string{"agents", "activity", "strikes", "refusals", "audit"},
	}, func(map[string]any) (any, error) {
		events, err := audit.Read(auditPath(root))
		if err != nil {
			return nil, err
		}
		reports := agentwatch.Look(events, time.Now())
		if len(reports) == 0 {
			return "no agent activity in the window", nil
		}
		var b strings.Builder
		for _, r := range reports {
			fmt.Fprintf(&b, "%s %d action(s) %d strike(s) %s\n", r.Principal,
				r.Actions, len(r.Strikes), r.Summary)
		}
		return strings.TrimSpace(b.String()), nil
	})

	srv.Register(mcp.Operation{
		Name:    "export_site",
		Summary: "the whole site in a portable format",
		Args: map[string]string{
			"format": "markdown, json or wxr; markdown by default",
		},
		Keywords: []string{"export", "backup", "migrate", "portable", "leave"},
	}, func(a map[string]any) (any, error) {
		f, _ := a["format"].(string)
		if f == "" {
			f = string(export.Markdown)
		}
		pages, err := draftPages(root)
		if err != nil {
			return nil, err
		}
		files, err := export.Export(export.Format(f), export.Site{Pages: pages},
			time.Now())
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		var b strings.Builder
		for _, file := range files {
			fmt.Fprintf(&b, "===== %s =====\n%s\n\n", file.Path, file.Body)
		}
		return strings.TrimSpace(b.String()), nil
	})
}
