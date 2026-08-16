package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rsh1k/scrivet/internal/a11y"
	"github.com/rsh1k/scrivet/internal/audit"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/mcp"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
)

// The MCP surface is the third interface onto the same content, and the two
// before it each shipped with a control present in one and missing from the
// other. So every operation here goes through the same gates as the CLI and the
// admin, and the write path marks content as AI-generated without being asked —
// an agent calling a write tool is a model writing content, whatever the tool is
// called.

func cmdMCP(root string, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "where page.html lives")
	token := fs.String("token", "", "authenticate as the holder of this token")
	list := fs.Bool("list", false, "print the operations and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, *token)
	srv := buildMCP(root, s, caller, *tplDir)

	if *list {
		for _, op := range srv.Operations() {
			kind := "read"
			if op.Writes {
				kind = "write"
			}
			fmt.Printf("  %-22s %-6s %s\n", op.Name, kind, op.Summary)
		}
		fmt.Printf("\n  %s%d operations behind 4 tools; an agent loads only what it "+
			"searches for%s\n", dim, len(srv.Operations()), reset)
		return nil
	}

	// stdio. A hosted deployment fronts this with streamable HTTP, and the
	// framing is the only difference — the routing and the gates are identical,
	// which is why they live in buildMCP rather than in a transport.
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := json.NewEncoder(os.Stdout)

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var req mcp.Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = out.Encode(mcp.Response{JSONRPC: "2.0",
				Error: &mcp.Error{Code: mcp.CodeParse, Message: err.Error()}})
			continue
		}
		resp := srv.Handle(req)
		// A notification has no id and expects no reply.
		if len(req.ID) == 0 {
			continue
		}
		if err := out.Encode(resp); err != nil {
			return err
		}
	}
	return in.Err()
}

func buildMCP(root string, s *store.Store, caller *Caller, tplDir string) *mcp.Server {
	srv := mcp.NewServer("scrivet", version)

	// -- reading ------------------------------------------------------------

	srv.Register(mcp.Operation{
		Name: "list_pages", Summary: "list pages in the draft and whether they differ from live",
		Keywords: []string{"pages", "list", "content", "what"},
	}, func(map[string]any) (any, error) {
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(pages))
		for n := range pages {
			names = append(names, n)
		}
		sort.Strings(names)
		return strings.Join(names, ", "), nil
	})

	srv.Register(mcp.Operation{
		Name: "read_page", Summary: "read one page's fields",
		Args:     map[string]string{"page": "the page name"},
		Keywords: []string{"read", "get", "page", "content", "fields"},
	}, func(a map[string]any) (any, error) {
		name, _ := a["page"].(string)
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			return nil, err
		}
		body, ok := pages[name]
		if !ok {
			return nil, &mcp.Refusal{Reason: fmt.Sprintf("there is no page %q", name)}
		}
		b, _ := json.MarshalIndent(body, "", "  ")
		return string(b), nil
	})

	srv.Register(mcp.Operation{
		Name: "diff", Summary: "what differs between the draft and what is live",
		Keywords: []string{"diff", "changes", "pending", "review"},
	}, func(map[string]any) (any, error) {
		changes, err := site.Diff(s, s.GetRef(site.RefLive), s.GetRef(site.RefDraft))
		if err != nil {
			return nil, err
		}
		if len(changes) == 0 {
			return "no differences", nil
		}
		var b strings.Builder
		for _, c := range changes {
			fmt.Fprintf(&b, "%s %s\n", c.Kind, c.Path)
		}
		return strings.TrimSpace(b.String()), nil
	})

	// -- writing ------------------------------------------------------------

	srv.Register(mcp.Operation{
		Name: "write_page", Summary: "create or change a page in the draft",
		Detail: "Writes to the draft only. The page is recorded as AI-generated, " +
			"which the EU AI Act requires and which you cannot opt out of.",
		Args: map[string]string{
			"page":   "page name: letters, digits, dot, dash, underscore",
			"fields": "object of field names to string values",
		},
		Writes: true, NeedsRole: "author",
		Keywords: []string{"write", "edit", "create", "update", "page", "change"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		name, _ := a["page"].(string)
		if strings.TrimSpace(name) == "" {
			return nil, &mcp.Refusal{Reason: "no page name given"}
		}
		fields, _ := a["fields"].(map[string]any)
		if len(fields) == 0 {
			return nil, &mcp.Refusal{Reason: "no fields given; nothing to write"}
		}

		base := s.GetRef(site.RefDraft)
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			pages = map[string]any{}
		}
		existing, _ := pages[name].(map[string]any)
		body := map[string]any{}
		for k, v := range existing {
			body[k] = v
		}
		for k, v := range fields {
			body[k] = v
		}
		isNew := existing == nil
		pages[name] = body

		// The same gate the CLI and the web UI use. An agent given a looser
		// contract than a person is the most likely writer to produce content
		// nobody looks at before it ships.
		types, err := gateWrite(root, pages)
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}

		cid, err := site.SaveDraftFrom(s, pages, "mcp: write "+name,
			caller.Name, base)
		if err != nil {
			// A refusal, not a failure. An agent that reads "conflict" as "the
			// server broke" will retry, and retrying a conflict against the
			// same stale base fails identically forever.
			return nil, &mcp.Refusal{Reason: err.Error()}
		}

		// Marked without being asked. An agent is a model, and a model writing
		// a page is exactly what Article 50 is about — leaving this to the
		// caller would mean the one interface built for agents is the one that
		// forgets.
		if err := markAssisted(root, s, cid, []string{name},
			map[string]bool{name: isNew}, "mcp-client", "written over MCP",
			caller.Name); err != nil {
			return nil, fmt.Errorf("the page was written but not marked: %w", err)
		}

		if err := types.Save(); err != nil {
			return nil, err
		}

		record(root, audit.Record{
			Action: "mcp.write_page", Resource: "/" + name, Outcome: audit.Success,
			Principal: "mcp-client", Kind: audit.KindAI, Model: "mcp-client",
			Verified: false, Detail: map[string]string{"on_behalf_of": caller.Name},
		})
		return fmt.Sprintf("wrote %s to the draft as %s; it is marked AI-generated "+
			"and is not public until someone publishes", name, short(cid)), nil
	})

	srv.Register(mcp.Operation{
		Name: "publish", Summary: "make the draft live",
		Detail: "Runs the accessibility and provenance gates first and refuses if " +
			"either fails. There is no override here; that is a human decision.",
		Writes: true, NeedsRole: "publisher",
		Keywords: []string{"publish", "live", "release", "deploy", "ship"},
	}, func(map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		draft := s.GetRef(site.RefDraft)

		if reports, err := checkAccessibility(s, draft, tplDir); err == nil {
			if n := a11y.BlockingCount(reports); n > 0 {
				return nil, &mcp.Refusal{Reason: fmt.Sprintf(
					"%d blocking accessibility failure(s); this content is unusable "+
						"for someone. Fix them, or ask a person to override", n)}
			}
		}
		if unmarked, err := unmarkedAt(root, s, draft); err == nil && len(unmarked) > 0 {
			return nil, &mcp.Refusal{Reason: fmt.Sprintf(
				"%d page(s) have no provenance: %s. Article 50 requires AI-generated "+
					"content to be marked", len(unmarked), strings.Join(unmarked, ", "))}
		}

		pub, err := site.Publish(s, "")
		if err != nil {
			return nil, err
		}
		record(root, audit.Record{
			Action: "mcp.publish", Resource: "/", Outcome: audit.Success,
			Principal: "mcp-client", Kind: audit.KindAI, Model: "mcp-client",
			Verified: false, Detail: map[string]string{"on_behalf_of": caller.Name},
		})
		return fmt.Sprintf("published; %d change(s) are live", len(pub.Changes)), nil
	})

	// -- checking -----------------------------------------------------------

	srv.Register(mcp.Operation{
		Name: "check_accessibility", Summary: "run the accessibility checks on the draft",
		Keywords: []string{"check", "accessibility", "a11y", "wcag", "blocking"},
	}, func(map[string]any) (any, error) {
		reports, err := checkAccessibility(s, s.GetRef(site.RefDraft), tplDir)
		if err != nil {
			return nil, err
		}
		n := a11y.BlockingCount(reports)
		var b strings.Builder
		fmt.Fprintf(&b, "%d blocking failure(s)\n", n)
		for _, r := range reports {
			for _, f := range r.Findings {
				fmt.Fprintf(&b, "%s %s: %s (%s)\n", f.Severity, r.Page, f.Rule, f.Criterion)
			}
		}
		return strings.TrimSpace(b.String()), nil
	})

	srv.Register(mcp.Operation{
		Name: "check_provenance", Summary: "which pages lack an AI-content mark",
		Keywords: []string{"check", "provenance", "ai", "marked", "article 50"},
	}, func(map[string]any) (any, error) {
		unmarked, err := unmarkedAt(root, s, s.GetRef(site.RefDraft))
		if err != nil {
			return nil, err
		}
		if len(unmarked) == 0 {
			return "every page has usable provenance", nil
		}
		return fmt.Sprintf("%d page(s) without provenance: %s",
			len(unmarked), strings.Join(unmarked, ", ")), nil
	})

	// Records, types, media, the pipeline and the read-only assurance
	// operations. In another file because this one was already the length where
	// somebody adding an operation stops reading the gates at the top.
	registerContentOps(srv, root, s, caller)

	return srv
}

// unmarkedAt lists pages with no usable provenance at a commit.
func unmarkedAt(root string, s *store.Store, commitID string) ([]string, error) {
	if commitID == "" {
		return nil, nil
	}
	idx, err := loadProvenance(root)
	if err != nil {
		return nil, err
	}
	c, err := s.GetCommit(commitID)
	if err != nil {
		return nil, err
	}
	tree, err := s.GetTree(c.Tree)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, st := range provenance.Unmarked(provenance.Check(idx, tree)) {
		out = append(out, st.Page)
	}
	sort.Strings(out)
	return out, nil
}
