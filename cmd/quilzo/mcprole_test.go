// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
)

// Every operation this program registers declares a role that can be checked.
//
// The central gate refuses an operation with no role, so an ungated one fails
// closed at call time rather than leaking. This catches it in CI instead,
// which is the difference between a build somebody fixes and a refusal
// somebody debugs.
//
// It exists because the shape it guards against is what happened: NeedsRole
// was set on three of twenty-three operations and read in one place that only
// printed it, so twenty operations were reachable by anybody who could start
// the process — including the four that return the posture and inventory
// reports the admin restricts to an administrator.
func TestEveryMCPOperationDeclaresACheckableRole(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, &Caller{Name: "test"}, "templates")

	ops := srv.Operations()
	if len(ops) < 20 {
		t.Fatalf("only %d operations registered; this is checking the wrong "+
			"server", len(ops))
	}
	// Reads that are an author's on purpose: what visitors wrote, which a
	// reader does not read anywhere else either.
	visitorsWords := map[string]string{
		"list_chatbot_gaps": "visitors' unanswered questions, masked, an author's as the Inbox is",
	}
	for _, op := range ops {
		action, err := actionForRole(op.NeedsRole)
		if err != nil {
			t.Errorf("%s declares role %q, which cannot be checked: %v — so "+
				"the operation is refused at call time and nobody finds out "+
				"until they try it", op.Name, op.NeedsRole, err)
			continue
		}
		// A write must not be gated as a read. The four-tool split already
		// refuses calling a write through quilzo_read, but that is a
		// labelling boundary; this is the privilege one.
		if op.Writes && action == auth.ActView {
			t.Errorf("%s changes content and is gated on %s", op.Name, action)
		}
		if _, ok := visitorsWords[op.Name]; ok && action == auth.ActEditDraft {
			continue
		}
		if !op.Writes && (action == auth.ActEditDraft || action == auth.ActPublish) {
			t.Errorf("%s reads and is gated on %s, which is stricter than it "+
				"needs and will refuse a reader the read", op.Name, action)
		}
	}
}

// The gate is wired, not merely available.
//
// buildMCP sets Authorise. A server built without it refuses everything,
// which is safe but would take the whole agent interface down — so the thing
// worth asserting is that the real constructor wires it.
func TestBuildMCPWiresTheGate(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if srv := buildMCP(root, s, &Caller{Name: "test"}, "templates"); srv.Authorise == nil {
		t.Fatal("buildMCP left Authorise nil, so every operation refuses")
	}
}

// An operation with a twin on the command line is allowed whom the command
// is, and refused whom it refuses, as the jobs are granted: the same access
// policy whichever interface a person's AI app or terminal comes through.
//
// Every operation was asked about "/" unless it named an area, so the
// analyst, the compliance officer and the auditor, whose jobs are granted
// on /@security and /@compliance, were refused over MCP the shield, the
// control statements and the site report their commands give them ("no
// binding gives role-compliance any role on /"); verify_store asked an
// administrator where `quilzo verify` asks a reader; and list_checked and
// list_notes answered a reader whom `checked list` and `note list` refused.
func TestAnOperationIsAllowedWhomItsCommandIs(t *testing.T) {
	grants := map[string][]auth.Binding{
		"reader":     {{Role: auth.RoleReader, Resource: "/"}},
		"author":     {{Role: auth.RoleAuthor, Resource: "/"}},
		"publisher":  {{Role: auth.RolePublisher, Resource: "/"}},
		"admin":      {{Role: auth.RoleAdmin, Resource: "/"}},
		"analyst":    {{Role: auth.RoleAdmin, Resource: auth.AreaSecurity}},
		"compliance": {{Role: auth.RoleAdmin, Resource: auth.AreaCompliance}},
		"auditor":    {{Role: auth.RoleReader, Resource: auth.AreaCompliance}},
		"support":    {{Role: auth.RoleAuthor, Resource: auth.AreaInbox}},
	}
	var all []auth.Binding
	for who, bs := range grants {
		for _, b := range bs {
			b.Principal = "role-" + who
			all = append(all, b)
		}
	}
	root, secrets := storeWithTokenFor(t, all...)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	// pages marks an operation asked page by page (Area "/"): anybody who
	// may read somewhere is let in and answered only the pages they may
	// read, so somebody whose only grant is an area of the admin is given
	// no page by it, where the command, which reads them all, refuses them.
	// Those are compared for the roles over the site.
	twins := []struct {
		op    string
		cmd   []string
		pages bool
	}{
		{"shield_status", []string{"shield", "status"}, false},
		{"site_report", []string{"compliance", "site"}, false},
		{"policy_status", []string{"policy", "show"}, false},
		{"inventory", []string{"compliance", "inventory"}, false},
		{"verify_store", []string{"verify"}, false},
		{"list_checked", []string{"checked", "list"}, true},
		{"list_notes", []string{"note", "list"}, true},
		{"export_site", []string{"export"}, false},
		{"check_accessibility", []string{"a11y"}, false},
		{"check_provenance", []string{"provenance", "check"}, false},
		{"list_terms", []string{"terms"}, false},
		{"list_menus", []string{"menus"}, false},
		{"publish", []string{"publish"}, false},
	}
	for who, bs := range grants {
		t.Setenv("QUILZO_TOKEN", secrets["role-"+who])
		srv := buildMCP(root, s, resolveCaller(root, ""), "templates")
		ops := map[string]mcp.Operation{}
		for _, op := range srv.Operations() {
			ops[op.Name] = op
		}
		for _, tw := range twins {
			op, ok := ops[tw.op]
			if !ok {
				t.Fatalf("no operation %s", tw.op)
			}
			if tw.pages && bs[0].Resource != "/" {
				continue
			}
			cli := authoriseCommand(root, tw.cmd[0], tw.cmd[1:])
			mcpErr := srv.Authorise(op)
			if (cli == nil) != (mcpErr == nil) {
				t.Errorf("%s: quilzo %s answers %v, and %s over MCP answers %v",
					who, strings.Join(tw.cmd, " "), cli, tw.op, mcpErr)
			}
		}
		// The control statements are public in the source, and a reader of
		// the site had them over MCP: they are had by whoever may read
		// anything here, the compliance area's people included, whom the
		// check on the whole site refused them.
		if err := srv.Authorise(ops["control_implementation"]); err != nil {
			t.Errorf("%s: control_implementation answers %v", who, err)
		}
	}
}
