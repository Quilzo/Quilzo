// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/apiimport"
	"github.com/quilzo/quilzo/internal/audit"
)

// `quilzo integrations import FILE`: an OpenAPI 3 document becomes a REST
// integration, an MCP registry server.json an MCP server. Without --uses it
// lists what is on offer and declares nothing; with it, it declares exactly
// those operations or tools, switched off, for a person to pin and turn on.
func integrationsImport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("integrations import", flag.ContinueOnError)
	name := fs.String("name", "", "what to call it; from the document by default")
	endpoint := fs.String("endpoint", "", "the server to reach, when the document names none or names another")
	uses := fs.String("uses", "", "the operations or tools this install may call, comma-separated")
	secret := fs.String("secret", "", "the name of the credential it authenticates with, as quilzo secret set keeps it")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo integrations import openapi.json|server.json [--name N] [--endpoint HOST] [--uses A,B] [--secret NAME]")
	}
	body, err := readBounded(pos[0], apiimport.MaxDocument)
	if err != nil {
		return err
	}
	opts := apiimport.Options{Name: *name, Endpoint: *endpoint, Secret: *secret}
	for _, u := range strings.Split(*uses, ",") {
		if u = strings.TrimSpace(u); u != "" {
			opts.Uses = append(opts.Uses, u)
		}
	}
	var imp *apiimport.Imported
	if apiimport.IsServerJSON(body) {
		imp, err = apiimport.MCPServer(body, opts)
	} else {
		imp, err = apiimport.OpenAPI(body, opts)
	}
	if err != nil {
		return err
	}
	in := imp.Integration
	if len(opts.Uses) == 0 {
		return listOnOffer(root, imp)
	}
	set, err := loadIntegrations(root)
	if err != nil {
		return err
	}
	for _, d := range set.Declared {
		if d.Name == in.Name {
			return fmt.Errorf("an integration called %s is already declared; import with --name to call this one something else", in.Name)
		}
	}
	set.Declared = append(set.Declared, in)
	if err := set.Validate(); err != nil {
		return err
	}
	if err := saveJSON(integrationsPath(root), set); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	record(root, caller.auditRecord("integration.import", "/", audit.Success, map[string]string{
		"integration": in.Name, "kind": string(in.Kind), "endpoint": in.Where(), "uses": clip(strings.Join(in.Uses, ","), 500)}))
	if w.JSON(map[string]any{"declared": in, "notes": imp.Notes}) {
		return nil
	}
	w.Human("declared %s%s%s (%s) reaching %s, switched off\n", bold, in.Name, reset, in.Kind, in.Where())
	w.Human("  may call %s\n", strings.Join(in.Uses, ", "))
	for _, n := range imp.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	w.Human("\nnext: quilzo integrations tools %s, quilzo integrations pin %s, then turn it on in Administration › Integrations\n",
		in.Name, in.Name)
	return nil
}

// listOnOffer shows what a description offers, declaring nothing.
func listOnOffer(root string, imp *apiimport.Imported) error {
	in := imp.Integration
	offered := imp.Available
	if in.Kind == agent.IntegrationMCP {
		// What an MCP server offers is the server's to say: ask it.
		probe := in
		probe.Enabled, probe.Uses = true, []string{"-"}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tools, err := newMCPClient(root).Tools(ctx, probe)
		if err != nil {
			return fmt.Errorf("%s at %s could not be asked what it offers: %w", in.Name, in.Where(), err)
		}
		for _, t := range tools {
			offered = append(offered, apiimport.Offered{Name: t.Name, Summary: clip(t.Description, 100)})
		}
	}
	if w.JSON(map[string]any{"name": in.Name, "kind": in.Kind, "reaches": in.Where(), "offers": offered, "notes": imp.Notes}) {
		return nil
	}
	w.Human("%s%s%s (%s) at %s offers:\n", bold, in.Name, reset, in.Kind, in.Where())
	for _, o := range offered {
		mark := "   "
		if o.Writes {
			mark = yellow + " ! " + reset
		}
		w.Human("%s%-32s %-6s %s %s%s%s\n", mark, o.Name, o.Method, o.Path, dim, clip(o.Summary, 70), reset)
	}
	for _, n := range imp.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	w.Human("\nnothing is declared yet; name what this install may call:\n  quilzo integrations import FILE --uses NAME,NAME\n")
	return nil
}
