// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/fetch"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcpclient"
)

// Declaring the outside systems this install may reach, and reaching them.
//
// The declarations were a type with nothing storing them, so an operator could
// not name an integration and nothing could call one. This is that store and
// the two commands that use it: one to see what a server offers, one to call a
// tool it offers and this install agreed to.

func integrationsPath(root string) string {
	return filepath.Join(root, "integrations.json")
}

// loadIntegrations reads the declarations.
//
// Every declaration is validated on the way in, enabled or not. A declaration
// that does not validate is a landmine for whoever enables it later, and "it
// was fine until I turned it on" is the report nobody can act on.
func loadIntegrations(root string) (*agent.Integrations, error) {
	set := &agent.Integrations{}
	if err := loadJSON(integrationsPath(root), set); err != nil {
		return nil, fmt.Errorf(
			"integrations.json could not be read, so this install does not "+
				"know what it may reach: %w", err)
	}
	if err := set.Validate(); err != nil {
		return nil, fmt.Errorf("integrations.json: %w", err)
	}
	return set, nil
}

func cmdIntegrations(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return integrationsList(root)
	case "tools":
		return integrationsTools(root, args[1:])
	case "call":
		return integrationsCall(root, args[1:])
	case "pin":
		return integrationsPin(root, args[1:])
	default:
		return fmt.Errorf(
			"unknown integrations command %q; try list, tools, pin or call", args[0])
	}
}

func integrationsList(root string) error {
	set, err := loadIntegrations(root)
	if err != nil {
		return err
	}
	if len(set.Declared) == 0 {
		fmt.Printf("  %snothing declared, so this install reaches nothing "+
			"outside%s\n", dim, reset)
		return nil
	}
	for _, in := range set.Declared {
		state := yellow + "declared, not enabled" + reset
		if in.Enabled {
			state = green + "enabled" + reset
			if in.Kind == agent.IntegrationProcess && !set.AllowProcess {
				state = yellow + "enabled, but process integrations are off " +
					"for this install" + reset
			}
		}
		fmt.Printf("%s%s%s  %s  %s\n", bold, in.Name, reset, in.Kind, state)
		fmt.Printf("  %s%s%s\n", dim, in.Purpose, reset)
		if in.Endpoint != "" {
			fmt.Printf("  reaches %s\n", in.Endpoint)
		}
		fmt.Printf("  may call %s\n", strings.Join(in.Uses, ", "))
		if in.Writes {
			fmt.Printf("  %schanges something on the far side%s\n", yellow, reset)
		}
	}
	return nil
}

// integrationsTools asks a server what it offers.
//
// Shows everything, marking what this install agreed to. Comparing the two is
// how somebody notices that a server has started offering a tool nobody
// reviewed, which is the live risk in this ecosystem.
func integrationsTools(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("quilzo integrations tools NAME")
	}
	in, err := oneIntegration(root, args[0])
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tools, err := newMCPClient(root).Tools(ctx, in)
	if err != nil {
		return err
	}
	var unreviewed int
	for _, t := range tools {
		mark, colour := "not agreed", yellow
		if t.Allowed {
			mark, colour = "agreed", green
		} else {
			unreviewed++
		}
		pin := ""
		switch {
		case t.Pinned == "" && t.Allowed:
			pin = yellow + "  not pinned: a model cannot choose it" + reset
		case t.Pinned != "" && !t.Matches():
			pin = red + "  CHANGED since it was pinned: refused until pinned again" + reset
		case t.Pinned != "":
			pin = green + "  pinned" + reset
		}
		fmt.Printf("%s%-28s%s %s%s%s%s\n", bold, t.Name, reset, colour, mark, reset, pin)
		if t.Description != "" {
			fmt.Printf("  %s%s%s\n", dim, wrapIndent(t.Description, 62, 2), reset)
		}
	}
	if unreviewed > 0 {
		fmt.Printf("\n  %s%d tool(s) this server offers and this install has "+
			"not agreed to. A server can add or redefine a tool after the day "+
			"somebody trusted it%s\n", dim, unreviewed, reset)
	}
	return nil
}

func integrationsCall(root string, args []string) error {
	fs := flag.NewFlagSet("integrations call", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 2 {
		return fmt.Errorf(
			"quilzo integrations call NAME TOOL [key=value ...]")
	}
	name, tool := rest[0], rest[1]

	caller := resolveCaller(root, flagToken)
	// Reaching another system is not reading this one. An integration that
	// writes is a change somewhere nobody here can roll back, so the right to
	// call one is the right to publish rather than the right to view.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		record(root, caller.auditRecord("integration.call", name, audit.Denied,
			map[string]string{"reason": "authorisation", "tool": tool}))
		return err
	}

	in, err := oneIntegration(root, name)
	if err != nil {
		return err
	}
	argv := map[string]any{}
	for _, kv := range rest[2:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("%q is not key=value", kv)
		}
		argv[k] = typed(v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, cerr := newMCPClient(root).Call(ctx, in, tool, argv)
	if cerr != nil {
		record(root, caller.auditRecord("integration.call", name, audit.Denied,
			map[string]string{"tool": tool, "error": cerr.Error()}))
		return cerr
	}
	// Recorded whatever it returned. A call into somebody else's system is the
	// one thing here that cannot be rolled back, so the record of having made
	// it is the only thing that survives.
	record(root, caller.auditRecord("integration.call", name, audit.Success,
		map[string]string{"tool": tool, "endpoint": in.Endpoint}))
	fmt.Println(out)
	return nil
}

func oneIntegration(root, name string) (agent.Integration, error) {
	set, err := loadIntegrations(root)
	if err != nil {
		return agent.Integration{}, err
	}
	for _, in := range set.Declared {
		if in.Name == name {
			return in, nil
		}
	}
	return agent.Integration{}, fmt.Errorf(
		"no integration called %q; `quilzo integrations list`", name)
}

// mcpTransport stands in for the network in tests; nil is the network,
// with every address check fetch makes.
var mcpTransport func(ctx context.Context, url string, body []byte, headers map[string]string) (*fetch.Result, error)

// newMCPClient builds the client, with the vault if there is one.
func newMCPClient(root string) *mcpclient.Client {
	return &mcpclient.Client{
		Do: mcpTransport,
		Secrets: func(name string) (string, error) {
			return readSecret(root, name)
		},
		// A pinned tool redefined by its server is refused, and recorded:
		// it is what a server that was trusted turning on its users looks
		// like.
		Changed: func(in agent.Integration, tool, pinned, now string) {
			noteToolChanged(root, in, tool, pinned, now)
		},
	}
}

// integrationsPin records the definitions a person has read and approves:
// every tool the install uses, or the ones named.
func integrationsPin(root string, args []string) error {
	if len(args) < 1 {
		return errors.New("quilzo integrations pin NAME [TOOL...]")
	}
	set, err := loadIntegrations(root)
	if err != nil {
		return err
	}
	idx := -1
	for i, in := range set.Declared {
		if in.Name == args[0] {
			idx = i
		}
	}
	if idx < 0 {
		return fmt.Errorf("no integration called %q; `quilzo integrations list`", args[0])
	}
	in := set.Declared[idx]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tools, err := newMCPClient(root).Tools(ctx, in)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, t := range args[1:] {
		want[t] = true
	}
	if in.Pins == nil {
		in.Pins = map[string]string{}
	}
	caller := resolveCaller(root, flagToken)
	pinned := 0
	var looked []string
	for _, t := range tools {
		if !t.Allowed || (len(want) > 0 && !want[t.Name]) {
			continue
		}
		delete(want, t.Name)
		looked = append(looked, t.Name)
		// Shown in full: this is what is being approved, and a model that
		// chooses it is choosing what this says.
		fmt.Printf("%s%s%s  %s\n", bold, t.Name, reset, t.Definition[:16])
		if t.Description != "" {
			fmt.Printf("  %s\n", wrapIndent(t.Description, 70, 2))
		}
		if len(t.InputSchema) > 0 {
			fmt.Printf("  %sinput: %s%s\n", dim, clampString(string(t.InputSchema), 400), reset)
		}
		if old := in.Pins[t.Name]; old != t.Definition {
			in.Pins[t.Name] = t.Definition
			pinned++
			_ = recordE(root, caller.auditRecord("integration.pinned", "/integrations/"+in.Name, audit.Success,
				map[string]string{"integration": in.Name, "tool": t.Name, "definition": t.Definition, "was": old}))
		}
	}
	for t := range want {
		return fmt.Errorf("%s does not use %q, or the server no longer offers it", in.Name, t)
	}
	if pinned > 0 {
		set.Declared[idx] = in
		if err := set.Validate(); err != nil {
			return err
		}
		if err := saveJSON(integrationsPath(root), set); err != nil {
			return err
		}
	}
	// Shown and approved as they are: a redefinition seen earlier is now
	// one somebody has looked at, even one that changed back.
	if err := forgetToolChanges(root, in.Name, looked); err != nil {
		return err
	}
	if pinned == 0 {
		fmt.Printf("\n  %snothing changed: every definition was already pinned as it is%s\n", dim, reset)
		return nil
	}
	fmt.Printf("\npinned %d definition(s) of %s; a change by the server is refused until pinned again\n", pinned, in.Name)
	return nil
}

func clampString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// readSecret resolves a credential name to its value, from the environment.
//
// # Why not the store
//
// Integration.Secret names a credential and deliberately never carries one,
// because the declaration lives in a content-addressed object and an object
// cannot be deleted. A token written there is a token that is in the history
// forever, recoverable by anybody who can read any past commit, and no
// rotation removes it.
//
// So the value comes from the process environment, under a name derived from
// the declared one. That is where a container runtime, a systemd unit and a CI
// job all already put credentials, it survives no longer than the process, and
// rotating it is restarting with a different value rather than rewriting
// history that cannot be rewritten.
//
// The mapping is mechanical and stated in the error, because a secret that is
// present under a name nobody guessed reads exactly like a secret that is
// missing.
func readSecret(_ string, name string) (string, error) {
	env := secretEnvName(name)
	if v := os.Getenv(env); v != "" {
		return v, nil
	}
	return "", fmt.Errorf(
		"nothing is set in %s. The declaration names the credential and never "+
			"carries it — a token in a content-addressed object is in the "+
			"history permanently and no rotation removes it — so the value "+
			"comes from the environment", env)
}

// secretEnvName maps a declared name onto an environment variable.
//
// Upper case, and anything that is not a letter or a digit becomes an
// underscore, so "tracker-token" and "tracker.token" both land somewhere
// predictable rather than somewhere a shell cannot express.
func secretEnvName(name string) string {
	var b strings.Builder
	b.WriteString("QUILZO_SECRET_")
	for _, r := range strings.ToUpper(strings.TrimSpace(name)) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
