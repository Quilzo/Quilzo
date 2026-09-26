// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/vault"
)

// Connecting to a company's tools, one reviewable file per tool.
//
// A manifest in connect/ describes a tool: its host, how it authenticates,
// which endpoints to read, how they paginate, and which fields to keep.
// Nothing is executed and nothing is loaded — a new integration is a file,
// and reviewing one means reading it rather than reading a program.
//
// The credential never appears in the manifest. It is held under a name in
// connect/secrets.json, sealed with the store's keyring when one exists, and
// `connect run` is the only thing that fetches it.
//
// `connect probe` prints the shape of a response and never its values. An
// author needs to know a tool returns user.email; they do not need a page of
// customer records in their scrollback and in whatever collects it.

func connectDir(root string) string { return filepath.Join(root, "connect") }

func secretsPath(root string) string {
	return filepath.Join(connectDir(root), "secrets.json")
}

func statePath(root string) string {
	return filepath.Join(connectDir(root), "state.json")
}

func cmdConnect(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return connectList(root)
	case "check":
		return connectCheck(root, args[1:])
	case "secret":
		return connectSecret(root, args[1:])
	case "probe":
		return connectProbe(root, args[1:])
	case "run":
		return connectRun(root, args[1:])
	default:
		return fmt.Errorf("unknown connect command %q; try list, check, "+
			"secret, probe or run", args[0])
	}
}

// manifests reads every connector in the directory.
func manifests(root string) ([]connector.Manifest, error) {
	entries, err := os.ReadDir(connectDir(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []connector.Manifest
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") ||
			e.Name() == "secrets.json" || e.Name() == "state.json" {
			continue
		}
		m, merr := readManifest(filepath.Join(connectDir(root), e.Name()))
		if merr != nil {
			return nil, merr
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func readManifest(path string) (connector.Manifest, error) {
	var m connector.Manifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if uerr := json.Unmarshal(b, &m); uerr != nil {
		return m, fmt.Errorf("%s is not a connector: %w", path, uerr)
	}
	return m, nil
}

// findConnector returns a manifest by name, or reads one from a path.
func findConnector(root, what string) (connector.Manifest, error) {
	if strings.HasSuffix(what, ".json") || strings.Contains(what, "/") {
		return readManifest(what)
	}
	all, err := manifests(root)
	if err != nil {
		return connector.Manifest{}, err
	}
	for _, m := range all {
		if m.Name == what {
			return m, nil
		}
	}
	return connector.Manifest{}, fmt.Errorf(
		"no connector called %q in %s", what, connectDir(root))
}

func connectList(root string) error {
	all, err := manifests(root)
	if err != nil {
		return err
	}
	held, _ := loadSecrets(root)
	type row struct {
		Name      string `json:"name"`
		Tool      string `json:"tool"`
		Host      string `json:"host"`
		Endpoints int    `json:"endpoints"`
		Usable    bool   `json:"usable"`
		Problem   string `json:"problem,omitempty"`
		HasSecret bool   `json:"has_secret"`
	}
	var rows []row
	for _, m := range all {
		r := row{Name: m.Name, Tool: m.Tool, Host: m.Host,
			Endpoints: len(m.Endpoints), Usable: true}
		if verr := m.Validate(); verr != nil {
			r.Usable, r.Problem = false, verr.Error()
		}
		_, r.HasSecret = held[m.Auth.Secret]
		rows = append(rows, r)
	}
	if w.JSON(rows) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("no connectors in %s\n", connectDir(root))
		w.Human("  %sone file per tool; quilzo connect check FILE reads "+
			"one without installing it%s\n", dim, reset)
		return nil
	}
	for _, r := range rows {
		state, colour := "", green
		switch {
		case !r.Usable:
			state, colour = "will not load", red
		case !r.HasSecret:
			state, colour = "no credential", yellow
		}
		w.Human("%s%s%s  %s%s%s  %s%s%s\n", bold, r.Name, reset,
			dim, r.Host, reset, colour, state, reset)
		w.Human("  %s%s, %d endpoint(s)%s\n", dim, r.Tool, r.Endpoints, reset)
		if r.Problem != "" {
			w.Human("  %s%s%s\n", red, r.Problem, reset)
		}
	}
	return nil
}

func connectCheck(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo connect check NAME|FILE")
	}
	m, err := findConnector(root, pos[0])
	if err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"name": m.Name, "host": m.Host, "reach": m.Reach(),
		"endpoints": m.Endpoints,
	}) {
		return nil
	}
	w.Human("%s%s%s  %s\n", bold, m.Name, reset, m.Tool)
	w.Human("  %s%s%s\n", green, m.Reach(), reset)
	for _, e := range m.Endpoints {
		sort.Strings(e.Reads)
		w.Human("\n  %s%s%s  %s%s%s → %s\n", bold, e.Name, reset,
			dim, e.Path, reset, e.Produces)
		w.Human("    %sreads: %s%s\n", dim, strings.Join(e.Reads, ", "),
			reset)
		if e.Page.Kind == connector.NextURL {
			w.Human("    %sthe server chooses the next page's URL; a host "+
				"other than %s ends the run%s\n", yellow, m.Host, reset)
		}
	}
	if m.Note != "" {
		w.Human("\n  %s%s%s\n", dim, m.Note, reset)
	}
	return nil
}

// sealedSecrets is the file, which holds either plain values on a store with
// no keyring or sealed ones on a store with one.
type sealedSecrets struct {
	Sealed map[string]json.RawMessage `json:"sealed,omitempty"`
	Plain  map[string]string          `json:"plain,omitempty"`
}

func loadSecrets(root string) (map[string]string, error) {
	out := map[string]string{}
	b, err := os.ReadFile(secretsPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	var f sealedSecrets
	if uerr := json.Unmarshal(b, &f); uerr != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", secretsPath(root), uerr)
	}
	for k, v := range f.Plain {
		out[k] = v
	}
	if len(f.Sealed) == 0 {
		return out, nil
	}
	kr, err := loadKeyring(root)
	if err != nil {
		return nil, err
	}
	if kr == nil {
		return nil, fmt.Errorf(
			"%s holds sealed credentials and this store has no keyring",
			secretsPath(root))
	}
	for k, raw := range f.Sealed {
		s, uerr := vault.Unmarshal(raw)
		if uerr != nil {
			return nil, uerr
		}
		open, oerr := kr.Open(s, []byte("connect/"+k))
		if oerr != nil {
			return nil, fmt.Errorf("%s: %w", k, oerr)
		}
		out[k] = string(open)
	}
	return out, nil
}

func connectSecret(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: quilzo connect secret NAME\n" +
				"  the value is read from QUILZO_CONNECT_SECRET, never from " +
				"the command line:\n" +
				"  an argument is in the shell history and in the process " +
				"table")
	}
	name := pos[0]
	value := os.Getenv("QUILZO_CONNECT_SECRET")
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf(
			"QUILZO_CONNECT_SECRET is empty. The credential is read from " +
				"the environment rather than taken as an argument, because " +
				"an argument is visible in the shell history and to every " +
				"other process on the machine")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := os.MkdirAll(connectDir(root), 0o700); err != nil {
		return err
	}

	var f sealedSecrets
	if b, err := os.ReadFile(secretsPath(root)); err == nil {
		if uerr := json.Unmarshal(b, &f); uerr != nil {
			return uerr
		}
	}
	kr, err := loadKeyring(root)
	if err != nil {
		return err
	}
	if kr != nil {
		s, serr := kr.Seal([]byte(value), []byte("connect/"+name))
		if serr != nil {
			return serr
		}
		raw, merr := vault.Marshal(s)
		if merr != nil {
			return merr
		}
		if f.Sealed == nil {
			f.Sealed = map[string]json.RawMessage{}
		}
		f.Sealed[name] = raw
		delete(f.Plain, name)
	} else {
		if f.Plain == nil {
			f.Plain = map[string]string{}
		}
		f.Plain[name] = value
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(secretsPath(root), b, 0o600); err != nil {
		return err
	}
	// The name, never the value. The audit package refuses a detail key that
	// looks like a credential, which is the belt to this braces.
	record(root, audit.Record{
		Action: "connect.secret", Resource: "/connect/" + name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail:   map[string]string{"name": name, "sealed": fmt.Sprint(kr != nil)},
	})
	if w.JSON(map[string]any{"name": name, "sealed": kr != nil}) {
		return nil
	}
	w.Human("%s%s%s stored\n", bold, name, reset)
	if kr == nil {
		w.Human("  %skept in plain text: this store has no keyring. "+
			"quilzo vault enable seals it%s\n", yellow, reset)
	} else {
		w.Human("  %ssealed with the store's keyring%s\n", dim, reset)
	}
	return nil
}

// client is the outbound HTTP client for connectors.
//
// Through internal/egress, so a connector obeys offline mode and so the
// purpose appears in the egress report: the question "what does this program
// talk to" has one answer and connectors are in it.
func client(timeout time.Duration) connector.Doer {
	return egress.Client("connector", timeout)
}

func connectProbe(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	limit := fs.Int("limit", 60, "how many paths to print")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo connect probe NAME ENDPOINT")
	}
	m, err := findConnector(root, pos[0])
	if err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	held, err := loadSecrets(root)
	if err != nil {
		return err
	}
	_, _, timeout := m.Limits()

	// One page, and only the shape of it. An author needs to know the tool
	// returns user.email; they do not need a page of somebody's staff list
	// in their scrollback, in their terminal's history, and in whatever
	// collects that.
	probe := m
	for i := range probe.Endpoints {
		probe.Endpoints[i].Page = connector.Pagination{}
		probe.Endpoints[i].Records = ""
		probe.Endpoints[i].Since = ""
		probe.Endpoints[i].Watermark = ""
		probe.Endpoints[i].Reads = []string{"__probe"}
		probe.Endpoints[i].Map = map[string]string{"__probe": "__probe"}
	}
	shape, err := connector.Shape(context.Background(), probe, pos[1],
		client(timeout), connector.MapFunc(held))
	if err != nil {
		return err
	}
	paths := connector.Paths(shape, *limit)
	if w.JSON(map[string]any{"paths": paths}) {
		return nil
	}
	w.Human("%s%s/%s%s returns\n", bold, m.Name, pos[1], reset)
	for _, p := range paths {
		w.Human("  %s\n", p)
	}
	w.Human("\n  %sfield names only. A probe that printed values would put "+
		"a page of somebody's staff list in this terminal's history%s\n",
		dim, reset)
	return nil
}

func connectRun(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	full := fs.Bool("full", false,
		"ignore the checkpoint and read everything again")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) < 1 {
		return fmt.Errorf("usage: quilzo connect run NAME [ENDPOINT]")
	}
	m, err := findConnector(root, pos[0])
	if err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	held, err := loadSecrets(root)
	if err != nil {
		return err
	}
	states, err := loadStates(root)
	if err != nil {
		return err
	}
	_, _, timeout := m.Limits()
	doer := client(timeout)

	wanted := m.Endpoints
	if len(pos) == 2 {
		e, ok := m.Endpoint(pos[1])
		if !ok {
			return fmt.Errorf("%s has no endpoint called %q", m.Name, pos[1])
		}
		wanted = []connector.Endpoint{e}
	}

	out := struct {
		Connector string              `json:"connector"`
		Records   []map[string]string `json:"records"`
		Runs      []map[string]any    `json:"runs"`
	}{Connector: m.Name}

	for _, e := range wanted {
		key := m.Name + "/" + e.Name
		from := states[key]
		if *full {
			from = connector.State{}
		}
		res, rerr := connector.Run(context.Background(), m, e.Name, doer,
			connector.MapFunc(held), from, nil)
		// Recorded whatever happened: what was read, from where, how much.
		// Never what was read.
		record(root, audit.Record{
			Action: "connect.run", Resource: "/connect/" + key,
			Outcome: outcomeOfRun(rerr), Principal: caller.Name,
			Kind: caller.Kind, Verified: caller.Kind != audit.KindUnknown,
			Detail: map[string]string{
				"connector": m.Name, "endpoint": e.Name, "host": m.Host,
				"records": fmt.Sprint(len(res.Records)),
				"pages":   fmt.Sprint(res.Pages),
				"fields":  strings.Join(mappedFields(e), ","),
			},
		})
		if rerr != nil {
			return rerr
		}
		if res.Complete() {
			// Only on a complete run. See internal/connector on why a
			// checkpoint that advances after a partial read loses records
			// without ever reporting it.
			states[key] = connector.State{
				Watermark: res.Watermark, At: time.Now().UTC(),
			}
		}
		for _, rec := range res.Records {
			copied := map[string]string{"_source": m.Name,
				"_endpoint": e.Name, "_produces": string(e.Produces)}
			for k, v := range rec {
				copied[k] = v
			}
			out.Records = append(out.Records, copied)
		}
		out.Runs = append(out.Runs, map[string]any{
			"endpoint": e.Name, "records": len(res.Records),
			"pages": res.Pages, "complete": res.Complete(),
			"truncated": res.Truncated, "waited": res.Waited.String(),
		})
	}
	if err := saveStates(root, states); err != nil {
		return err
	}

	if w.JSON(out) {
		return nil
	}
	// One record per line on stdout, so this pipes into workforce and spool
	// without a format in the middle that either of them has to know about.
	enc := json.NewEncoder(os.Stdout)
	for _, rec := range out.Records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	for _, r := range out.Runs {
		line := fmt.Sprintf("%v: %v record(s) over %v page(s)",
			r["endpoint"], r["records"], r["pages"])
		if r["complete"] != true {
			line += ", " + fmt.Sprint(r["truncated"])
		}
		fmt.Fprintf(os.Stderr, "%s%s%s\n", dim, line, reset)
	}
	return nil
}

// mappedFields is what an endpoint brings back, for the audit record.
//
// The names, never the values. A log of what a connector read is what makes
// it reviewable afterwards; a log of what it read back is a second copy of
// the company's staff list.
func mappedFields(e connector.Endpoint) []string {
	out := make([]string, 0, len(e.Map))
	for k := range e.Map {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func outcomeOfRun(err error) audit.Outcome {
	if err == nil {
		return audit.Success
	}
	return audit.Failure
}

func loadStates(root string) (map[string]connector.State, error) {
	out := map[string]connector.State{}
	b, err := os.ReadFile(statePath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if uerr := json.Unmarshal(b, &out); uerr != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", statePath(root), uerr)
	}
	return out, nil
}

func saveStates(root string, states map[string]connector.State) error {
	if err := os.MkdirAll(connectDir(root), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(states, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(statePath(root), b, 0o600)
}
