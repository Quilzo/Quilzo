// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/yamlite"
)

// The reference Docker Compose stack, checked against itself.
//
// deploy/compose.yaml was written, reviewed and never run as its own README
// says to run it. When it was, none of its three setup steps worked: each
// `docker compose run --rm admin ...` replaced the service's command, so the
// --root that named the store went with it, and Quilzo looked for a store in
// the image's read-only working directory. Without read_only it was worse:
// `init` said "created .quilzo" into the container's own layer, which --rm
// deleted. The public site then never started, because nothing had put a
// design in its templates volume.
//
// None of that needs Docker to see. It is the shape of three text files --
// compose.yaml, the Dockerfile and the README's steps -- and these tests
// read them.

// composeFile is deploy/compose.yaml as Compose reads it, with its anchors
// merged into the mappings that name them.
//
// yamlite refuses anchors and aliases, rightly for agent definitions, so the
// two forms this file uses -- `key: &name` on a top-level key and `<<: *name`
// -- are rewritten into plain keys first and merged here, the merged mapping's
// own keys winning as they do in Compose.
func composeFile(t *testing.T) map[string]any {
	t.Helper()
	src := read(t, "deploy/compose.yaml")
	anchors := map[string]string{}
	anchorDef := regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]+):[ \t]*&([A-Za-z0-9_-]+)[ \t]*$`)
	for _, m := range anchorDef.FindAllStringSubmatch(src, -1) {
		anchors[m[2]] = m[1]
	}
	src = anchorDef.ReplaceAllString(src, "$1:")
	src = regexp.MustCompile(`(?m)^([ \t]*)<<:[ \t]*\*([A-Za-z0-9_-]+)[ \t]*$`).
		ReplaceAllString(src, "${1}x-merge-from: $2")
	doc, err := yamlite.Parse([]byte(src))
	if err != nil {
		t.Fatalf("deploy/compose.yaml: %v", err)
	}
	top, ok := doc.(map[string]any)
	if !ok {
		t.Fatal("deploy/compose.yaml is not a mapping")
	}
	var merge func(v any)
	merge = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if name, ok := x["x-merge-from"].(string); ok {
				from, _ := top[anchors[name]].(map[string]any)
				if from == nil {
					t.Fatalf("deploy/compose.yaml merges *%s, which names nothing", name)
				}
				for k, fv := range from {
					if _, own := x[k]; !own {
						x[k] = fv
					}
				}
				delete(x, "x-merge-from")
			}
			for _, c := range x {
				merge(c)
			}
		case []any:
			for _, c := range x {
				merge(c)
			}
		}
	}
	merge(top)
	return top
}

func services(t *testing.T) map[string]map[string]any {
	t.Helper()
	raw, _ := composeFile(t)["services"].(map[string]any)
	if len(raw) == 0 {
		t.Fatal("deploy/compose.yaml has no services")
	}
	out := map[string]map[string]any{}
	for name, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("service %s is not a mapping", name)
		}
		out[name] = m
	}
	return out
}

func strs(v any) []string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
	case string:
		out = append(out, x)
	}
	return out
}

// quilzoServices are the services that run this program's image.
func quilzoServices(t *testing.T) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for name, s := range services(t) {
		if img, _ := s["image"].(string); strings.Contains(img, "quilzo/quilzo") {
			out[name] = s
		}
	}
	if len(out) == 0 {
		t.Fatal("no service in deploy/compose.yaml runs the Quilzo image")
	}
	return out
}

// mounts is a service's volumes, by where they are mounted: the volume's
// name and whether it is read-only.
func mounts(s map[string]any) map[string]struct {
	Volume   string
	ReadOnly bool
} {
	out := map[string]struct {
		Volume   string
		ReadOnly bool
	}{}
	for _, v := range strs(s["volumes"]) {
		parts := strings.Split(v, ":")
		if len(parts) < 2 {
			continue
		}
		out[parts[1]] = struct {
			Volume   string
			ReadOnly bool
		}{parts[0], len(parts) > 2 && strings.Contains(parts[2], "ro")}
	}
	return out
}

// entrypoint is the Dockerfile's ENTRYPOINT, in exec form.
func entrypoint(t *testing.T) []string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^ENTRYPOINT\s+\[(.*)\]\s*$`).FindStringSubmatch(read(t, "Dockerfile"))
	if m == nil {
		t.Fatal("the Dockerfile has no ENTRYPOINT in exec form")
	}
	var out []string
	for _, f := range strings.Split(m[1], ",") {
		out = append(out, strings.Trim(strings.TrimSpace(f), `"`))
	}
	return out
}

// composeSteps is every `docker compose` command in the README's compose
// section, in the order a reader runs them.
func composeSteps(t *testing.T) []string {
	t.Helper()
	readme := read(t, "deploy/README.md")
	var steps []string
	in := false
	for _, line := range strings.Split(readme, "\n") {
		if strings.HasPrefix(line, "```") {
			in = !in
			continue
		}
		if !in {
			continue
		}
		cmd := strings.TrimSpace(line)
		if i := strings.Index(cmd, "  #"); i >= 0 {
			cmd = strings.TrimSpace(cmd[:i])
		}
		if strings.HasPrefix(cmd, "docker compose ") {
			steps = append(steps, cmd)
		}
	}
	if len(steps) == 0 {
		t.Fatal("deploy/README.md shows no docker compose command")
	}
	return steps
}

// runArgs is what a `docker compose run --rm SERVICE ARGS...` step hands the
// service: its name and the arguments after it.
func runArgs(step string) (string, []string, bool) {
	f := strings.Fields(step)
	if len(f) < 4 || f[2] != "run" {
		return "", nil, false
	}
	i := 3
	for i < len(f) && strings.HasPrefix(f[i], "-") {
		i++
	}
	if i >= len(f) {
		return "", nil, false
	}
	return f[i], f[i+1:], true
}

// Finding STACK-F1. Every command the README runs reaches the store on its
// volume, however the command is given.
//
// `docker compose run --rm admin init` replaces the service's command, so a
// --root written in the command is lost on exactly the commands that set the
// store up. The image's entrypoint is the one part a command cannot replace,
// so that is where the store is named.
func TestComposeCommandsReachTheStoreOnItsVolume(t *testing.T) {
	ep := entrypoint(t)
	i := slices.Index(ep, "--root")
	if i < 0 || i+1 >= len(ep) {
		t.Fatalf("the image's entrypoint is %q: it does not name the store, so "+
			"`docker compose run --rm admin init` looks for one in the working "+
			"directory, which read_only makes read-only and --rm throws away", ep)
	}
	store := ep[i+1]
	for name, s := range quilzoServices(t) {
		if slices.Contains(strs(s["command"]), "--root") {
			t.Errorf("%s's command names --root again; the entrypoint does, and a "+
				"command given to `docker compose run` would replace this one", name)
		}
		if ro, _ := s["read_only"].(bool); !ro {
			t.Errorf("%s is not read_only: a write anywhere but a volume would go "+
				"into the container's own layer, and from there nowhere", name)
		}
	}
	for _, name := range []string{"admin", "site"} {
		s, ok := quilzoServices(t)[name]
		if !ok {
			t.Fatalf("there is no %s service running the Quilzo image", name)
		}
		m, ok := mounts(s)[store]
		if !ok || m.Volume != "store" || m.ReadOnly {
			t.Errorf("%s does not mount the store volume read-write at %s, where the "+
				"entrypoint names it", name, store)
		}
	}
	if vols, _ := composeFile(t)["volumes"].(map[string]any); vols == nil {
		t.Error("deploy/compose.yaml declares no named volumes")
	} else if _, ok := vols["store"]; !ok {
		t.Error("deploy/compose.yaml does not declare the store volume")
	}
}

// The README's steps name services the compose file has, and run in the
// directory it is in.
func TestComposeStepsNameItsServices(t *testing.T) {
	svc := services(t)
	for _, step := range composeSteps(t) {
		if name, _, ok := runArgs(step); ok {
			if _, found := svc[name]; !found {
				t.Errorf("the README runs %q, and deploy/compose.yaml has no service %s", step, name)
			}
		}
	}
	if !strings.Contains(read(t, "deploy/README.md"), "cd deploy") {
		t.Error("the README never says to run the steps in deploy/, where compose.yaml and .env are")
	}
}

// The hardening the stack is designed around stays: no Quilzo container
// holds a capability, gains one, or runs as root.
func TestComposeKeepsItsHardening(t *testing.T) {
	for name, s := range quilzoServices(t) {
		if !slices.Contains(strs(s["cap_drop"]), "ALL") {
			t.Errorf("%s does not drop every capability", name)
		}
		if !slices.Contains(strs(s["security_opt"]), "no-new-privileges:true") {
			t.Errorf("%s can gain privileges", name)
		}
		if u, _ := s["user"].(string); u == "0" || strings.HasPrefix(u, "0:") || u == "root" {
			t.Errorf("%s runs as root", name)
		}
	}
	if !regexp.MustCompile(`(?m)^USER\s+nonroot`).MatchString(read(t, "Dockerfile")) {
		t.Error("the image does not run as nonroot")
	}
}
