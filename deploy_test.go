// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/netip"
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
	// The run flags that take the next word as their value.
	valued := map[string]bool{"-e": true, "--env": true, "-v": true, "--volume": true,
		"-w": true, "--workdir": true, "-u": true, "--user": true, "--name": true,
		"--entrypoint": true, "-p": true, "--publish": true, "-l": true, "--label": true}
	i := 3
	for i < len(f) && strings.HasPrefix(f[i], "-") {
		if valued[f[i]] {
			i++
		}
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

// workdir is the image's working directory, which a relative path in a
// command is read against.
func workdir(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^WORKDIR\s+(\S+)\s*$`).FindAllStringSubmatch(read(t, "Dockerfile"), -1)
	if len(m) == 0 {
		t.Fatal("the Dockerfile sets no WORKDIR")
	}
	return m[len(m)-1][1]
}

// writableIn reports whether a service can write path: under a volume it
// mounts read-write, or the /tmp every Quilzo container has.
func writableIn(s map[string]any, path string) bool {
	for at, m := range mounts(s) {
		if !m.ReadOnly && (path == at || strings.HasPrefix(path, at+"/")) {
			return true
		}
	}
	return strings.HasPrefix(path, "/tmp/")
}

// flagValue is the value given to --name in args, or "".
func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == "--"+name && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--"+name+"="); ok {
			return v
		}
	}
	return ""
}

// Finding STACK-F2. Following the reference, the public site never started:
// nothing put a design in the templates volume, so `quilzo site` exited
// with "no layout in templates", Docker restarted it for ever and Caddy
// answered 502. A step before `up -d` writes one, where the site reads it.
func TestComposeSiteHasADesignBeforeItStarts(t *testing.T) {
	steps := composeSteps(t)
	up := slices.IndexFunc(steps, func(s string) bool { return strings.HasPrefix(s, "docker compose up") })
	if up < 0 {
		t.Fatal("the README never starts the stack")
	}
	svc := services(t)
	wd := workdir(t)
	designed := false
	for _, step := range steps[:up] {
		name, args, ok := runArgs(step)
		if !ok || len(args) == 0 {
			continue
		}
		isDemo := args[0] == "demo"
		if !isDemo && !(len(args) > 1 && args[0] == "template" && args[1] == "use") {
			continue
		}
		designed = true
		// Where it writes, as the command reads its flags: templates
		// relative to the working directory, and the demonstration's
		// examples beside them unless told otherwise.
		tpl := flagValue(args, "templates")
		if !isDemo {
			tpl = flagValue(args, "dir")
		}
		if tpl == "" {
			tpl = "templates"
		}
		if !strings.HasPrefix(tpl, "/") {
			tpl = wd + "/" + tpl
		}
		dirs := map[string]string{"templates": tpl}
		if isDemo {
			ex := flagValue(args, "examples")
			if ex == "" {
				ex = tpl[:strings.LastIndex(tpl, "/")] + "/examples"
			}
			dirs["examples"] = ex
		}
		for what, dir := range dirs {
			if !writableIn(svc[name], dir) {
				t.Errorf("%q writes its %s to %s, which %s cannot write: the read-only "+
					"container refuses it", step, what, dir, name)
			}
		}
		site, ok := svc["site"]
		if !ok {
			t.Fatal("there is no site service")
		}
		m, found := mounts(site)[tpl]
		if !found || m.Volume != mounts(svc[name])[tpl].Volume {
			t.Errorf("%q writes the design to %s, and the site does not read that volume there", step, tpl)
		}
	}
	if !designed {
		t.Error("nothing before `docker compose up` writes a design, so the site exits " +
			"with \"no layout in templates\" and Caddy answers 502")
	}
}

// cmsUID is the account every Quilzo container but the log writer runs as:
// distroless's nonroot.
const cmsUID = "65532"

// Finding STACK-F12. The reference ran no separate log writer, so the
// processes that publish content and face the internet wrote their own
// audit log, and anything that could run code as them could rewrite the
// record of it: `quilzo logd status` answered "no log writer", and the
// posture scan "The CMS writes its own audit log". The writer is its own
// service, as an account the CMS is not, holding the only writable mount of
// the log; the CMS reaches it over its socket.
func TestComposeKeepsTheAuditLogOutOfTheCMSsReach(t *testing.T) {
	svc := quilzoServices(t)
	var name string
	for n, s := range svc {
		if c := strs(s["command"]); len(c) > 0 && c[0] == "logd" {
			name = n
		}
	}
	if name == "" {
		t.Fatal("no service runs `quilzo logd`, so the CMS writes its own audit log")
	}
	logd := svc[name]
	dir := flagValue(strs(logd["command"]), "log-dir")
	if dir == "" {
		t.Fatalf("%s names no --log-dir", name)
	}
	user, _ := logd["user"].(string)
	uid := strings.SplitN(user, ":", 2)[0]
	if uid == "" || uid == "0" || uid == cmsUID {
		t.Errorf("%s runs as %q: the writer has to be an account the CMS is not, or the CMS can open the log", name, user)
	}
	if got := flagValue(strs(logd["command"]), "allow-uid"); got != cmsUID {
		t.Errorf("%s takes records from uid %q; the CMS is %s", name, got, cmsUID)
	}
	if m, ok := mounts(logd)[dir]; !ok || m.ReadOnly {
		t.Errorf("%s does not mount %s read-write", name, dir)
	}
	if nm, _ := logd["network_mode"].(string); nm != "none" {
		t.Errorf("%s has a network; it needs a socket and nothing else", name)
	}
	vol := mounts(logd)[dir].Volume
	for n, s := range svc {
		if n == name {
			continue
		}
		m, ok := mounts(s)[dir]
		if (n == "admin" || n == "site") && !ok {
			t.Errorf("%s does not mount the log at %s, so it cannot reach the writer's socket", n, dir)
		}
		if ok && (m.Volume != vol || !m.ReadOnly) {
			t.Errorf("%s mounts %s other than read-only, and could write the log itself", n, dir)
		}
		if ok && !slices.Contains(strs(s["depends_on"]), name) {
			t.Errorf("%s starts without waiting for %s, whose socket its records go to", n, name)
		}
	}
	// The volume is seeded from the image, ownership included, so the
	// directory has to exist there owned by the writer.
	if !regexp.MustCompile(`(?m)^COPY --from=build --chown=` + uid + `:\d+ \S+ ` + regexp.QuoteMeta(dir) + `\s*$`).
		MatchString(read(t, "Dockerfile")) {
		t.Errorf("the image has no %s owned by uid %s, so the volume is made owned by root and the writer cannot use it", dir, uid)
	}
	// The store has to say where the log is, as the step right after init,
	// so everything after it is recorded by the writer.
	steps := composeSteps(t)
	at := -1
	for i, step := range steps {
		if _, args, ok := runArgs(step); ok && len(args) >= 3 && args[0] == "auditlog" && args[1] == "dir" && args[2] == dir {
			at = i
		}
	}
	if at < 1 {
		t.Fatalf("the README never points the store at %s (quilzo auditlog dir %s)", dir, dir)
	}
	if _, args, _ := runArgs(steps[at-1]); len(args) != 1 || args[0] != "init" {
		t.Errorf("the store is pointed at the writer's log after %q rather than right after init", steps[at-1])
	}
}

// Finding STACK-F9. An image built as documented answered "quilzo dev": the
// Dockerfile takes the version as a build argument and passes it to the
// linker, and nothing that told people how to build one passed it. The
// reference can run an image built here, under a name of its own rather than
// the release's, and the README's build passes the version.
func TestComposeRunsAnImageThatKnowsItsVersion(t *testing.T) {
	df := read(t, "Dockerfile")
	stages := regexp.MustCompile(`(?m)^FROM\s`).Split(df, -1)
	if len(stages) < 3 {
		t.Fatal("the Dockerfile has no separate build stage")
	}
	build := stages[1]
	arg := strings.Index(build, "ARG VERSION")
	use := strings.Index(build, "-X main.version=$VERSION")
	if arg < 0 || use < 0 || use < arg {
		t.Error("the build stage does not declare ARG VERSION before passing it to -X main.version, " +
			"and a build argument nothing declares is discarded without a word")
	}
	for name, s := range quilzoServices(t) {
		img, _ := s["image"].(string)
		if !strings.HasPrefix(img, "${QUILZO_IMAGE:-ghcr.io/quilzo/quilzo}:") || !strings.Contains(img, "${QUILZO_VERSION") {
			t.Errorf("%s runs %q: an image built here can only be run under the release's own name", name, img)
		}
	}
	readme := read(t, "deploy/README.md")
	if !regexp.MustCompile(`docker build --build-arg VERSION=\S+ -t \S+`).MatchString(readme) {
		t.Error("the README does not show how to build an image that knows its version")
	}
	for _, v := range []string{"QUILZO_IMAGE", "QUILZO_VERSION"} {
		if !strings.Contains(read(t, "deploy/compose.env.example"), v+"=") {
			t.Errorf("compose.env.example does not say %s can be set", v)
		}
	}
}

// networksOf is the networks a service is on, given as a list or as a
// mapping of each to its settings.
func networksOf(s map[string]any) []string {
	if m, ok := s["networks"].(map[string]any); ok {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	return strs(s["networks"])
}

// envDefaults is compose.env.example, the values a reader starts from.
func envDefaults(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(read(t, "deploy/compose.env.example"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			out[k] = v
		}
	}
	return out
}

// stepIndex is the first README step whose arguments, after the service,
// start with these words; -1 if none does.
func stepIndex(steps []string, words ...string) int {
	for i, step := range steps {
		if _, args, ok := runArgs(step); ok && len(args) >= len(words) && slices.Equal(args[:len(words)], words) {
			return i
		}
	}
	return -1
}

// Finding STACK-F10. `init --admin` printed http://localhost:8080/enrol/...
// whatever the admin was published on, because nothing had told the store
// where its admin is: with QUILZO_ADMIN_PORT=18092 the link pointed at
// nothing, and a passkey is made for the address it is made on. The admin
// is reached through a Caddy of its own, over HTTPS, on this machine's
// loopback and nowhere else; the README tells the store that address, from
// the same .env the port is published from, before the link is made.
func TestComposeEnrolmentLinkNamesThePublishedAdmin(t *testing.T) {
	svc := services(t)
	if ports := strs(svc["admin"]["ports"]); len(ports) > 0 {
		t.Errorf("the admin publishes %v itself; it is reached through its own proxy", ports)
	}
	var proxy string
	for name, s := range svc {
		for _, v := range strs(s["volumes"]) {
			if strings.HasPrefix(v, "./Caddyfile.admin:") {
				proxy = name
			}
		}
	}
	if proxy == "" {
		t.Fatal("no service serves the admin over HTTPS (./Caddyfile.admin)")
	}
	p := svc[proxy]
	if nets := networksOf(p); !slices.Equal(nets, []string{"admin"}) {
		t.Errorf("%s is on %v: the admin's proxy shares a network with the admin and nothing else", proxy, nets)
	}
	ports := strs(p["ports"])
	if len(ports) == 0 {
		t.Fatalf("%s publishes nothing", proxy)
	}
	for _, port := range ports {
		if !strings.HasPrefix(port, "127.0.0.1:${QUILZO_ADMIN_PORT") {
			t.Errorf("%s publishes %q: the admin is this machine's, on its loopback, at QUILZO_ADMIN_PORT", proxy, port)
		}
	}
	// One capability at most, the one the image's caddy carries as a file
	// capability and cannot be run without under no-new-privileges.
	if !slices.Contains(strs(p["cap_drop"]), "ALL") ||
		!slices.Contains(strs(p["security_opt"]), "no-new-privileges:true") ||
		len(strs(p["cap_add"])) > 1 || (len(strs(p["cap_add"])) == 1 && strs(p["cap_add"])[0] != "NET_BIND_SERVICE") {
		t.Errorf("%s holds more than caddy's one capability, or can gain more", proxy)
	}
	if ro, _ := p["read_only"].(bool); !ro {
		t.Errorf("%s is not read-only", proxy)
	}
	caddyfile := read(t, "deploy/Caddyfile.admin")
	for _, want := range []string{"tls internal", "reverse_proxy admin:8080"} {
		if !strings.Contains(caddyfile, want) {
			t.Errorf("Caddyfile.admin has no %q", want)
		}
	}
	// The proxy the internet reaches, and the site behind it, still cannot
	// reach the admin at all.
	for _, name := range []string{"caddy", "site"} {
		if slices.Contains(networksOf(svc[name]), "admin") {
			t.Errorf("%s is on the admin's network", name)
		}
	}

	readme := read(t, "deploy/README.md")
	if !strings.Contains(readme, "set -a; . ./.env; set +a") {
		t.Error("the README does not read .env into the shell, so its steps cannot name the addresses .env gives")
	}
	steps := composeSteps(t)
	enrol := stepIndex(steps, "init", "--admin")
	if enrol < 0 {
		t.Fatal("the README makes no first administrator")
	}
	for _, set := range [][]string{
		{"config", "set", "admin.base_url", `"https://localhost:$QUILZO_ADMIN_PORT"`},
		{"config", "set", "admin.behind_tls_proxy", "true"},
	} {
		at := stepIndex(steps, set...)
		if at < 0 {
			t.Errorf("the README never runs %s", strings.Join(set, " "))
		} else if at > enrol {
			t.Errorf("%s comes after init --admin, whose link it decides", strings.Join(set, " "))
		}
	}
	if envDefaults(t)["QUILZO_ADMIN_PORT"] == "" {
		t.Error("compose.env.example does not set QUILZO_ADMIN_PORT")
	}
}

// The first token, for the commands that come after the steps.
//
// The README gave it as something to run "once there is an administrator",
// and said an administrator makes the rest in the admin, which has no page
// for it. The command was the store's one exception, a token issued without
// one being shown, and the exception holds only while the store has no
// token at all: signing in with the passkey the enrolment link adds makes
// one. So by the time anybody followed the README to that command, it was
// refused, and nothing after the steps could be run. It is a step, after
// the first administrator is named and before the admin starts; every other
// token is issued with one.
func TestComposeIssuesTheFirstTokenBeforeAnybodySignsIn(t *testing.T) {
	steps := composeSteps(t)
	up := slices.IndexFunc(steps, func(s string) bool { return strings.HasPrefix(s, "docker compose up") })
	enrol := stepIndex(steps, "init", "--admin")
	if up < 0 || enrol < 0 {
		t.Fatal("the README neither names a first administrator nor starts the stack")
	}
	_, enrolArgs, _ := runArgs(steps[enrol])
	admin := flagValue(enrolArgs, "admin")
	first := -1
	for i, step := range steps {
		_, args, ok := runArgs(step)
		if !ok || len(args) < 2 || args[0] != "token" || args[1] != "issue" || strings.Contains(step, "QUILZO_TOKEN") {
			continue
		}
		if i < enrol || i > up {
			t.Errorf("%q issues a token without one where the store has nobody to give it to or has a token already", step)
		}
		if who := flagValue(args, "principal"); who != admin {
			t.Errorf("%q issues the first token to %q, not to the first administrator, %s", step, who, admin)
		}
		first = i
	}
	if first < 0 {
		t.Error("the README's steps issue no first token, so no command after them can be run")
	}
	// Nor anywhere else in it, in a sentence as much as in a block.
	setup := map[string]bool{}
	for _, s := range steps[:up] {
		setup[s] = true
	}
	for _, m := range regexp.MustCompile("docker compose run[^`\n]*token issue[^`\n]*").FindAllString(read(t, "deploy/README.md"), -1) {
		cmd := m
		if i := strings.Index(cmd, "  #"); i >= 0 {
			cmd = cmd[:i]
		}
		cmd = strings.TrimSpace(cmd)
		if !strings.Contains(cmd, "QUILZO_TOKEN") && !setup[cmd] {
			t.Errorf("the README gives %q, which is refused once anybody has signed in", cmd)
		}
	}
}

// Finding STACK-F11. The site was given --base-url https://DOMAIN, right on
// 443 only: with Caddy published elsewhere, the sitemap and every canonical
// link named a port nothing listened on. The port Caddy is published on, the
// port it believes it serves (so its redirects and Alt-Svc name it too), and
// the site's address all come from the one variable; the store is told the
// same address for what the admin sends out, newsletters and share links.
func TestComposeSiteURLNamesThePublishedPort(t *testing.T) {
	svc := services(t)
	caddy := svc["caddy"]
	const https = "${QUILZO_HTTPS_PORT:-443}"
	want := map[string]bool{https + ":" + https: false, https + ":" + https + "/udp": false}
	for _, p := range strs(caddy["ports"]) {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("caddy does not publish %q: the port inside and out must be one, or Caddy's "+
				"redirects and Alt-Svc name a port nobody can reach", p)
		}
	}
	env, _ := caddy["environment"].(map[string]any)
	if _, ok := env["QUILZO_HTTPS_PORT"]; !ok {
		t.Error("caddy is not told QUILZO_HTTPS_PORT")
	}
	cf := read(t, "deploy/Caddyfile.compose")
	if !strings.Contains(cf, "\n{$QUILZO_DOMAIN}:{$QUILZO_HTTPS_PORT:443} {") {
		t.Error("Caddyfile.compose does not serve the site on QUILZO_HTTPS_PORT")
	}
	if !strings.Contains(cf, "http_port {$QUILZO_HTTP_PORT:80}") {
		t.Error("Caddyfile.compose does not listen for HTTP on QUILZO_HTTP_PORT")
	}
	// Caddy's redirect from HTTP leaves the site's port out when it is
	// https_port, so https_port must not be set to it.
	if regexp.MustCompile(`(?m)^\s*https_port\s`).MatchString(cf) {
		t.Error("Caddyfile.compose sets https_port, so its redirect from HTTP drops the port")
	}
	base := flagValue(strs(svc["site"]["command"]), "base-url")
	if base != "https://${QUILZO_DOMAIN:?set QUILZO_DOMAIN in deploy/.env}:"+https {
		t.Errorf("the site's --base-url is %q, which does not name the port Caddy is published on", base)
	}
	steps := composeSteps(t)
	at := stepIndex(steps, "config", "set", "site.base_url", `"https://$QUILZO_DOMAIN:$QUILZO_HTTPS_PORT"`)
	if at < 0 {
		t.Error("the README does not tell the store the site's address, so the demonstration " +
			"sets it to http://127.0.0.1:8081 and every link the admin sends out names that")
	} else if demo := stepIndex(steps, "demo"); demo >= 0 && demo < at {
		t.Error("the site's address is set after the demonstration, which sets its own when there is none")
	}
	if envDefaults(t)["QUILZO_HTTPS_PORT"] != "443" {
		t.Error("compose.env.example does not set QUILZO_HTTPS_PORT=443")
	}
}

// The site believes X-Forwarded-For from one address, Caddy's, and the
// README tells the store that address. They were two copies of
// 172.31.250.10, and the edge network's range a third: on a machine where
// that range was taken -- by a second stack, as the test machine's was -- the
// stack could not be made at all, and moving it meant editing three places
// that had to agree. Now .env holds the range and the address once, and the
// default address is in the default range.
func TestComposeTrustsTheAddressCaddyHas(t *testing.T) {
	top := composeFile(t)
	nets, _ := top["networks"].(map[string]any)
	edge, _ := nets["edge"].(map[string]any)
	ipam, _ := edge["ipam"].(map[string]any)
	cfg, _ := ipam["config"].([]any)
	if len(cfg) != 1 {
		t.Fatal("the edge network has no single address range")
	}
	subnet, _ := cfg[0].(map[string]any)["subnet"].(string)
	if subnet != "${QUILZO_EDGE_SUBNET:-172.31.250.0/28}" {
		t.Errorf("the edge network's range is %q, not QUILZO_EDGE_SUBNET", subnet)
	}
	caddyNets, _ := services(t)["caddy"]["networks"].(map[string]any)
	onEdge, _ := caddyNets["edge"].(map[string]any)
	if addr, _ := onEdge["ipv4_address"].(string); addr != "${QUILZO_PROXY_ADDRESS:-172.31.250.10}" {
		t.Errorf("caddy's address on edge is %q, not QUILZO_PROXY_ADDRESS", addr)
	}
	if stepIndex(composeSteps(t), "config", "set", "network.trusted_proxies", `"$QUILZO_PROXY_ADDRESS"`) < 0 {
		t.Error("the README does not trust QUILZO_PROXY_ADDRESS, the address .env gives Caddy")
	}
	env := envDefaults(t)
	pfx, err := netip.ParsePrefix(env["QUILZO_EDGE_SUBNET"])
	if err != nil {
		t.Fatalf("compose.env.example's QUILZO_EDGE_SUBNET: %v", err)
	}
	addr, err := netip.ParseAddr(env["QUILZO_PROXY_ADDRESS"])
	if err != nil || !pfx.Contains(addr) {
		t.Errorf("compose.env.example gives Caddy %q, which is not in %s", env["QUILZO_PROXY_ADDRESS"], pfx)
	}
	if pfx.String() != "172.31.250.0/28" || addr.String() != "172.31.250.10" {
		t.Errorf("compose.env.example's defaults (%s, %s) are not compose.yaml's", pfx, addr)
	}
}
