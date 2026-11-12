// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/yamlite"
)

// The workflows, checked as the files GitHub reads.
//
// CI ran `go test ./...` and nothing else: no race detector, no shuffled
// order, no fuzzing. Quilzo shares memory between goroutines in the store,
// the audit log, logd, the scheduler, the public site and the agent
// executor, so a data race passed every pull request, and the fuzz targets
// were only ever run as unit tests, which replay their seeds and stop.
// Nothing said so, because a check that does not run cannot fail.
//
// A workflow is YAML that nobody runs before it is merged, and this
// repository has no workflow linter, so these tests read the files: that
// each is a shape GitHub accepts, and that the jobs added for that finding
// still test what they were added to test. The scripts that find the
// packages to race and the targets to fuzz are run here with `go test`
// stood in for, and what they would test is compared with what the source
// says there is: a search that quietly found fewer would bring the finding
// back with every check green.

// workflow is .github/workflows/name as GitHub reads it.
func workflow(t *testing.T, name string) map[string]any {
	t.Helper()
	doc, err := yamlite.Parse([]byte(read(t, ".github/workflows/"+name)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	m, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a mapping", name)
	}
	return m
}

// workflowJobs is a workflow's jobs by id.
func workflowJobs(t *testing.T, name string, wf map[string]any) map[string]map[string]any {
	t.Helper()
	raw, _ := wf["jobs"].(map[string]any)
	if len(raw) == 0 {
		t.Fatalf("%s has no jobs", name)
	}
	out := map[string]map[string]any{}
	for id, v := range raw {
		j, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: job %s is not a mapping", name, id)
		}
		out[id] = j
	}
	return out
}

// jobSteps is a job's steps, in order.
func jobSteps(job map[string]any) []map[string]any {
	var out []map[string]any
	steps, _ := job["steps"].([]any)
	for _, s := range steps {
		if m, ok := s.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// stepRunning is the one step of the jobs given whose script contains every
// word in words, and the id of its job.
func stepRunning(t *testing.T, name string, jobs map[string]map[string]any, words ...string) (string, map[string]any) {
	t.Helper()
	var found []string
	var job string
	var step map[string]any
	for id, j := range jobs {
		for _, s := range jobSteps(j) {
			run, _ := s["run"].(string)
			if !slices.ContainsFunc(words, func(w string) bool { return !strings.Contains(run, w) }) {
				found = append(found, id)
				job, step = id, s
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want one step running %q, found %d (in %v)", name, words, len(found), found)
	}
	return job, step
}

var pinnedAction = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)

// Every workflow is one GitHub can start: the keys it reads, jobs that say
// where they run and what they do, steps that either use an action or run a
// script, and every action pinned to a commit, for the reason ci.yml gives
// at its top.
func TestEveryWorkflowIsOneGitHubCanRun(t *testing.T) {
	names, _ := filepath.Glob(".github/workflows/*.yml")
	if len(names) < 3 {
		t.Fatalf("found %d workflows; the glob is wrong and a test that reads nothing passes", len(names))
	}
	for _, path := range names {
		name := filepath.Base(path)
		wf := workflow(t, name)
		for _, key := range []string{"name", "on", "permissions", "jobs"} {
			if wf[key] == nil {
				t.Errorf("%s has no %s", name, key)
			}
		}
		on, _ := wf["on"].(map[string]any)
		if len(on) == 0 {
			t.Errorf("%s says no event starts it", name)
		}
		if sched, ok := on["schedule"]; ok {
			entries, _ := sched.([]any)
			if len(entries) == 0 {
				t.Errorf("%s: schedule is not a list", name)
			}
			for _, e := range entries {
				m, _ := e.(map[string]any)
				cron, _ := m["cron"].(string)
				if len(strings.Fields(cron)) != 5 {
					t.Errorf("%s: schedule %v is not a five-field cron", name, e)
				}
			}
		}
		for id, job := range workflowJobs(t, name, wf) {
			if s, _ := job["runs-on"].(string); s == "" {
				t.Errorf("%s: job %s does not say where it runs", name, id)
			}
			steps := jobSteps(job)
			if len(steps) == 0 {
				t.Errorf("%s: job %s has no steps", name, id)
			}
			for i, s := range steps {
				uses, isUse := s["uses"].(string)
				_, isRun := s["run"].(string)
				if isUse == isRun {
					t.Errorf("%s: job %s step %d must either use an action or run a script", name, id, i+1)
				}
				if isUse && !pinnedAction.MatchString(uses) {
					t.Errorf("%s: job %s uses %s, which is not pinned to a commit", name, id, uses)
				}
			}
		}
	}
}

// goTestsIn runs a step's script as GitHub would, with `go test` stood in
// for, and returns the arguments of each `go test` it would have run. Every
// other command runs for real, `go list` among them.
func goTestsIn(t *testing.T, script string) [][]string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed, and GitHub runs these scripts with it")
	}
	// A function named go is found before the program of that name.
	const standIn = `go() {
  if [ "$1" = test ]; then printf 'qz-go-test'; printf ' %s' "$@"; printf '\n'; return 0; fi
  command go "$@"
}
`
	// -e, as GitHub runs a step that names no shell.
	out, err := exec.Command(bash, "-e", "-c", standIn+script).CombinedOutput()
	if err != nil {
		t.Fatalf("the script failed: %v\n%s", err, out)
	}
	var runs [][]string
	for line := range strings.Lines(string(out)) {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "qz-go-test "); ok {
			runs = append(runs, strings.Fields(rest)[1:])
		}
	}
	return runs
}

// sourcePackage is what parsing one package's files found.
type sourcePackage struct {
	// concurrent: a file starts a goroutine or imports sync or sync/atomic.
	concurrent bool
	// fuzz are the fuzz targets its tests declare.
	fuzz []string
}

// sourcePackages is every directory of Go source in the module, by import
// path, as the go command sees it: testdata and directories starting with
// a dot or an underscore are not packages.
func sourcePackages(t *testing.T) map[string]*sourcePackage {
	t.Helper()
	pkgs := map[string]*sourcePackage{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		imp := "github.com/quilzo/quilzo"
		if dir := filepath.ToSlash(filepath.Dir(path)); dir != "." {
			imp += "/" + dir
		}
		p := pkgs[imp]
		if p == nil {
			p = &sourcePackage{}
			pkgs[imp] = p
		}
		for _, s := range f.Imports {
			if v, _ := strconv.Unquote(s.Path.Value); v == "sync" || v == "sync/atomic" {
				p.concurrent = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if _, ok := n.(*ast.GoStmt); ok {
				p.concurrent = true
			}
			return !p.concurrent
		})
		if strings.HasSuffix(path, "_test.go") {
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Fuzz") {
					p.fuzz = append(p.fuzz, fn.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) < 50 {
		t.Fatalf("found %d packages; the walk is wrong", len(pkgs))
	}
	return pkgs
}

// Every pull request runs the race detector over every package that starts
// a goroutine or takes a lock, beside the plain run of the whole suite.
func TestCIRacesEveryConcurrentPackageOnEveryPullRequest(t *testing.T) {
	wf := workflow(t, "ci.yml")
	on, _ := wf["on"].(map[string]any)
	if _, ok := on["pull_request"]; !ok {
		t.Fatal("ci.yml no longer runs on pull requests")
	}
	jobs := workflowJobs(t, "ci.yml", wf)
	// The plain run stays: the race detector is in addition to it.
	if job, _ := stepRunning(t, "ci.yml", jobs, "go test -count=1 ./..."); job != "test" {
		t.Errorf("the plain run of the whole suite moved from the test job to %s", job)
	}
	job, step := stepRunning(t, "ci.yml", jobs, "go test -race")
	if jobs[job]["if"] != nil || step["if"] != nil {
		t.Errorf("the race job is conditional, so some pull requests skip it")
	}
	runs := goTestsIn(t, step["run"].(string))
	if len(runs) != 1 {
		t.Fatalf("the race step would run go test %d times, want once: %v", len(runs), runs)
	}
	raced := map[string]bool{}
	for _, a := range runs[0] {
		if !strings.HasPrefix(a, "-") {
			raced[a] = true
		}
	}
	if !slices.Contains(runs[0], "-race") {
		t.Errorf("the race step runs go test %v, without -race", runs[0])
	}
	var missing []string
	for imp, p := range sourcePackages(t) {
		if p.concurrent && !raced[imp] {
			missing = append(missing, imp)
		}
	}
	sort.Strings(missing)
	for _, imp := range missing {
		t.Errorf("%s starts goroutines or imports sync, and the race step would not test it", imp)
	}
	// The packages the finding named, so a search that went wrong in the
	// same way as this test's walk is still caught.
	for _, p := range []string{"cmd/quilzo", "internal/store", "internal/audit", "internal/logd",
		"internal/public", "internal/agentexec"} {
		if !raced["github.com/quilzo/quilzo/"+p] {
			t.Errorf("the race step would not test %s", p)
		}
	}
}

var fuzzFlag = regexp.MustCompile(`^-fuzz=\^(Fuzz\w*)\$$`)

// Every pull request fuzzes every fuzz target for thirty seconds, found from
// the source, so a target added later is fuzzed without editing the
// workflow.
func TestCIFuzzesEveryTargetOnEveryPullRequest(t *testing.T) {
	wf := workflow(t, "ci.yml")
	jobs := workflowJobs(t, "ci.yml", wf)
	job, step := stepRunning(t, "ci.yml", jobs, "-fuzz=")
	if jobs[job]["if"] != nil || step["if"] != nil {
		t.Errorf("the fuzz job is conditional, so some pull requests skip it")
	}
	fuzzed := map[string]bool{}
	for _, args := range goTestsIn(t, step["run"].(string)) {
		var target, pkg string
		for _, a := range args {
			if m := fuzzFlag.FindStringSubmatch(a); m != nil {
				target = m[1]
			} else if !strings.HasPrefix(a, "-") {
				pkg = strings.TrimPrefix(a, "./")
			}
		}
		if target == "" || pkg == "" || !slices.Contains(args, "-fuzztime=30s") || !slices.Contains(args, "-run=^$") {
			t.Errorf("the fuzz step runs go test %v: want one target, one package, thirty seconds "+
				"and no unit tests", args)
			continue
		}
		fuzzed["github.com/quilzo/quilzo/"+pkg+" "+target] = true
	}
	want := 0
	for imp, p := range sourcePackages(t) {
		for _, f := range p.fuzz {
			want++
			if !fuzzed[imp+" "+f] {
				t.Errorf("%s in %s is never fuzzed by the fuzz step", f, imp)
			}
		}
	}
	if want == 0 {
		t.Fatal("found no fuzz targets in the source; the walk is wrong")
	}
	if len(fuzzed) != want {
		t.Errorf("the fuzz step would fuzz %d targets, the source declares %d", len(fuzzed), want)
	}
}

// Every night the whole suite runs under the race detector in a shuffled
// order, from a workflow of its own.
func TestTheWholeSuiteRunsRacedAndShuffledEveryNight(t *testing.T) {
	wf := workflow(t, "nightly.yml")
	on, _ := wf["on"].(map[string]any)
	if _, ok := on["schedule"]; !ok {
		t.Fatal("nightly.yml has no schedule")
	}
	if _, ok := on["pull_request"]; ok {
		t.Error("nightly.yml runs on pull requests, where ci.yml already races what is worth the wait")
	}
	jobs := workflowJobs(t, "nightly.yml", wf)
	_, step := stepRunning(t, "nightly.yml", jobs, "go test")
	args := strings.Fields(step["run"].(string))
	for _, want := range []string{"-race", "-shuffle=on", "./..."} {
		if !slices.Contains(args, want) {
			t.Errorf("the nightly run is %q, without %s", step["run"], want)
		}
	}
}
