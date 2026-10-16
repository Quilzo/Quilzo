// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/research"
	"github.com/quilzo/quilzo/internal/shell"
)

// Research projects whose every claim can be checked. See internal/research.

func researchStore(root string) *research.Store {
	return &research.Store{Dir: filepath.Join(root, "research")}
}

// researchIndex is the open indexes, through the program's own client: a
// variable so a test can point it at a stand-in.
var researchIndex = func(root string) research.Index {
	c := fetch.For("research")
	c.Limits = fetch.Limits{MaxBytes: 4 << 20, Timeout: 30 * time.Second, MaxRedirects: 3}
	return research.Index{Get: func(ctx context.Context, u string) ([]byte, int, error) {
		res, err := c.Do(ctx, "GET", u, nil, map[string]string{"Accept": "application/json"})
		if err != nil {
			return nil, 0, err
		}
		return res.Body, res.Status, nil
	}}
}

// researchScreens is the store's projects, for the admin's screens. Who may
// read them is the screen's to decide.
func researchScreens(root string) *admin.Research {
	st := researchStore(root)
	return &admin.Research{
		List: st.List,
		Load: func(name string) (research.Project, []research.Run, []research.Finding, error) {
			p, err := st.Load(name)
			if err != nil {
				return p, nil, nil, err
			}
			runs, err := st.Runs(name)
			if err != nil {
				return p, nil, nil, err
			}
			return p, runs, research.Check(p, runs), nil
		},
	}
}

// researchTimeout bounds one computation.
const researchTimeout = 30 * time.Minute

// interpreters are what runs a script, by its extension.
var interpreters = map[string]string{".py": "python3", ".r": "Rscript", ".jl": "julia"}

func cmdResearch(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := func() *Caller { return resolveCaller(root, flagToken) }
	rest := args[1:]
	usage := func(u string) error { return errors.New("usage: quilzo research " + u) }
	switch args[0] {
	case "list":
		return researchList(root, caller())
	case "ideas":
		pos, flags := leadingArgs(rest, 1)
		var o ideasOptions
		if err := ideaFlagSet(&o).Parse(flags); err != nil {
			return err
		}
		if len(pos) != 1 {
			return usage("ideas NAME [--count N | --play | --verdict ID --outcome OUTCOME [--claim NAME]… [--note TEXT]]")
		}
		return researchIdeas(root, pos[0], o, caller())
	case "new":
		pos, flags := leadingArgs(rest, 1)
		fs := flag.NewFlagSet("research new", flag.ContinueOnError)
		question := fs.String("question", "", "the question the project answers")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 1 || *question == "" {
			return usage(`new NAME --question "…"`)
		}
		if err := researchNew(root, pos[0], *question, caller()); err != nil {
			return err
		}
		fmt.Printf("started %s. Next: quilzo research add %s FILE… and quilzo research plan %s PLAN.md\n", pos[0], pos[0], pos[0])
		return nil
	case "show":
		if len(rest) != 1 {
			return usage("show NAME")
		}
		return researchShow(root, rest[0], caller())
	case "add":
		pos, flags := leadingArgs(rest, len(rest))
		fs := flag.NewFlagSet("research add", flag.ContinueOnError)
		to := fs.String("to", "", "the folder in the project to put them in")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) < 2 {
			return usage("add NAME FILE… [--to FOLDER]")
		}
		added, err := researchAdd(root, pos[0], pos[1:], *to, caller())
		for _, f := range added {
			fmt.Printf("added %s  %s\n", f.Path, f.Digest[:12])
		}
		return err
	case "plan":
		pos, flags := leadingArgs(rest, 2)
		fs := flag.NewFlagSet("research plan", flag.ContinueOnError)
		why := fs.String("why", "", "why a registered plan changes")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 2 {
			return usage(`plan NAME FILE [--why "…"]`)
		}
		text, err := readTextArg(pos[1], research.MaxPlan)
		if err != nil {
			return err
		}
		a, err := researchSetPlan(root, pos[0], text, *why, caller())
		switch {
		case err != nil:
			return err
		case a != nil:
			fmt.Printf("amended the registered plan: %s to %s\n", a.From[:12], a.To[:12])
		default:
			fmt.Printf("the plan is a draft until it is registered: quilzo research register %s\n", pos[0])
		}
		return nil
	case "register":
		if len(rest) != 1 {
			return usage("register NAME")
		}
		p, err := researchRegister(root, rest[0], caller())
		if err != nil {
			return err
		}
		fmt.Printf("registered the plan of %s, SHA-256 %s, signed with the log's key\n", p.Name, p.Plan.Digest)
		if !p.Plan.BeforeData {
			fmt.Println("  the data had already been analysed, and the plan says so")
		}
		return nil
	case "run":
		pos, flags := leadingArgs(rest, 2)
		fs := flag.NewFlagSet("research run", flag.ContinueOnError)
		var inputs multiFlag
		fs.Var(&inputs, "input", "a file in the project the script reads (repeat for each)")
		idea := fs.String("idea", "", "the idea this computation executes, by id (quilzo research ideas lists them)")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 2 {
			return usage("run NAME SCRIPT [--input FILE]… [--idea ID]")
		}
		r, err := researchRunScript(context.Background(), root, pos[0], pos[1], inputs, "", caller(), *idea)
		if err != nil {
			return err
		}
		printRun(r)
		if !r.OK() {
			return fmt.Errorf("%s did not finish cleanly", r.ID)
		}
		return nil
	case "rerun":
		if len(rest) != 2 {
			return usage("rerun NAME RUN")
		}
		r, err := researchRerun(context.Background(), root, rest[0], rest[1], caller())
		if err != nil {
			return err
		}
		printRun(r)
		if r.Reproduced == nil || !*r.Reproduced {
			return fmt.Errorf("%s did not reproduce %s", r.ID, rest[1])
		}
		return nil
	case "claim":
		pos, flags := leadingArgs(rest, len(rest))
		fs := flag.NewFlagSet("research claim", flag.ContinueOnError)
		run := fs.String("run", "", "the computation the numbers come from")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) < 1 || *run == "" {
			return usage("claim NAME [VALUE…] --run RUN   (no VALUE: every value it wrote down)")
		}
		claims, err := researchClaim(root, pos[0], *run, pos[1:], caller())
		for _, c := range claims {
			fmt.Printf("{{%s}} = %s, from %s\n", c.Name, research.Format(c.Value, c.Unit), c.Run)
		}
		return err
	case "search":
		pos, flags := leadingArgs(rest, 1)
		fs := flag.NewFlagSet("research search", flag.ContinueOnError)
		n := fs.Int("limit", 10, "how many")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 1 {
			return usage(`search "WORDS" [--limit N]`)
		}
		found, err := researchSearch(context.Background(), root, pos[0], *n, caller())
		if err != nil {
			return err
		}
		for _, c := range found {
			by := ""
			if len(c.Authors) > 0 {
				by = c.Authors[0]
				if len(c.Authors) > 1 {
					by += " et al."
				}
			}
			fmt.Printf("%s\n  %s (%d) %s, cited %d times\n", c.ID, c.Title, c.Year, by, c.CitedBy)
		}
		if len(found) > 0 {
			fmt.Println("cite one with quilzo research cite PROJECT ID")
		}
		return nil
	case "cite":
		pos, flags := leadingArgs(rest, 2)
		fs := flag.NewFlagSet("research cite", flag.ContinueOnError)
		key := fs.String("key", "", "how the report cites it, as [@KEY]")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 2 {
			return usage("cite NAME doi:…|pmid:…|arxiv:…|W… [--key KEY]")
		}
		src, err := researchCite(context.Background(), root, pos[0], pos[1], *key, caller())
		if err != nil {
			return err
		}
		fmt.Printf("[@%s] %s\n  resolved in %s", src.Key, research.Reference(src), src.Resolver)
		if src.Abstract == "" {
			fmt.Printf("; the index holds no abstract, so quote the passage a sentence rests on: quilzo research quote %s %s \"…\"", pos[0], src.Key)
		}
		fmt.Println()
		return nil
	case "quote":
		if len(rest) != 3 {
			return usage(`quote NAME KEY "PASSAGE"`)
		}
		return researchQuote(root, rest[0], rest[1], rest[2], caller())
	case "write":
		if len(rest) != 2 {
			return usage("write NAME REPORT.md")
		}
		text, err := readTextArg(rest[1], research.MaxReport)
		if err != nil {
			return err
		}
		fs, err := researchWrite(root, rest[0], text, caller())
		if err != nil {
			return err
		}
		fmt.Printf("kept the report; %d problem(s): quilzo research check %s\n", research.Problems(fs), rest[0])
		return nil
	case "check":
		if len(rest) != 1 {
			return usage("check NAME")
		}
		_, fs, err := researchCheck(root, rest[0], caller())
		if err != nil {
			return err
		}
		for _, f := range fs {
			mark := "note "
			if f.Problem {
				mark = "PROBLEM"
			}
			if f.Line > 0 {
				fmt.Printf("%s line %d: %s\n", mark, f.Line, f.What)
			} else {
				fmt.Printf("%s %s\n", mark, f.What)
			}
		}
		if n := research.Problems(fs); n > 0 {
			return fmt.Errorf("%d problem(s): every number linked, every citation resolved and supporting its sentence", n)
		}
		fmt.Println("every number is linked to a computation, and every citation resolved and supports its sentence")
		return nil
	case "report":
		pos, flags := leadingArgs(rest, 1)
		fs := flag.NewFlagSet("research report", flag.ContinueOnError)
		outPath := fs.String("o", "", "write it to a file")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 1 {
			return usage("report NAME [-o FILE]")
		}
		md, err := researchReport(root, pos[0], caller())
		if err != nil {
			return err
		}
		if *outPath == "" {
			_, err = io.WriteString(os.Stdout, md)
			return err
		}
		return os.WriteFile(*outPath, []byte(md), 0o644)
	}
	return fmt.Errorf("unknown research command %q; try list, new, show, add, plan, register, run, rerun, claim, "+
		"search, cite, quote, write, check or report", args[0])
}

// readTextArg reads a file, or standard input for "-".
func readTextArg(path string, limit int) (string, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, int64(limit)+1))
	} else {
		b, err = readBounded(path, int64(limit)+1)
	}
	if err != nil {
		return "", err
	}
	if len(b) > limit {
		return "", fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return string(b), nil
}

func researchRecord(root string, caller *Caller, action, project string, d map[string]string) {
	if d == nil {
		d = map[string]string{}
	}
	d["project"] = project
	record(root, caller.auditRecord(action, "/research/"+project, audit.Success, d))
}

func researchNew(root, name, question string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	p := research.Project{Name: name, Question: plaintext.Clean(question), By: caller.Name, Created: time.Now().UTC()}
	if err := researchStore(root).Create(p); err != nil {
		return err
	}
	researchRecord(root, caller, "research.created", name, nil)
	return nil
}

func researchList(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	all, err := researchStore(root).List()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Println(`no research projects; start one with quilzo research new NAME --question "…"`)
		return nil
	}
	for _, p := range all {
		plan := "plan not registered"
		if p.Registered() {
			plan = "plan registered " + p.Plan.Registered.Format("2 Jan 2006")
		}
		fmt.Printf("%-24s %s; %d claims, %d sources\n  %s\n", p.Name, plan, len(p.Claims), len(p.Sources),
			clampString(p.Question, 100))
	}
	return nil
}

func researchShow(root, name string, caller *Caller) error {
	p, fs, err := researchCheck(root, name, caller)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n  %s\n", p.Name, p.Question)
	switch {
	case p.Registered():
		fmt.Printf("plan: registered %s by %s, %s\n", p.Plan.Registered.Format("2 Jan 2006"), p.Plan.By, p.Plan.Digest[:12])
	case p.Plan.Text != "":
		fmt.Println("plan: a draft, not registered")
	default:
		fmt.Println("plan: none yet")
	}
	for _, a := range p.Amendments {
		fmt.Printf("  amended %s by %s: %s\n", a.At.Format("2 Jan 2006"), a.By, a.Why)
	}
	runs, _ := researchStore(root).Runs(name)
	if len(runs) > 0 {
		fmt.Println("computations:")
	}
	for i, r := range runs {
		if i == 10 {
			fmt.Printf("  and %d more\n", len(runs)-10)
			break
		}
		state := "finished"
		if !r.OK() {
			state = "failed"
		}
		if r.Reproduced != nil {
			state = "reproduced " + r.Rerun
			if !*r.Reproduced {
				state = "did not reproduce " + r.Rerun
			}
		}
		fmt.Printf("  %s %s %s, %d values, %s\n", r.ID, r.Code.Path, state, len(r.Values), r.Started.Format("2 Jan 15:04"))
	}
	for _, c := range p.Claims {
		fmt.Printf("claim {{%s}} = %s from %s\n", c.Name, research.Format(c.Value, c.Unit), c.Run)
	}
	for _, s := range p.Sources {
		fmt.Printf("source [@%s] %s\n", s.Key, research.Reference(s))
	}
	if len(p.Ideas) > 0 {
		decided := 0
		for _, i := range p.Ideas {
			if i.Verdict != nil {
				decided++
			}
		}
		fmt.Printf("ideas: %d, %d with a verdict (quilzo research ideas %s)\n", len(p.Ideas), decided, p.Name)
	}
	fmt.Printf("report: %d problem(s)\n", research.Problems(fs))
	return nil
}

// projectFile is a file inside a project's folder, by its path there.
func projectFile(work, rel string) (string, string, error) {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == "." || strings.HasPrefix(rel, "../") || rel == ".." || filepath.IsAbs(rel) {
		return "", "", fmt.Errorf("%q is not a file in the project", rel)
	}
	p := filepath.Join(work, filepath.FromSlash(rel))
	fi, err := os.Lstat(p)
	if err != nil {
		return "", "", fmt.Errorf("the project has no file %s (quilzo research add)", rel)
	}
	if !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("%s is not a plain file", rel)
	}
	return p, rel, nil
}

func digestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

func copyFile(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// maxProjectFile bounds a file added to a project.
const maxProjectFile = 1 << 30

func researchAdd(root, name string, files []string, to string, caller *Caller) ([]research.File, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return nil, err
	}
	st := researchStore(root)
	if _, err := st.Load(name); err != nil {
		return nil, err
	}
	to = filepath.ToSlash(filepath.Clean("/" + to))[1:]
	var added []research.File
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil || !fi.Mode().IsRegular() {
			return added, fmt.Errorf("%s is not a file", f)
		}
		if fi.Size() > maxProjectFile {
			return added, fmt.Errorf("%s is over %d bytes", f, maxProjectFile)
		}
		rel := filepath.ToSlash(filepath.Join(to, filepath.Base(f)))
		dst := filepath.Join(st.Work(name), filepath.FromSlash(rel))
		tmp := dst + ".adding"
		_ = os.Remove(tmp)
		if err := copyFile(f, tmp); err != nil {
			return added, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return added, err
		}
		d, n, err := digestFile(dst)
		if err != nil {
			return added, err
		}
		added = append(added, research.File{Path: rel, Digest: d, Bytes: n})
		researchRecord(root, caller, "research.added", name, map[string]string{"file": rel, "digest": d})
	}
	return added, nil
}

// personOnly refuses a model: some acts are a researcher's commitment.
func personOnly(caller *Caller, what string) error {
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("%s is a researcher's commitment, made by a person, not a model", what)
	}
	return nil
}

func researchSetPlan(root, name, text, why string, caller *Caller) (*research.Amendment, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return nil, err
	}
	var amended *research.Amendment
	p, err := researchStore(root).Change(name, func(p *research.Project) error {
		if p.Registered() {
			if err := personOnly(caller, "amending a registered plan"); err != nil {
				return err
			}
		}
		a, err := research.SetPlan(p, plaintext.Clean(text), caller.Name, plaintext.Clean(why), time.Now())
		amended = a
		return err
	})
	if err != nil {
		return nil, err
	}
	if amended != nil {
		researchRecord(root, caller, "research.amended", name, map[string]string{"from": amended.From,
			"to": amended.To, "why": clampString(amended.Why, 300), "after_data": strconv.FormatBool(amended.AfterData)})
	} else {
		researchRecord(root, caller, "research.planned", name, map[string]string{"digest": research.Digest(p.Plan.Text)})
	}
	return amended, nil
}

func researchRegister(root, name string, caller *Caller) (research.Project, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return research.Project{}, err
	}
	if err := personOnly(caller, "registering a plan"); err != nil {
		return research.Project{}, err
	}
	signer, err := headSigner(root)
	if err != nil {
		return research.Project{}, err
	}
	p, err := researchStore(root).Change(name, func(p *research.Project) error {
		if err := research.Register(p, caller.Name, time.Now()); err != nil {
			return err
		}
		st, err := signer.SignStatement(research.PlanContext, []byte(p.Plan.Digest))
		if err != nil {
			return err
		}
		p.Plan.Signature = &research.Signature{KeyID: st.KeyID, Ed25519: st.Ed25519, MLDSA: st.MLDSA, Algorithms: st.Algorithms}
		return nil
	})
	if err != nil {
		return p, err
	}
	researchRecord(root, caller, "research.registered", name, map[string]string{"digest": p.Plan.Digest,
		"before_data": strconv.FormatBool(p.Plan.BeforeData)})
	return p, nil
}

func newResearchRunID(at time.Time) (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "r-" + at.UTC().Format("20060102") + "-" + hex.EncodeToString(raw[:]), nil
}

// researchRunScript runs a project's script in a box with no network, on
// copies of the code and the inputs named, and keeps what it wrote. A
// re-run (of) runs the code the earlier computation kept, on inputs that
// must not have changed since.
func researchRunScript(ctx context.Context, root, name, script string, inputs []string, of string,
	caller *Caller, idea string) (research.Run, error) {

	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return research.Run{}, err
	}
	st := researchStore(root)
	project, err := st.Load(name)
	if err != nil {
		return research.Run{}, err
	}
	// The idea a run executes must be one this project proposed: a link to
	// an id nobody proposed would hang an outcome on nothing.
	if idea != "" {
		found := false
		for _, i := range project.Ideas {
			if i.ID == idea {
				found = true
				break
			}
		}
		if !found {
			return research.Run{}, fmt.Errorf("%q is not an idea of %s; quilzo research ideas %s lists them",
				idea, name, name)
		}
	}
	work := st.Work(name)
	var earlier research.Run
	codeFrom := ""
	if of != "" {
		var err error
		if earlier, err = st.LoadRun(name, of); err != nil {
			return research.Run{}, err
		}
		script = earlier.Code.Path
		codeFrom = filepath.Join(st.RunDir(name, of), "code", filepath.FromSlash(script))
		inputs = nil
		for _, in := range earlier.Inputs {
			inputs = append(inputs, in.Path)
		}
	} else {
		var err error
		if codeFrom, script, err = projectFile(work, script); err != nil {
			return research.Run{}, err
		}
	}
	interp, ok := interpreters[strings.ToLower(filepath.Ext(script))]
	if !ok {
		return research.Run{}, fmt.Errorf("%s is not a script this runs: Python (.py), R (.R) or Julia (.jl)", script)
	}
	interpPath, err := shell.Find(interp)
	if err != nil {
		return research.Run{}, err
	}
	codeDigest, codeBytes, err := digestFile(codeFrom)
	if err != nil {
		return research.Run{}, err
	}
	if of != "" && codeDigest != earlier.Code.Digest {
		return research.Run{}, fmt.Errorf("the code %s kept is not what it ran", of)
	}
	type input struct {
		from string
		file research.File
	}
	var ins []input
	for _, rel := range inputs {
		from, rel, err := projectFile(work, rel)
		if err != nil {
			return research.Run{}, err
		}
		if rel == script {
			continue
		}
		d, n, err := digestFile(from)
		if err != nil {
			return research.Run{}, err
		}
		ins = append(ins, input{from, research.File{Path: rel, Digest: d, Bytes: n}})
	}
	if of != "" {
		for i, in := range ins {
			if in.file.Digest != earlier.Inputs[i].Digest {
				return research.Run{}, fmt.Errorf("%s changed since %s: a re-run is of the same code on the same inputs", in.file.Path, of)
			}
		}
	}

	backend := testBackend
	if backend == nil {
		if backend, err = programBackend(root, "native", ""); err != nil {
			return research.Run{}, err
		}
	}
	if a := backend.Check(); !a.OK {
		return research.Run{}, fmt.Errorf("a computation runs in a box, and there is none here: %s", a.Why)
	}
	started := time.Now()
	id, err := newResearchRunID(started)
	if err != nil {
		return research.Run{}, err
	}
	// The box is given absolute paths; the store's root may be relative.
	dir, err := filepath.Abs(st.RunDir(name, id))
	if err != nil {
		return research.Run{}, err
	}
	box := filepath.Join(dir, "out")
	if err := copyFile(codeFrom, filepath.Join(dir, "code", filepath.FromSlash(script))); err != nil {
		return research.Run{}, err
	}
	copied := map[string]string{script: codeDigest}
	if err := copyFile(codeFrom, filepath.Join(box, filepath.FromSlash(script))); err != nil {
		return research.Run{}, err
	}
	for _, in := range ins {
		if err := copyFile(in.from, filepath.Join(box, filepath.FromSlash(in.file.Path))); err != nil {
			return research.Run{}, err
		}
		copied[in.file.Path] = in.file.Digest
	}
	home := filepath.Join(dir, ".home")
	defer removeAllForce(home)
	sb := shell.Box{Backend: backend, RunID: id, Agent: "research-" + name, Workspace: box, Home: home,
		Timeout: researchTimeout, MemoryMB: 4096}

	env := research.Environment{Interpreter: interp, Box: backend.Name(), Quilzo: version}
	if v, err := sb.Run(ctx, shell.Command{Path: interpPath, Args: []string{"--version"}}); err == nil && v.Exit == 0 {
		env.Version = strings.TrimSpace(strings.SplitN(strings.TrimSpace(v.Text), "\n", 2)[0])
	}
	out, err := sb.Run(ctx, shell.Command{Path: interpPath, Args: []string{script}, Kind: shell.Kind{Writes: true}})
	if err != nil && out.Stopped == "" {
		out.Stopped = err.Error()
	}
	r := research.Run{ID: id, Project: name, By: caller.Name, Started: started.UTC(),
		Took: time.Since(started).Round(time.Millisecond).String(), Code: research.File{Path: script, Digest: codeDigest, Bytes: codeBytes},
		Environment: env, Exit: out.Exit, Stopped: out.Stopped, Log: out.Text, LogDigest: out.Digest, Rerun: of,
		Idea: idea}
	for _, in := range ins {
		r.Inputs = append(r.Inputs, in.file)
	}
	// What it wrote is its output; the copies it was given, unchanged,
	// are not kept twice.
	err = filepath.WalkDir(box, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(box, p)
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			return os.Remove(p)
		}
		dg, n, err := digestFile(p)
		if err != nil {
			return err
		}
		if copied[rel] == dg {
			return os.Remove(p)
		}
		if rel == "values.json" {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			vs, verr := research.ReadValues(b)
			if verr != nil && r.Stopped == "" {
				r.Stopped = verr.Error()
			}
			r.Values = vs
		}
		r.Outputs = append(r.Outputs, research.File{Path: rel, Digest: dg, Bytes: n})
		return nil
	})
	if err != nil {
		return research.Run{}, err
	}
	sort.Slice(r.Outputs, func(i, j int) bool { return r.Outputs[i].Path < r.Outputs[j].Path })
	if of != "" {
		reproduced, differs := compareRuns(earlier, r)
		r.Reproduced, r.Differs = &reproduced, differs
	}
	if err := st.SaveRun(r); err != nil {
		return r, err
	}
	if _, err := st.Change(name, func(p *research.Project) error {
		if p.DataSeen.IsZero() {
			p.DataSeen = r.Started
		}
		return nil
	}); err != nil {
		return r, err
	}
	d := map[string]string{"run": r.ID, "code": r.Code.Digest, "exit": strconv.Itoa(r.Exit),
		"values": strconv.Itoa(len(r.Values)), "environment": env.Digest()}
	if idea != "" {
		d["idea"] = idea
	}
	action := "research.ran"
	if of != "" {
		action, d["rerun"], d["reproduced"] = "research.reran", of, strconv.FormatBool(*r.Reproduced)
	}
	researchRecord(root, caller, action, name, d)
	return r, nil
}

// compareRuns says whether a re-run gave what the first run did.
func compareRuns(a, b research.Run) (bool, []string) {
	var differs []string
	if a.OK() != b.OK() {
		differs = append(differs, fmt.Sprintf("exit %d, then %d", a.Exit, b.Exit))
	}
	got := map[string]research.Value{}
	for _, v := range b.Values {
		got[v.Name] = v
	}
	for _, v := range a.Values {
		w, ok := got[v.Name]
		switch {
		case !ok:
			differs = append(differs, v.Name+" was not written again")
		case math.Abs(v.Value-w.Value) > 1e-9*math.Max(1, math.Abs(v.Value)):
			differs = append(differs, fmt.Sprintf("%s %s, then %s", v.Name, research.Format(v.Value, v.Unit), research.Format(w.Value, w.Unit)))
		}
	}
	files := map[string]string{}
	for _, f := range b.Outputs {
		files[f.Path] = f.Digest
	}
	for _, f := range a.Outputs {
		if f.Path == "values.json" {
			continue
		}
		switch d, ok := files[f.Path]; {
		case !ok:
			differs = append(differs, f.Path+" was not written again")
		case d != f.Digest:
			differs = append(differs, f.Path+" differs")
		}
	}
	return len(differs) == 0, differs
}

func researchRerun(ctx context.Context, root, name, id string, caller *Caller) (research.Run, error) {
	earlier, err := researchStore(root).LoadRun(name, id)
	if err != nil {
		return research.Run{}, err
	}
	return researchRunScript(ctx, root, name, "", nil, id, caller, earlier.Idea)
}

func printRun(r research.Run) {
	state := "finished"
	if !r.OK() {
		state = fmt.Sprintf("failed (exit %d) %s", r.Exit, r.Stopped)
	}
	fmt.Printf("%s %s %s in %s, %s %s\n", r.ID, r.Code.Path, state, r.Took, r.Environment.Interpreter, r.Environment.Version)
	for _, v := range r.Values {
		fmt.Printf("  %s = %s\n", v.Name, research.Format(v.Value, v.Unit))
	}
	for _, f := range r.Outputs {
		fmt.Printf("  wrote %s  %s\n", f.Path, f.Digest[:12])
	}
	if r.Reproduced != nil {
		if *r.Reproduced {
			fmt.Printf("  reproduced %s: the same numbers and files\n", r.Rerun)
		} else {
			fmt.Printf("  did not reproduce %s: %s\n", r.Rerun, strings.Join(r.Differs, "; "))
		}
	}
	if !r.OK() && r.Log != "" {
		fmt.Println(r.Log)
	}
}

func researchClaim(root, name, runID string, values []string, caller *Caller) ([]research.Claim, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return nil, err
	}
	st := researchStore(root)
	r, err := st.LoadRun(name, runID)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		for _, v := range r.Values {
			values = append(values, v.Name)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("%s wrote down no values (values.json)", runID)
		}
	}
	var out []research.Claim
	_, err = st.Change(name, func(p *research.Project) error {
		for _, v := range values {
			c, err := research.Pin(p, r, v, caller.Name, time.Now())
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	researchRecord(root, caller, "research.claimed", name, map[string]string{"run": runID,
		"values": clampString(strings.Join(values, " "), 300)})
	return out, nil
}

func researchSearch(ctx context.Context, root, query string, n int, caller *Caller) ([]research.Candidate, error) {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return nil, err
	}
	return researchIndex(root).Search(ctx, plaintext.Clean(query), n)
}

func researchCite(ctx context.Context, root, name, ident, key string, caller *Caller) (research.Source, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return research.Source{}, err
	}
	id, err := research.ParseIdentifier(ident)
	if err != nil {
		return research.Source{}, err
	}
	st := researchStore(root)
	if _, err := st.Load(name); err != nil {
		return research.Source{}, err
	}
	src, err := researchIndex(root).Resolve(ctx, id)
	if errors.Is(err, research.ErrNotFound) {
		return research.Source{}, fmt.Errorf("%s did not resolve: no open index has it, so it is not cited", id)
	}
	if err != nil {
		return research.Source{}, fmt.Errorf("resolving %s: %w", id, err)
	}
	src.By, src.Resolved = caller.Name, time.Now().UTC()
	_, err = st.Change(name, func(p *research.Project) error {
		src.Key = key
		if src.Key == "" {
			taken := map[string]bool{}
			for _, s := range p.Sources {
				if s.ID == src.ID {
					src.Key = s.Key
				}
				taken[s.Key] = true
			}
			if src.Key == "" {
				src.Key = research.SuggestKey(src, taken)
			}
		}
		return research.AddSource(p, src)
	})
	if err != nil {
		return research.Source{}, err
	}
	researchRecord(root, caller, "research.cited", name, map[string]string{"cited_as": src.Key, "work": id.String(),
		"resolver": src.Resolver})
	return src, nil
}

func researchQuote(root, name, key, passage string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	passage = strings.TrimSpace(plaintext.Clean(passage))
	if passage == "" || len(passage) > research.MaxPassage {
		return fmt.Errorf("a passage is between 1 and %d characters", research.MaxPassage)
	}
	_, err := researchStore(root).Change(name, func(p *research.Project) error {
		for i := range p.Sources {
			if p.Sources[i].Key == key {
				if len(p.Sources[i].Passages) >= 50 {
					return errors.New("a source holds at most 50 quoted passages")
				}
				p.Sources[i].Passages = append(p.Sources[i].Passages, research.Passage{Text: passage, By: caller.Name})
				return nil
			}
		}
		return fmt.Errorf("%s cites nothing as [@%s]", name, key)
	})
	if err != nil {
		return err
	}
	researchRecord(root, caller, "research.quoted", name, map[string]string{"cited_as": key,
		"digest": research.Digest(passage)})
	return nil
}

func researchWrite(root, name, text string, caller *Caller) ([]research.Finding, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return nil, err
	}
	text = plaintext.Clean(text)
	if len(text) > research.MaxReport {
		return nil, fmt.Errorf("a report is at most %d bytes", research.MaxReport)
	}
	p, err := researchStore(root).Change(name, func(p *research.Project) error {
		p.Report, p.ReportBy, p.ReportEdited = text, caller.Name, time.Now().UTC()
		return nil
	})
	if err != nil {
		return nil, err
	}
	runs, _ := researchStore(root).Runs(name)
	fs := research.Check(p, runs)
	researchRecord(root, caller, "research.written", name, map[string]string{"digest": research.Digest(text),
		"problems": strconv.Itoa(research.Problems(fs))})
	return fs, nil
}

func researchCheck(root, name string, caller *Caller) (research.Project, []research.Finding, error) {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return research.Project{}, nil, err
	}
	st := researchStore(root)
	p, err := st.Load(name)
	if err != nil {
		return p, nil, err
	}
	runs, err := st.Runs(name)
	if err != nil {
		return p, nil, err
	}
	return p, research.Check(p, runs), nil
}

func researchReport(root, name string, caller *Caller) (string, error) {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return "", err
	}
	st := researchStore(root)
	p, err := st.Load(name)
	if err != nil {
		return "", err
	}
	runs, err := st.Runs(name)
	if err != nil {
		return "", err
	}
	return research.Markdown(p, runs), nil
}
