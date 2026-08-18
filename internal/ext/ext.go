// Package ext runs extensions: third-party code that observes or transforms
// content, without being linked into this program.
//
// This is the OSGi-shaped hole. Competitors ship a plugin container — dynamic
// bundles, versioned, hot-loadable, sharing a process with the CMS — and it is
// genuinely the feature customers ask for, because "we need it to do one thing
// your product does not" is the normal state of an enterprise deployment.
//
// Three ways to provide it, and the constraint decides between them.
//
//	Go's plugin package. Same compiler, same flags, same dependency versions,
//	no unloading, and a crash in the plugin is a crash in the CMS. Nobody ships
//	this on purpose.
//
//	WebAssembly, which is the right answer in 2026 — capability-based, no
//	ambient authority, a component starts able to do nothing. It needs a
//	runtime, and every usable one is a third-party dependency. This program has
//	none and refuses them in CI, so this door is closed. That is a real cost of
//	the zero-dependency policy and worth naming rather than pretending the
//	chosen design was first choice.
//
//	A subprocess speaking a defined protocol. What Terraform, the language
//	servers and every editor plugin system settled on. No dependency, and the
//	isolation comes from the operating system, which is better at it than a
//	library would be: a separate address space, a separate lifetime, and a
//	crash that kills the extension rather than the CMS.
//
// So: subprocesses, over JSON on stdin and stdout, with a manifest declaring
// what the extension is allowed to see and do. The manifest is the interesting
// half. An extension gets exactly the fields it declares and nothing else — not
// the page, not the store, not the environment — because the alternative is
// that every extension sees every credential in the process that started it.
//
// What this deliberately does not do:
//
//   - No network. Not "no network by default": none. An extension that needs to
//     call something is a webhook, which this program already has, and which is
//     audited and rate-limited and does not run inside a publish.
//   - No writing to the store. An extension returns a value; the host decides
//     what to do with it. Handing a subprocess the store would make every
//     extension able to rewrite history.
//   - No unbounded anything. Time, output and payload are all capped, and the
//     operation continues without the extension when it exceeds them.
package ext

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Hook is when an extension runs.
type Hook string

const (
	// OnValidate is called with a page before it is stored, and may refuse it.
	// The most useful hook and the safest: refusing is the only thing it can
	// do, so a broken extension blocks work rather than corrupting it.
	OnValidate Hook = "validate"
	// OnTransform is called with declared fields and may return replacements.
	// The dangerous one, and the reason the manifest exists: an extension that
	// can rewrite content is an extension that can rewrite content into a
	// script tag, so its output goes through the same escaping and the same
	// content-type gate as anything an author typed.
	OnTransform Hook = "transform"
	// OnPublish is called after the live pointer moves. Advisory only: the
	// publish has happened and nothing this returns can undo it, which is
	// stated so nobody builds an approval gate out of it.
	OnPublish Hook = "publish"
)

func (h Hook) Valid() bool {
	return h == OnValidate || h == OnTransform || h == OnPublish
}

// Manifest is what an extension declares about itself.
//
// Declared, not discovered. An extension that could ask for a field at call
// time would be an extension whose reach nobody can review — the manifest is
// the thing an operator reads before deciding to run it, and it is only worth
// reading if it is complete.
type Manifest struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	// Command is the executable and its arguments.
	Command []string `json:"command"`
	// Hooks are when it runs.
	Hooks []Hook `json:"hooks"`
	// Fields are the content fields it is sent. Empty means none — not all.
	//
	// The direction matters: an extension that gets everything by default is
	// one that sees the unpublished legal review because somebody added a
	// field last Tuesday.
	Fields []string `json:"fields"`
	// Optional says the operation may continue when this extension cannot
	// run. The default — false — blocks.
	//
	// The default is the whole point, and it is the same lesson the
	// accessibility gate taught: a check that could not run must not exit like
	// a check that passed. An extension registered to validate content exists
	// to refuse some of it, so if it crashes, times out, or fails its pin,
	// nothing validated that page and storing it anyway records a check that
	// did not happen.
	//
	// The counter-argument is real: a flaky extension then makes the CMS
	// flaky. That is a decision an operator should make per extension and with
	// their eyes open, which is what this field is. A house-style linter is
	// Optional; a compliance rule is not.
	Optional bool `json:"optional,omitempty"`
	// SHA256 pins the executable. The binary that runs is the binary that was
	// reviewed; without this, replacing the file on disk replaces the code
	// with no record and no signal.
	SHA256 string `json:"sha256,omitempty"`
}

// Validate refuses a manifest that cannot be run safely.
func (m Manifest) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("an extension needs a name")
	}
	if len(m.Command) == 0 {
		return fmt.Errorf("%s declares no command", m.Name)
	}
	if len(m.Hooks) == 0 {
		return fmt.Errorf("%s declares no hooks, so it would never run", m.Name)
	}
	for _, h := range m.Hooks {
		if !h.Valid() {
			return fmt.Errorf("%s declares unknown hook %q", m.Name, h)
		}
	}
	for _, f := range m.Fields {
		if strings.ContainsAny(f, " \t\n") {
			return fmt.Errorf("%s declares a field name with whitespace: %q",
				m.Name, f)
		}
	}
	// A relative command would resolve against the working directory, which is
	// wherever the operator happened to be. That is how "./quilzo publish" in
	// a checkout runs a binary from the checkout.
	if !strings.HasPrefix(m.Command[0], "/") {
		return fmt.Errorf(
			"%s must give an absolute path to its command, not %q: a relative "+
				"one resolves against whatever directory the operator was in",
			m.Name, m.Command[0])
	}
	return nil
}

// Limits bound one call.
type Limits struct {
	Timeout    time.Duration
	MaxOutput  int
	RequirePin bool
	// Wrap rewrites the command line before it is run, so a host can put the
	// extension inside a sandbox.
	//
	// A hook rather than the sandbox itself, because this package must not
	// know where the binary is or how the host chooses to confine things — and
	// because the confinement is Linux-only, while this is not. Nil runs the
	// command directly, which is what every existing caller does and what the
	// tests here rely on.
	//
	// The host that sets this is cmd/quilzo, which re-executes itself as a
	// shim: Landlock restricts a thread and execve keeps the domain, so the
	// extension starts already confined. See internal/sandbox for why that is
	// the only correct sequence from Go.
	Wrap func(argv []string) []string
}

func (l Limits) withDefaults() Limits {
	if l.Timeout <= 0 {
		l.Timeout = 5 * time.Second
	}
	if l.MaxOutput <= 0 {
		l.MaxOutput = 1 << 20
	}
	return l
}

// Request is what an extension is sent.
type Request struct {
	Hook Hook   `json:"hook"`
	Page string `json:"page"`
	// Fields holds only what the manifest declared.
	Fields map[string]any `json:"fields"`
}

// Response is what it may return.
type Response struct {
	// Refuse blocks the operation, with Reason shown to the author.
	Refuse bool   `json:"refuse,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Fields replaces declared fields. Keys outside the manifest are dropped
	// rather than refused, because an extension returning an extra field is
	// usually a version skew and failing the publish over it is worse than
	// ignoring it — but it is reported, so the skew is visible.
	Fields map[string]any `json:"fields,omitempty"`
	// Note is recorded in the audit log.
	Note string `json:"note,omitempty"`
}

// Result is what the host gets back.
type Result struct {
	Extension string
	Response  Response
	// Dropped names fields the extension returned that it had not declared.
	Dropped []string
	// Err is set when the extension failed, timed out, or could not be run.
	// The operation continues: an extension is not permitted to take a publish
	// down by crashing, and the failure is recorded instead.
	Err  error
	Took time.Duration
}

// Runner executes extensions.
type Runner struct {
	Limits Limits
	// Now is for tests.
	Now func() time.Time
}

// Run calls one extension.
func (r *Runner) Run(ctx context.Context, m Manifest, req Request) Result {
	lim := r.Limits.withDefaults()
	started := time.Now()
	res := Result{Extension: m.Name}

	if err := m.Validate(); err != nil {
		res.Err = err
		return res
	}
	if lim.RequirePin {
		if m.SHA256 == "" {
			res.Err = fmt.Errorf(
				"%s has no recorded hash and ext.require_pinned is on. Record "+
					"one with `quilzo ext pin %s`", m.Name, m.Name)
			return res
		}
		sum, err := hashFile(m.Command[0])
		if err != nil {
			res.Err = fmt.Errorf("%s: cannot hash %s: %w", m.Name, m.Command[0], err)
			return res
		}
		if sum != m.SHA256 {
			res.Err = fmt.Errorf(
				"%s does not match its recorded hash. The binary on disk is "+
					"not the one that was reviewed:\n  recorded %s\n  found    %s",
				m.Name, short(m.SHA256), short(sum))
			return res
		}
	}

	// Only the declared fields. Built fresh rather than filtered in place, so
	// a field added to a page later cannot appear in a request through a
	// manifest nobody re-read.
	sent := Request{Hook: req.Hook, Page: req.Page, Fields: map[string]any{}}
	for _, f := range m.Fields {
		if v, ok := req.Fields[f]; ok {
			sent.Fields[f] = v
		}
	}

	body, err := json.Marshal(sent)
	if err != nil {
		res.Err = err
		return res
	}

	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	argv := m.Command
	if lim.Wrap != nil {
		argv = lim.Wrap(argv)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)

	// Killing the extension has to kill what the extension started.
	//
	// CommandContext signals the direct child only, and Wait then blocks until
	// the output pipes close — which a surviving grandchild holds open. A
	// three-line shell script that runs `sleep 30` therefore held a publish for
	// the full thirty seconds despite a timeout of three hundred milliseconds,
	// which a test caught by measuring how long the timeout took to happen.
	//
	// Two changes, and both are needed. A process group so the signal reaches
	// everything the extension spawned, and WaitDelay so that even if something
	// survives the signal, the pipes are closed and this returns anyway. The
	// first is the fix; the second is the guarantee, because an extension can
	// always find a way to keep a descendant alive and the host must not care.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid: the whole group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second

	// An empty environment.
	//
	// Not a filtered one: an allow-list of variables is a list somebody
	// forgets to update, and the process this inherits from holds tokens,
	// store paths and whatever the operator's shell had in it. An extension
	// that needs configuration gets it on stdin, where it is visible in the
	// manifest.
	cmd.Env = []string{}
	// And no working directory of consequence. It still has whatever
	// filesystem access its uid has — that is the operating system's business
	// and this cannot change it, which is why the manifest tells an operator
	// to run extensions as an account that owns nothing.
	cmd.Dir = os.TempDir()
	cmd.Stdin = strings.NewReader(string(body))

	var stdout, stderr strings.Builder
	cmd.Stdout = &limitedWriter{w: &stdout, n: lim.MaxOutput}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 4096}

	runErr := cmd.Run()
	res.Took = time.Since(started)

	if ctx.Err() == context.DeadlineExceeded {
		res.Err = fmt.Errorf("%s did not answer within %s", m.Name, lim.Timeout)
		return res
	}
	if runErr != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			res.Err = fmt.Errorf("%s failed: %v: %s", m.Name, runErr, firstLine(detail))
		} else {
			res.Err = fmt.Errorf("%s failed: %v", m.Name, runErr)
		}
		return res
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		// Silence is agreement. An extension that has nothing to say should
		// not have to say so, and requiring an empty JSON object would make
		// the simplest possible extension a program rather than a script.
		return res
	}
	if err := json.Unmarshal([]byte(out), &res.Response); err != nil {
		res.Err = fmt.Errorf("%s returned something that is not a response: %w",
			m.Name, err)
		return res
	}

	// Keys outside the manifest are dropped and named.
	if len(res.Response.Fields) > 0 {
		declared := map[string]bool{}
		for _, f := range m.Fields {
			declared[f] = true
		}
		for k := range res.Response.Fields {
			if !declared[k] {
				res.Dropped = append(res.Dropped, k)
				delete(res.Response.Fields, k)
			}
		}
		sort.Strings(res.Dropped)
	}
	return res
}

// limitedWriter stops an extension filling memory by talking.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		// Reported as written so the child is not killed by a broken pipe
		// mid-sentence, which would surface as a confusing exec error rather
		// than as the limit it is.
		return len(p), nil
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.w.Write(p)
	l.n -= n
	return len(p), err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReader(f)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Pin computes the hash to record for an extension's binary.
func Pin(path string) (string, error) { return hashFile(path) }

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
