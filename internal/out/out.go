// Package out decides how the CLI talks, to a person or to a program.
//
// # Why this exists
//
// The measured case against MCP is real: naive servers preload every tool schema
// into the context window, and comparisons through 2026 put that at roughly 35x
// the tokens of an equivalent CLI call, with reliability falling as the tool
// count grows. A shell command costs a couple of hundred tokens because the
// model already knows bash and reads `--help` only when it needs to.
//
// But that comparison quietly assumes the CLI's *output* is usable. A tool that
// answers in coloured English prose has not removed the parsing problem, it has
// moved it: the agent now writes a regex against a sentence somebody will
// reword. Schema bloat is traded for parsing fragility, which is worse, because
// schema bloat is merely expensive and a mis-parse is silently wrong.
//
// So this package holds two rules.
//
// **Colour only for a terminal.** Escape codes in piped output corrupt anything
// reading it. Every earlier demo of this CLI leaked `\033[2m` into captured
// output, which is exactly the failure being described. `NO_COLOR` is honoured
// because it is the convention, and a non-terminal disables colour regardless.
//
// **A machine mode that is not the human mode with the paint removed.** `--json`
// emits a stable document with the fields a caller needs, not a transcription of
// the prose. Prose is free to improve; the JSON is a contract.
package out

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Mode is how output should be rendered.
type Mode int

const (
	// Human is prose, coloured if the destination is a terminal.
	Human Mode = iota
	// JSON is one document on stdout and nothing else.
	JSON
)

// Writer carries the decision so no code has to re-derive it.
type Writer struct {
	Mode   Mode
	Colour bool
	Out    io.Writer
	Err    io.Writer
}

// New builds a Writer for the process.
//
// Colour is enabled only when writing to a character device and NO_COLOR is
// unset. Guessing wrongly in this direction is what puts escape codes into a
// log file, a pipe, or an agent's transcript.
func New(jsonMode bool) *Writer {
	w := &Writer{Out: os.Stdout, Err: os.Stderr}
	if jsonMode {
		w.Mode = JSON
		return w // never coloured; JSON is for a parser
	}
	w.Colour = isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == ""
	return w
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Colour codes. Empty strings when colour is off, so call sites stay unchanged
// rather than sprouting conditionals.
func (w *Writer) c(code string) string {
	// The mode is checked as well as the flag, so JSON cannot be coloured even
	// if a caller sets Colour. New() already avoids that combination, but
	// relying on construction discipline means the invariant breaks the first
	// time someone wires Colour to a --color flag and forgets the interaction.
	// Make it impossible rather than unlikely.
	if w.Mode == JSON || !w.Colour {
		return ""
	}
	return code
}

func (w *Writer) Bold() string   { return w.c("\033[1m") }
func (w *Writer) Dim() string    { return w.c("\033[2m") }
func (w *Writer) Green() string  { return w.c("\033[32m") }
func (w *Writer) Yellow() string { return w.c("\033[33m") }
func (w *Writer) Red() string    { return w.c("\033[31m") }
func (w *Writer) Reset() string  { return w.c("\033[0m") }

// Human writes prose. A no-op in JSON mode, so a command can call it freely
// without wrapping every line in a mode check.
func (w *Writer) Human(format string, args ...any) {
	if w.Mode == JSON {
		return
	}
	fmt.Fprintf(w.Out, format, args...)
}

// JSON writes the machine document and reports whether it did.
//
// Returning a bool lets a command do `if w.JSON(doc) { return nil }` and then
// carry on with prose, which keeps the two renderings adjacent in the source
// where they are easiest to keep in step.
func (w *Writer) JSON(v any) bool {
	if w.Mode != JSON {
		return false
	}
	enc := json.NewEncoder(w.Out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(w.Err, "cannot encode output: %v\n", err)
	}
	return true
}

// Error reports a failure in whichever form the caller can read.
//
// In JSON mode this still goes to stderr, leaving stdout holding exactly one
// document or nothing at all. A caller that has to distinguish an error object
// from a result object on the same stream is being made to do work for no
// reason.
func (w *Writer) Error(err error) {
	if err == nil {
		return
	}
	if w.Mode == JSON {
		enc := json.NewEncoder(w.Err)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]string{"error": err.Error()})
		return
	}
	fmt.Fprintf(w.Err, "%s%v%s\n", w.Red(), err, w.Reset())
}

// Exit codes, fixed and documented.
//
// An agent branching on output text breaks the first time somebody rewords a
// sentence. Branching on an exit code does not, so the codes are part of the
// interface and are listed in `scrivet help`.
const (
	OK              = 0 // did what was asked
	ExitFailure     = 1 // the operation failed
	ExitUsage       = 2 // the command was wrong
	ExitBlocked     = 3 // refused by a gate: accessibility, provenance, permission
	ExitNotFound    = 4 // the thing asked for does not exist
	ExitUnavailable = 5 // a dependency was missing, e.g. no template to render
)

// Describe names an exit code, for help output.
func Describe(code int) string {
	switch code {
	case OK:
		return "success"
	case ExitFailure:
		return "the operation failed"
	case ExitUsage:
		return "the command was used incorrectly"
	case ExitBlocked:
		return "refused by a gate (accessibility, provenance, permission)"
	case ExitNotFound:
		return "not found"
	case ExitUnavailable:
		return "a required dependency was missing"
	}
	return "unknown"
}
