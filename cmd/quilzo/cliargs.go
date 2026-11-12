// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"strings"
)

// One rule for the words on a command line: a word a command does not take
// is refused, with the command's usage and exit 2, and is never dropped or
// read as something else.
//
// Go's flag package stops at the first word that is not a flag and leaves
// the rest in fs.Args(), which most commands never looked at. So whatever
// followed an unquoted value was thrown away with every flag after it:
// `auth grant fay publisher --note covering for Bea --for 30d --on /news`
// made a permanent grant on the whole site, `rollback 2` went back one
// publication, `init mysite` made ./.quilzo, and `auth deny`, which put its
// --deny at the end of the line, granted the role it was asked to deny.
// Each command parsing for itself is how the check was missing from all of
// them at once, so it is made here, in the helpers they share.

// errMisused is a command line that does not parse. It exits 2, which the
// help documents as "misused", rather than 1, which is a command that ran
// and failed.
type errMisused struct{ error }

func (e errMisused) Unwrap() error { return e.error }

// invoked is the command and the arguments main dispatched, so that a
// refusal can quote the lines of the help about the command rather than a
// flag set's bare name. Empty in a test that calls a command directly.
var invoked struct {
	cmd  string
	args []string
}

// parseFlags parses fs's flags wherever they stand among args, adds the
// positional arguments to *pos until it holds n of them, and refuses a word
// past those. pos may be nil for a command that takes nothing but flags.
//
// Wherever, because leadingArgs gathered names only up to the first flag:
// `auth grant --on /news fay publisher` found no names and answered with its
// usage, while `agent new --kind operator b2` took the same order.
// Everything after "--" is positional, as the flag package has it.
func parseFlags(fs *flag.FlagSet, args []string, pos *[]string, n int) error {
	got, at, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	have := 0
	if pos != nil {
		have = len(*pos)
	}
	if have+len(got) > n {
		i := max(n-have, 0)
		return strayWord(fs, args, at[i], have > 0 || i > 0)
	}
	if pos != nil {
		*pos = append(*pos, got...)
	}
	return nil
}

// parseInterspersed is the loop under parseFlags and parseAnywhere: each
// positional argument and where it stood in args.
func parseInterspersed(fs *flag.FlagSet, args []string) (pos []string, at []int, err error) {
	off := 0
	for off <= len(args) {
		if err := fs.Parse(args[off:]); err != nil {
			return nil, nil, err
		}
		rest := fs.Args()
		next := len(args) - len(rest)
		// "--" ends the flags: what follows belongs to whatever the command
		// hands it to, a program's own --root among it, and is not parsed.
		if next > off && args[next-1] == "--" {
			for i := next; i < len(args); i++ {
				pos, at = append(pos, args[i]), append(at, i)
			}
			return pos, at, nil
		}
		if len(rest) == 0 {
			return pos, at, nil
		}
		pos, at = append(pos, rest[0]), append(at, next)
		off = next + 1
	}
	return pos, at, nil
}

// strayWord is the refusal of args[i], a word the command does not take.
//
// It says what the word most likely was. A word after a flag's value is the
// rest of that value, unquoted, as `--note contract ended` is: the hint
// quotes the value back so the line can be typed again as it was meant. A
// word after the names a command takes (afterName) is the rest of the last
// of them, as `note add index the price is wrong` is.
func strayWord(fs *flag.FlagSet, args []string, i int, afterName bool) error {
	name := "this command"
	if invoked.cmd != "" {
		name = "quilzo " + invoked.cmd
		// The subcommand, where the first word is one: the help has lines
		// of its own for it. `lock about` is a page.
		if len(invoked.args) > 0 && !strings.HasPrefix(invoked.args[0], "-") &&
			helpFor(invoked.cmd, invoked.args[:1]) != helpFor(invoked.cmd, nil) {
			name += " " + invoked.args[0]
		}
	}
	msg := fmt.Sprintf("usage: %s does not take %q", name, args[i])
	if flagAt, value := valueBefore(fs, args, i); flagAt >= 0 {
		end := i + 1
		for end < len(args) && !strings.HasPrefix(args[end], "-") {
			end++
		}
		words := strings.Join(append(value, args[i:end]...), " ")
		flagName, _, _ := strings.Cut(args[flagAt], "=")
		msg += fmt.Sprintf("; if it is part of %s's value, the value goes in quotes: %s %q", flagName, flagName, words)
	} else if afterName {
		msg += "; words that go together go in quotes"
	}
	if help := helpFor(invoked.cmd, invoked.args); invoked.cmd != "" && help != "" {
		msg += "\n" + strings.TrimRight(help, "\n")
	}
	return errMisused{fmt.Errorf("%s", msg)}
}

// valueBefore finds the flag whose value args[i] follows, if the words
// between them are all that value's: the flag's index and its value's
// words, or -1.
func valueBefore(fs *flag.FlagSet, args []string, i int) (int, []string) {
	for j := i - 1; j >= 0; j-- {
		a := args[j]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		if a == "--" {
			return -1, nil
		}
		name, inline, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			return -1, nil
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			return -1, nil
		}
		// The flag's own value, then the words between it and args[i]; any
		// more than one word there were not its value but a positional
		// argument, and the hint would be wrong.
		if hasValue {
			if j != i-1 {
				return -1, nil
			}
			return j, []string{inline}
		}
		if j != i-2 {
			return -1, nil
		}
		return j, []string{args[j+1]}
	}
	return -1, nil
}

// positionals is parseFlags for a command that takes no flags: up to n
// names, and a word or a flag past them refused. The commands that read
// names with leadingArgs and threw the rest away took `assistant remove
// help now` as `assistant remove help`.
func positionals(args []string, n int) ([]string, error) {
	var pos []string
	if err := parseFlags(flag.NewFlagSet("arguments", flag.ContinueOnError), args, &pos, n); err != nil {
		return nil, err
	}
	return pos, nil
}

// noArguments refuses anything after a subcommand that takes nothing. Such a
// subcommand was called with the store's root alone, so what followed it was
// never read: `config show site.name` showed all of the settings and said
// nothing of the key, and `verify everything` checked what it always checks.
func noArguments(args []string) error {
	_, err := positionals(args, 0)
	return err
}
