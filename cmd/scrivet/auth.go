package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
)

// Access lives beside the content rather than inside it. The object store is
// append-only and content-addressed; access changes are neither, and pretending
// otherwise would mean a revocation that could never be forgotten.

// leadingArgs splits positional arguments from the flags that follow them.
//
// Go's flag package stops parsing at the first argument that does not start
// with a dash, so `auth explain dana publish --on /legal` parses no flags at
// all and silently answers about "/" instead. In an access-control tool that is
// not an inconvenience — it is a confident wrong answer about who can do what.
//
// Splitting first lets the command read the way people write it.
func leadingArgs(args []string, n int) (pos []string, rest []string) {
	for i, a := range args {
		if len(pos) == n || strings.HasPrefix(a, "-") {
			return pos, args[i:]
		}
		pos = append(pos, a)
	}
	return pos, nil
}

func policyPath(root string) string { return filepath.Join(root, "policy.json") }
func tokensPath(root string) string { return filepath.Join(root, "tokens.json") }

func loadJSON(path string, into any) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // absent is empty, which is deny-by-default
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// 0600: the token file holds hashes, and the policy names who can publish.
	// Neither is world-readable material.
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func loadPolicy(root string) (*auth.Policy, error) {
	p := &auth.Policy{}
	return p, loadJSON(policyPath(root), p)
}

func loadTokens(root string) (*auth.TokenStore, error) {
	ts := &auth.TokenStore{}
	return ts, loadJSON(tokensPath(root), ts)
}

func cmdAuth(root string, args []string) error {
	if len(args) == 0 {
		return authUsage()
	}
	switch args[0] {
	case "grant":
		return authGrant(root, args[1:])
	case "revoke":
		return authRevoke(root, args[1:])
	case "list":
		return authList(root)
	case "explain":
		return authExplain(root, args[1:])
	case "roles":
		return authRoles()
	default:
		fmt.Fprintf(os.Stderr, "unknown auth command %q\n\n", args[0])
		return authUsage()
	}
}

func authUsage() error {
	fmt.Print(`scrivet auth — who can do what

  grant <principal> <role> [--on /path] [--deny] [--note "..."]
  revoke <principal> <role> [--on /path]
  list
  explain <principal> <action> [--on /path]
  roles

Four roles, in order. Each includes the ones below it:

`)
	for _, r := range auth.Roles {
		fmt.Printf("  %-10s %s\n", r, r.Describe())
	}
	fmt.Print(`
A grant on /blog covers everything under it. A deny wins wherever it sits, so
"publisher everywhere except /legal" is two bindings rather than a broad grant
you meant to narrow later.
`)
	return nil
}

func authRoles() error {
	fmt.Printf("%sroles%s\n", bold, reset)
	for _, r := range auth.Roles {
		fmt.Printf("  %-10s %s\n", r, r.Describe())
	}
	fmt.Printf("\n%sactions, and the role each needs%s\n", bold, reset)
	for _, a := range auth.Actions() {
		need, _ := auth.Needs(a)
		fmt.Printf("  %-14s %s\n", a, need)
	}
	fmt.Printf("\n  %sthat is the whole model — there are no custom roles and no\n"+
		"  permission assembly, because that is how a role surface stops being\n"+
		"  reviewable%s\n", dim, reset)
	return nil
}

func authGrant(root string, args []string) error {
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	on := fs.String("on", "/", "resource path the binding covers")
	deny := fs.Bool("deny", false, "deny instead of grant; a deny always wins")
	note := fs.String("note", "", "why this access exists")
	by := fs.String("by", "cli", "who granted it")
	rest, flags := leadingArgs(args, 2)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 2 {
		return fmt.Errorf("usage: scrivet auth grant <principal> <role> [--on /path] [--deny]")
	}

	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	b := auth.Binding{
		Principal: rest[0], Role: auth.Role(rest[1]), Resource: *on,
		Deny: *deny, GrantedBy: *by, Note: *note,
	}
	if err := p.Grant(b); err != nil {
		return err
	}
	if err := saveJSON(policyPath(root), p); err != nil {
		return err
	}

	verb := "granted"
	if *deny {
		verb = "denied"
	}
	fmt.Printf("%s %s to %s on %s\n", verb, rest[1], rest[0], *on)
	// Show the consequence immediately. A grant whose effect you have to work
	// out later is one nobody checks.
	fmt.Printf("  %s%s can now: ", dim, rest[0])
	var can []string
	for _, a := range auth.Actions() {
		if p.Evaluate(rest[0], a, *on).Allowed {
			can = append(can, string(a))
		}
	}
	if len(can) == 0 {
		fmt.Printf("nothing on %s%s\n", *on, reset)
	} else {
		fmt.Printf("%s on %s%s\n", strings.Join(can, ", "), *on, reset)
	}
	return nil
}

func authRevoke(root string, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	on := fs.String("on", "/", "resource path the binding covered")
	rest, flags := leadingArgs(args, 2)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 2 {
		return fmt.Errorf("usage: scrivet auth revoke <principal> <role> [--on /path]")
	}

	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	n := p.Revoke(rest[0], auth.Role(rest[1]), *on)
	if n == 0 {
		return fmt.Errorf("no binding matched %s %s on %s", rest[0], rest[1], *on)
	}
	if err := saveJSON(policyPath(root), p); err != nil {
		return err
	}
	fmt.Printf("removed %d binding(s)\n", n)
	// Inherited access survives revoking a narrow binding, and someone who does
	// not notice will think they removed access they did not.
	if d := p.Evaluate(rest[0], auth.ActView, *on); d.Allowed {
		fmt.Printf("  %s%s still has %s on %s — %s%s\n",
			yellow, rest[0], d.Role, *on, d.Reason, reset)
	}
	return nil
}

func authList(root string) error {
	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	if len(p.Bindings) == 0 {
		fmt.Println("no bindings; nobody has access")
		return nil
	}
	fmt.Printf("  %-18s %-10s %-16s %s\n", "principal", "role", "resource", "")
	fmt.Printf("  %s %s %s\n", strings.Repeat("-", 18), strings.Repeat("-", 10),
		strings.Repeat("-", 16))
	for _, b := range p.Bindings {
		mark := ""
		if b.Deny {
			mark = red + "DENY" + reset
		}
		fmt.Printf("  %-18s %-10s %-16s %s", b.Principal, b.Role, b.Resource, mark)
		if b.Note != "" {
			fmt.Printf("  %s%s%s", dim, b.Note, reset)
		}
		fmt.Println()
	}
	return nil
}

// authExplain is the command that makes this model usable.
//
// Google needed a separate Policy Troubleshooter product because working out why
// someone has access is genuinely hard once inheritance is in play. If that
// answer is hard to get, nobody audits, and access quietly drifts upward.
func authExplain(root string, args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	on := fs.String("on", "/", "resource path")
	rest, flags := leadingArgs(args, 2)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) < 1 {
		return fmt.Errorf("usage: scrivet auth explain <principal> [action] [--on /path]")
	}
	principal := rest[0]

	p, err := loadPolicy(root)
	if err != nil {
		return err
	}

	if len(rest) == 1 {
		fmt.Printf("%s%s on %s%s\n\n", bold, principal, *on, reset)
		for _, a := range auth.Actions() {
			d := p.Evaluate(principal, a, *on)
			mark := red + "no " + reset
			if d.Allowed {
				mark = green + "yes" + reset
			}
			fmt.Printf("  %s  %-14s %s%s%s\n", mark, a, dim, d.Reason, reset)
		}
		return nil
	}

	d := p.Evaluate(principal, auth.Action(rest[1]), *on)
	verdict := red + "DENIED" + reset
	if d.Allowed {
		verdict = green + "ALLOWED" + reset
	}
	fmt.Printf("%s  %s %s on %s\n\n", verdict, principal, rest[1], *on)
	fmt.Printf("  %s\n", d.Reason)
	if d.Binding != nil {
		fmt.Printf("  %sdeciding binding: %s %s on %s%s\n",
			dim, d.Binding.Principal, d.Binding.Role, d.Binding.Resource, reset)
	}
	if len(d.Trail) > 0 {
		fmt.Printf("\n  %sconsidered:%s\n", bold, reset)
		for _, line := range d.Trail {
			fmt.Printf("    %s%s%s\n", dim, line, reset)
		}
	}
	if !d.Allowed {
		return fmt.Errorf("not permitted")
	}
	return nil
}

// -- tokens -------------------------------------------------------------------

func cmdToken(root string, args []string) error {
	if len(args) == 0 {
		fmt.Print(`scrivet token — credentials for API access

  issue <name> --principal <who> --role <role> [--on /path] [--ttl 720h]
  list
  revoke <id>
  stale [--idle 720h]

Tokens start with ` + auth.TokenPrefix + ` so a secret scanner can spot one in a repository.
Only a hash is stored, so the secret is shown exactly once and cannot be
recovered from this machine.
`)
		return nil
	}
	switch args[0] {
	case "issue":
		return tokenIssue(root, args[1:])
	case "list":
		return tokenList(root)
	case "revoke":
		return tokenRevoke(root, args[1:])
	case "stale":
		return tokenStale(root, args[1:])
	default:
		return fmt.Errorf("unknown token command %q", args[0])
	}
}

func tokenIssue(root string, args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	principal := fs.String("principal", "", "who the token acts as")
	role := fs.String("role", string(auth.RoleReader), "role the token carries")
	on := fs.String("on", "/", "resource path the token is scoped to")
	ttl := fs.Duration("ttl", 720*time.Hour, "how long it lasts")
	as := fs.String("as", string(auth.RoleAdmin), "role of whoever is issuing")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: scrivet token issue <name> --principal <who> --role <role>")
	}
	if strings.TrimSpace(*principal) == "" {
		return fmt.Errorf("--principal is required: a token acts as somebody")
	}

	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	secret, tok, err := ts.Issue(rest[0], *principal, auth.Role(*role), *on, *ttl,
		auth.Role(*as))
	if err != nil {
		return err
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		return err
	}

	fmt.Printf("%s%s%s\n", bold, secret, reset)
	fmt.Printf("\n  %sid %s · %s on %s · expires %s%s\n", dim, tok.ID, tok.Role,
		tok.Resource, time.Unix(tok.ExpiresAt, 0).UTC().Format("2006-01-02"), reset)
	fmt.Printf("  %sthis is the only time it is shown; only a hash is stored%s\n",
		yellow, reset)
	return nil
}

func tokenList(root string) error {
	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	if len(ts.Tokens) == 0 {
		fmt.Println("no tokens")
		return nil
	}
	now := time.Now()
	fmt.Printf("  %-14s %-16s %-10s %-12s %s\n", "id", "name", "role", "expires", "last used")
	for _, t := range ts.Tokens {
		state := ""
		switch {
		case t.Revoked:
			state = red + "revoked" + reset
		case t.Expired(now):
			state = dim + "expired" + reset
		}
		last := "never"
		if t.LastUsed > 0 {
			last = time.Unix(t.LastUsed, 0).UTC().Format("2006-01-02")
		}
		fmt.Printf("  %-14s %-16s %-10s %-12s %-10s %s\n", t.ID, t.Name, t.Role,
			time.Unix(t.ExpiresAt, 0).UTC().Format("2006-01-02"), last, state)
	}
	return nil
}

func tokenRevoke(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet token revoke <id>")
	}
	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	if err := ts.Revoke(args[0]); err != nil {
		return err
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		return err
	}
	fmt.Printf("revoked %s\n", args[0])
	fmt.Printf("  %sthe record is kept, so what it was and when it last worked "+
		"survives the revocation%s\n", dim, reset)
	return nil
}

func tokenStale(root string, args []string) error {
	fs := flag.NewFlagSet("stale", flag.ContinueOnError)
	idle := fs.Duration("idle", 720*time.Hour, "unused for at least this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	stale := ts.Stale(time.Now(), *idle)
	if len(stale) == 0 {
		fmt.Println("no stale tokens")
		return nil
	}
	fmt.Printf("%d token(s) unused for %s and still valid:\n", len(stale), *idle)
	for _, t := range stale {
		last := "never used"
		if t.LastUsed > 0 {
			last = "last used " + time.Unix(t.LastUsed, 0).UTC().Format("2006-01-02")
		}
		fmt.Printf("  %s  %-16s %s\n", t.ID, t.Name, last)
	}
	fmt.Printf("\n  %sa credential nobody uses is one nobody notices is still "+
		"valid%s\n", dim, reset)
	return nil
}
