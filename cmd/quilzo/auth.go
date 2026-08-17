package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
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
	// Atomic, because the site process reads this file while the admin
	// process writes it. A truncated token store is not stale data, it is a
	// parse error, and a store whose tokens cannot be read is correctly
	// treated as one nobody may write to — so the site refuses to start.
	return atomicfile.Write(path, append(b, '\n'), 0o600)
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
	case "recover":
		return cmdRecover(root, args[1:])
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
	fmt.Print(`quilzo auth — who can do what

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
	ownOnly := fs.Bool("own-only", false,
		"restrict to content this principal created — the contributor shape")
	rest, flags := leadingArgs(args, 2)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 2 {
		return fmt.Errorf("usage: quilzo auth grant <principal> <role> [--on /path] [--deny]")
	}

	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	b := auth.Binding{
		Principal: rest[0], Role: auth.Role(rest[1]), Resource: *on,
		Deny: *deny, GrantedBy: *by, Note: *note, OwnOnly: *ownOnly,
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

	// AU-2 names privileged actions as the ones that must be logged, and a
	// change to who holds a role is the most privileged action this program
	// performs: it decides who may perform every other one. This was missing
	// until a demo showed an empty log after granting somebody admin.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action:    "auth." + verb,
		Resource:  *on,
		Outcome:   audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"subject": rest[0], "role": rest[1], "deny": fmt.Sprintf("%t", *deny),
		},
	})

	fmt.Printf("%s %s to %s on %s\n", verb, rest[1], rest[0], *on)
	if *ownOnly {
		fmt.Printf("  %sonly on content %s created — reads are unrestricted, "+
			"because a team\n  where people cannot see each other's drafts "+
			"is not a team%s\n", dim, rest[0], reset)
	}
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
		return fmt.Errorf("usage: quilzo auth revoke <principal> <role> [--on /path]")
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
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "auth.revoke", Resource: *on, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"subject": rest[0], "bindings_removed": fmt.Sprintf("%d", n),
		},
	})

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
		return fmt.Errorf("usage: quilzo auth explain <principal> [action] [--on /path]")
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
		fmt.Print(`quilzo token — credentials for API access

  issue <name> --principal <who> --role <role> [--on /path] [--ttl 720h]
  exchange [--role R] [--on /path] [--ttl 15m]   short-lived session from a token
  list
  revoke <id>                                    cascades to its sessions
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
	case "exchange":
		return tokenExchange(root, args[1:])
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
	ttl := fs.Duration("ttl", 0, "how long it lasts (default from config)")
	as := fs.String("as", string(auth.RoleAdmin), "role of whoever is issuing")
	types := fs.String("types", "",
		"comma-separated content types this token may touch; all if unset")
	locales := fs.String("locales", "",
		"comma-separated locales this token may touch; all if unset")
	readOnly := fs.Bool("read-only", false,
		"refuse every write regardless of role")
	forAPI := fs.Bool("api", false,
		"short-lived and read-only: the shape an integration should hold")
	rest, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: quilzo token issue <name> --principal <who> --role <role>")
	}
	if strings.TrimSpace(*principal) == "" {
		return fmt.Errorf("--principal is required: a token acts as somebody")
	}

	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}

	scope := auth.Scope{
		Types:    splitList(*types),
		Locales:  splitList(*locales),
		ReadOnly: *readOnly,
	}
	// --api is a shorthand for the shape an integration should hold, because
	// the right answer is several flags and nobody types several flags. A
	// program that reads content needs to read content; anything else it needs
	// is a decision somebody should make explicitly.
	if *forAPI {
		scope.ReadOnly = true
	}

	life := *ttl
	if life == 0 {
		life = cfg.Dur("token.ttl.default")
		if *forAPI {
			life = cfg.Dur("token.api.ttl.default")
		}
	}
	// The ceiling is checked here rather than inside Issue, because it is a
	// deployment policy rather than a property of tokens, and the message has
	// to name the setting that produced it or nobody can find what to change.
	if max := cfg.Dur("token.ttl.max"); life > max {
		return fmt.Errorf(
			"a %s token is longer than token.ttl.max (%s).\n"+
				"  Raise the ceiling deliberately if that is right:\n"+
				"    quilzo config set token.ttl.max %s --accept-risk \"why\"",
			life, max, life)
	}

	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	secret, tok, err := ts.IssueScoped(rest[0], *principal, auth.Role(*role),
		*on, life, auth.Role(*as), scope)
	if err != nil {
		return err
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "token.issue", Resource: tok.Resource, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			// The id, never the secret. The audit package refuses Detail keys
			// containing "token" or "secret" for exactly this reason, and the
			// keys here are named so that check keeps working.
			"issued_id": tok.ID, "for": tok.Principal, "role": string(tok.Role),
			"expires": time.Unix(tok.ExpiresAt, 0).UTC().Format(time.RFC3339),
		},
	})

	fmt.Printf("%s%s%s\n", bold, secret, reset)
	fmt.Printf("\n  %sid %s · %s on %s · expires %s%s\n", dim, tok.ID, tok.Role,
		tok.Resource, time.Unix(tok.ExpiresAt, 0).UTC().Format("2006-01-02"), reset)
	if !tok.Scope.Empty() {
		// Shown at issue time because this is the only moment anybody looks.
		// A scope nobody can see is a scope nobody trusts, and an operator who
		// cannot confirm the token is narrow will issue a wide one.
		fmt.Printf("  %sscope: %s%s\n", dim, tok.Scope, reset)
	}
	fmt.Printf("  %sthis is the only time it is shown; only a hash is stored%s\n",
		yellow, reset)
	return nil
}

// tokenExchange mints a session from a long-lived token.
//
// Store the durable credential; use one of these. What is stored and what is
// used stop being the same object, so an exposed session is bounded by a clock
// rather than by whoever notices.
func tokenExchange(root string, args []string) error {
	fs := flag.NewFlagSet("exchange", flag.ContinueOnError)
	role := fs.String("role", "", "narrow to this role (default: the parent's)")
	on := fs.String("on", "", "narrow to this path (default: the parent's)")
	ttl := fs.Duration("ttl", auth.DefaultSessionTTL, "how long the session lasts")
	tok := fs.String("token", "", "the long-lived token (default: the usual sources)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	parent, from := findToken(*tok)
	if parent == "" {
		return fmt.Errorf(
			"no token to exchange; pass --token, or put one in %s", tokenFile())
	}

	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	secret, t, err := ts.Exchange(parent, auth.Role(*role), *on, *ttl, time.Now())
	if err != nil {
		return err
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		return err
	}

	if w.JSON(map[string]any{
		"token": secret, "id": t.ID, "role": string(t.Role),
		"resource": t.Resource, "expires_at": t.ExpiresAt,
		"expires_in_seconds": t.ExpiresAt - time.Now().Unix(),
		"parent":             t.Parent,
	}) {
		return nil
	}

	// An exchange is a privileged action too: it mints a live credential. The
	// parent is recorded, so a compromised long-lived token can be traced to
	// every session it produced rather than only to itself.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "token.exchange", Resource: t.Resource, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"session_id": t.ID, "parent_id": t.Parent, "role": string(t.Role),
			"expires": time.Unix(t.ExpiresAt, 0).UTC().Format(time.RFC3339),
		},
	})

	fmt.Printf("%s%s%s\n", bold, secret, reset)
	fmt.Printf("\n  %s%s on %s · expires in %s · from %s (%s)%s\n", dim,
		t.Role, t.Resource, time.Until(time.Unix(t.ExpiresAt, 0)).Round(time.Second),
		t.Parent, from, reset)
	fmt.Printf("  %srevoking the parent revokes this too%s\n", dim, reset)
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
		return fmt.Errorf("usage: quilzo token revoke <id>")
	}
	ts, err := loadTokens(root)
	if err != nil {
		return err
	}
	sessions, err := ts.Revoke(args[0])
	if err != nil {
		return err
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "token.revoke", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"revoked_id":        args[0],
			"sessions_cascaded": fmt.Sprintf("%d", sessions),
		},
	})

	fmt.Printf("revoked %s\n", args[0])
	if sessions > 0 {
		// Said out loud, because a cascade that happens quietly is one nobody
		// relies on.
		fmt.Printf("  %sand %d live session(s) minted from it%s\n", yellow, sessions, reset)
	}
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

// splitList turns a comma-separated flag into a list, dropping blanks so that
// `--types article,` does not produce a scope containing an empty name — which
// would fail validation and read as though the flag itself were rejected.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
