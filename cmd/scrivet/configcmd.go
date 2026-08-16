package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/atomicfile"
	"github.com/lithoform/lithoform/internal/audit"
	"github.com/lithoform/lithoform/internal/config"
	"github.com/lithoform/lithoform/internal/throttle"
)

func configPath(root string) string { return filepath.Join(root, "config.json") }

// loadConfig reads the store's configuration.
//
// A broken configuration is fatal rather than ignored. The alternative — fall
// back to defaults and carry on — means a typo silently returns the store to
// stock settings, and the operator's whole configuration stops applying at the
// moment they are least likely to check.
func loadConfig(root string) (*config.Config, error) {
	body, err := os.ReadFile(configPath(root))
	if os.IsNotExist(err) {
		return config.New(), nil
	}
	if err != nil {
		return nil, err
	}
	c, err := config.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", configPath(root), err)
	}
	return c, nil
}

func saveConfig(root string, c *config.Config) error {
	body, err := c.Bytes()
	if err != nil {
		return err
	}
	return atomicfile.Write(configPath(root), append(body, '\n'), 0o600)
}

// throttlePolicy turns the configuration into a throttle policy.
//
// One place, so the CLI, the admin interface and the API cannot end up with
// three different ideas of how many attempts are free.
func throttlePolicy(c *config.Config) throttle.Policy {
	return throttle.Policy{
		On:      c.Bool("auth.throttle"),
		After:   c.Int("auth.throttle.after"),
		Ceiling: c.Int("auth.throttle.ceiling"),
		Base:    c.Dur("auth.throttle.base"),
		Max:     c.Dur("auth.throttle.max"),
		Window:  time.Hour,
		Hard:    c.Bool("auth.lockout.hard"),
		Alert:   c.Int("auth.lockout.alert"),
	}
}

func cmdConfig(root string, args []string) error {
	if len(args) == 0 {
		return configShow(root)
	}
	switch args[0] {
	case "show":
		return configShow(root)
	case "list":
		return configList()
	case "explain":
		return configExplain(args[1:])
	case "set":
		return configSet(root, args[1:])
	case "unset":
		return configUnset(root, args[1:])
	default:
		return fmt.Errorf("unknown config command %q; try show, list, "+
			"explain, set or unset", args[0])
	}
}

func configShow(root string) error {
	c, err := loadConfig(root)
	if err != nil {
		return err
	}
	effs := c.Effectives()

	if w.JSON(effs) {
		return nil
	}
	changed, weak := 0, 0
	for _, e := range effs {
		if e.Overriden {
			changed++
		}
		if e.Weaker {
			weak++
		}
	}
	w.Human("%d setting(s), %d changed from the default\n", len(effs), changed)
	if changed == 0 {
		w.Human("  %severything is at its default, which is the intended "+
			"posture%s\n", dim, reset)
	}
	for _, e := range effs {
		if !e.Overriden && !e.Weaker {
			continue
		}
		mark, colour := " ", ""
		if e.Weaker {
			mark, colour = "!", yellow
		}
		w.Human("\n  %s%s %-26s %s%s\n", colour, mark, e.Setting.Key, e.Value, reset)
		w.Human("      %sdefault %s · %s%s\n", dim, e.Setting.Default,
			e.Setting.Summary, reset)
		if e.Weaker {
			w.Human("      %s%s%s\n", yellow, e.Why, reset)
			switch {
			case e.Accepted == nil:
				w.Human("      %sno reason was recorded, so this reads as an "+
					"accident rather than a decision%s\n", red, reset)
			case e.Expired:
				w.Human("      %saccepted by %s (%q) — that acceptance has "+
					"lapsed%s\n", red, e.Accepted.By, e.Accepted.Reason, reset)
			default:
				w.Human("      %saccepted by %s until %s: %q%s\n", dim,
					e.Accepted.By, shortDate(e.Accepted.Until),
					e.Accepted.Reason, reset)
			}
		}
	}
	if weak > 0 {
		w.Human("\n  %s%d setting(s) are weaker than the default and are "+
			"reported by `scrivet posture scan`%s\n", dim, weak, reset)
	}
	return nil
}

func configList() error {
	all := config.All()
	if w.JSON(all) {
		return nil
	}
	group := ""
	for _, s := range all {
		if g, _, _ := strings.Cut(s.Key, "."); g != group {
			group = g
			w.Human("\n%s%s%s\n", bold, group, reset)
		}
		guarded := ""
		if s.Weaker != nil {
			guarded = yellow + " ·" + reset
		}
		w.Human("  %-28s %-10s %s%s\n", s.Key, s.Default, s.Summary, guarded)
	}
	w.Human("\n  %s· marked settings give up security if changed; they are "+
		"still changeable,%s\n", dim, reset)
	w.Human("  %s  with --accept-risk and a reason that is recorded%s\n", dim, reset)
	w.Human("  %sscrivet config explain KEY%s\n", dim, reset)
	return nil
}

func configExplain(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet config explain <key>")
	}
	s, ok := config.Lookup(args[0])
	if !ok {
		return fmt.Errorf("%q is not a setting; `scrivet config list` shows "+
			"every one", args[0])
	}
	if w.JSON(s) {
		return nil
	}
	w.Human("%s%s%s  %s\n", bold, s.Key, reset, s.Summary)
	w.Human("  %sdefault %s · %s%s\n\n", dim, s.Default, s.Kind, reset)
	w.Human("%s\n", wrapText(s.Why, 74, "  "))
	if s.Weaker != nil {
		w.Human("\n  %sthis setting has a security dimension: some values "+
			"need a recorded reason%s\n", yellow, reset)
	}
	if len(s.Controls) > 0 {
		w.Human("\n  %s%s", dim, strings.Join(s.Controls, " "))
		if s.OWASP != "" {
			w.Human("  %s", s.OWASP)
		}
		w.Human("%s\n", reset)
	}
	return nil
}

func configSet(root string, args []string) error {
	var key, value, reason string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--accept-risk" && i+1 < len(args):
			reason = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--accept-risk="):
			reason = strings.TrimPrefix(args[i], "--accept-risk=")
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) != 2 {
		return fmt.Errorf("usage: scrivet config set <key> <value> " +
			"[--accept-risk \"reason\"]")
	}
	key, value = rest[0], rest[1]

	c, err := loadConfig(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	before := c.Raw(key)

	if err := c.Set(key, value, reason, caller.Name); err != nil {
		var need *config.ErrNeedsAcceptance
		if errorsAs(err, &need) {
			// A gate refusing, not the command breaking. The caller is being
			// asked for a reason, not told they cannot do this.
			return errBlocked{err}
		}
		return err
	}
	if err := saveConfig(root, c); err != nil {
		return err
	}

	detail := map[string]string{"setting": key, "from": before, "to": value}
	outcome := audit.Success
	if reason != "" {
		detail["accepted_risk"] = reason
	}
	// The audit key must not be a forbidden substring — "key" is one, which is
	// why the field is called "setting".
	record(root, caller.auditRecord("config.set", "/", outcome, detail))

	w.Human("%s = %s\n", key, value)
	if reason != "" {
		w.Human("  %srisk accepted for %d days: %q%s\n", yellow,
			int(config.MaxAcceptance.Hours()/24), reason, reset)
		w.Human("  %s`scrivet posture scan` reports this until it is changed "+
			"back or renewed%s\n", dim, reset)
	}
	return nil
}

func configUnset(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet config unset <key>")
	}
	c, err := loadConfig(root)
	if err != nil {
		return err
	}
	before := c.Raw(args[0])
	if err := c.Unset(args[0]); err != nil {
		return err
	}
	if err := saveConfig(root, c); err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	record(root, caller.auditRecord("config.unset", "/", audit.Success,
		map[string]string{"setting": args[0], "from": before,
			"to": c.Raw(args[0])}))
	w.Human("%s is back to its default, %s\n", args[0], c.Raw(args[0]))
	return nil
}

func shortDate(rfc string) string {
	t, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		return rfc
	}
	return t.Format("2 Jan 2006")
}

// wrapText is a small paragraph wrapper, because `config explain` prints prose
// and prose that runs off the edge of a terminal does not get read.
func wrapText(s string, width int, indent string) string {
	var out strings.Builder
	line := indent
	for _, word := range strings.Fields(s) {
		if len(line)+len(word)+1 > width && len(line) > len(indent) {
			out.WriteString(line + "\n")
			line = indent
		}
		if len(line) > len(indent) {
			line += " "
		}
		line += word
	}
	out.WriteString(line)
	return out.String()
}

var _ = json.Marshal

// errorsAs is errors.As, wrapped so this file does not import errors purely
// for one call in a branch.
func errorsAs(err error, target **config.ErrNeedsAcceptance) bool {
	return errors.As(err, target)
}
