// Package config is every knob this program has, with defaults that are safe
// and an explicit, recorded way to move any of them.
//
// The requirement was "highly customizable, but do not undermine security",
// and those pull against each other in exactly one place: the settings where a
// customer's legitimate operational need — a longer token life, a higher rate
// limit, a disabled gate — is also what an attacker would ask for. Everything
// else is preference and should simply be settable.
//
// Three ways to resolve that, two of them bad:
//
//   - Refuse to allow the weak value. Customers who need it patch the binary,
//     fork, or run the gate elsewhere with no record at all. The setting has
//     not been prevented, only hidden.
//   - Allow it silently. Then the difference between a considered decision and
//     an accident is invisible, including to the person who has to answer for
//     it later.
//   - Allow it, require a reason, record it, expire it, and report it until it
//     is fixed or renewed.
//
// The third is what this does, and it is the same shape as `posture suppress`,
// which accepts a risk for at most ninety days with a name attached. A setting
// weaker than its floor is not blocked; it needs --accept-risk with a reason,
// the acceptance goes in the audit log, and the posture scan reports it as a
// finding for as long as it stands. Nothing is forbidden. Nothing is quiet.
package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is a setting's type, which decides how a value is parsed and validated.
type Kind string

const (
	Int      Kind = "int"
	Duration Kind = "duration"
	Bool     Kind = "bool"
	Text     Kind = "text"
	List     Kind = "list" // comma-separated
)

// Setting describes one knob: what it is, what it defaults to, and — when it
// has a security dimension — what makes a value weaker than the default.
type Setting struct {
	Key     string
	Kind    Kind
	Default string
	Summary string
	// Why explains what the setting is for, shown by `config explain`. Written
	// for somebody deciding whether to change it, not for somebody who already
	// knows what it does.
	Why string
	// Weaker reports whether a value gives up security relative to the
	// default, and says what is given up. Nil means the setting has no
	// security dimension and can be set freely — most of them.
	//
	// A function rather than a numeric floor because "weaker" is not always a
	// direction on a number: a longer token life is weaker, a longer lockout
	// is weaker in a different way (denial of service against real users), and
	// turning a gate off is weaker regardless of type.
	Weaker func(value string) (bool, string)
	// Controls and OWASP tie the setting to the frameworks an enterprise is
	// audited against, so a reviewer can find it from their side.
	Controls []string
	OWASP    string
}

// AcceptedRisk records a deliberate decision to run weaker than the default.
type AcceptedRisk struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
	By     string `json:"by"`
	At     string `json:"at"`
	// Until is when the acceptance lapses. An acceptance that never expires is
	// a decision nobody revisits, and the reason it was made stops being true
	// long before anybody notices.
	Until string `json:"until"`
}

// MaxAcceptance is how long a risk may be accepted for.
//
// Ninety days matches the posture suppressions, and the number matters less
// than the fact that there is one: it forces the question to be asked again by
// somebody who can see whether the reason still holds.
const MaxAcceptance = 90 * 24 * time.Hour

// File is what is stored.
type File struct {
	Values   map[string]string `json:"values,omitempty"`
	Accepted []AcceptedRisk    `json:"accepted,omitempty"`
}

// Config is the effective configuration.
type Config struct {
	file File
	now  func() time.Time
}

// New returns a configuration with nothing overridden.
func New() *Config {
	return &Config{
		file: File{Values: map[string]string{}},
		now:  time.Now,
	}
}

// Parse reads a stored configuration.
func Parse(body []byte) (*Config, error) {
	c := New()
	if len(strings.TrimSpace(string(body))) == 0 {
		return c, nil
	}
	if err := json.Unmarshal(body, &c.file); err != nil {
		return nil, fmt.Errorf("the configuration is not readable: %w", err)
	}
	if c.file.Values == nil {
		c.file.Values = map[string]string{}
	}
	// Refused at load rather than at use. A configuration holding a value that
	// cannot be parsed is a configuration whose effective behaviour nobody can
	// predict, and finding that out when the setting is first read means
	// finding out in the middle of serving a request.
	for key, v := range c.file.Values {
		s, ok := Lookup(key)
		if !ok {
			return nil, fmt.Errorf(
				"%q is not a setting this version knows about. Remove it, or "+
					"check `quilzo config list` for the current name", key)
		}
		if err := s.Validate(v); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
	}
	return c, nil
}

// WithClock is for tests, which cannot wait ninety days.
func (c *Config) WithClock(now func() time.Time) *Config { c.now = now; return c }

// Bytes serialises the configuration.
func (c *Config) Bytes() ([]byte, error) {
	// Sorted so a configuration under version control produces a readable
	// diff rather than a reordering of the whole file.
	sort.Slice(c.file.Accepted, func(i, j int) bool {
		return c.file.Accepted[i].Key < c.file.Accepted[j].Key
	})
	return json.MarshalIndent(c.file, "", "  ")
}

// -- reading -----------------------------------------------------------------

// Raw returns the effective string value of a setting.
func (c *Config) Raw(key string) string {
	s, ok := Lookup(key)
	if !ok {
		return ""
	}
	if v, set := c.file.Values[key]; set {
		return v
	}
	return s.Default
}

// Int returns a setting as a number. A setting that does not parse returns its
// default, because Parse already refused anything that does not — reaching
// here with a bad value means the caller built a Config by hand.
func (c *Config) Int(key string) int {
	n, err := strconv.Atoi(c.Raw(key))
	if err != nil {
		s, _ := Lookup(key)
		n, _ = strconv.Atoi(s.Default)
	}
	return n
}

// Dur returns a setting as a duration.
func (c *Config) Dur(key string) time.Duration {
	d, err := time.ParseDuration(c.Raw(key))
	if err != nil {
		s, _ := Lookup(key)
		d, _ = time.ParseDuration(s.Default)
	}
	return d
}

// Bool returns a setting as a boolean.
func (c *Config) Bool(key string) bool {
	b, err := strconv.ParseBool(c.Raw(key))
	if err != nil {
		s, _ := Lookup(key)
		b, _ = strconv.ParseBool(s.Default)
	}
	return b
}

// Strings returns a list setting, empty entries dropped.
func (c *Config) Strings(key string) []string {
	var out []string
	for _, p := range strings.Split(c.Raw(key), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// IsDefault reports whether a setting has not been overridden.
func (c *Config) IsDefault(key string) bool {
	_, set := c.file.Values[key]
	return !set
}

// -- writing -----------------------------------------------------------------

// ErrNeedsAcceptance is returned when a value is weaker than the default and
// no reason was given. It carries what is given up, so the caller can print it
// rather than inventing its own wording.
type ErrNeedsAcceptance struct {
	Key   string
	Value string
	Why   string
}

func (e *ErrNeedsAcceptance) Error() string {
	return fmt.Sprintf(
		"%s = %s gives up security: %s\n"+
			"  This is allowed. It needs a reason, which is recorded in the "+
			"audit log and reported by `quilzo posture scan` until it is "+
			"changed back or renewed:\n"+
			"    quilzo config set %s %s --accept-risk \"why this is right here\"",
		e.Key, e.Value, e.Why, e.Key, e.Value)
}

// Set changes a setting.
//
// A value weaker than the default needs a reason. Everything else is simply
// set, because most settings have no security dimension and asking for a
// justification to change a page size trains people to type anything into the
// box that also guards the settings that matter.
func (c *Config) Set(key, value, reason, by string) error {
	s, ok := Lookup(key)
	if !ok {
		return fmt.Errorf("%q is not a setting; `quilzo config list` shows "+
			"every one", key)
	}
	if err := s.Validate(value); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}

	if weaker, why := s.IsWeaker(value); weaker {
		if strings.TrimSpace(reason) == "" {
			return &ErrNeedsAcceptance{Key: key, Value: value, Why: why}
		}
		now := c.now()
		c.dropAcceptance(key)
		c.file.Accepted = append(c.file.Accepted, AcceptedRisk{
			Key: key, Value: value, Reason: strings.TrimSpace(reason),
			By: by, At: now.UTC().Format(time.RFC3339),
			Until: now.Add(MaxAcceptance).UTC().Format(time.RFC3339),
		})
	} else {
		// Back to a safe value, so the acceptance goes with it rather than
		// lingering to be reported about a setting that is now fine.
		c.dropAcceptance(key)
	}

	if value == s.Default {
		delete(c.file.Values, key)
		return nil
	}
	c.file.Values[key] = value
	return nil
}

// Unset returns a setting to its default.
func (c *Config) Unset(key string) error {
	if _, ok := Lookup(key); !ok {
		return fmt.Errorf("%q is not a setting", key)
	}
	delete(c.file.Values, key)
	c.dropAcceptance(key)
	return nil
}

func (c *Config) dropAcceptance(key string) {
	kept := c.file.Accepted[:0]
	for _, a := range c.file.Accepted {
		if a.Key != key {
			kept = append(kept, a)
		}
	}
	c.file.Accepted = kept
}

// -- reporting ---------------------------------------------------------------

// Effective is one setting as it currently stands.
type Effective struct {
	Setting   Setting
	Value     string
	Overriden bool
	// Weaker and Why describe the security cost, if any.
	Weaker bool
	Why    string
	// Accepted is the recorded decision, when there is one. A weaker value
	// with no acceptance is the state that should not be reachable through
	// Set — it means the file was edited by hand.
	Accepted *AcceptedRisk
	Expired  bool
}

// Effectives returns every setting, in declaration order.
func (c *Config) Effectives() []Effective {
	out := make([]Effective, 0, len(settings))
	for _, s := range settings {
		v := c.Raw(s.Key)
		e := Effective{Setting: s, Value: v, Overriden: !c.IsDefault(s.Key)}
		e.Weaker, e.Why = s.IsWeaker(v)
		if a := c.acceptance(s.Key); a != nil {
			e.Accepted = a
			if until, err := time.Parse(time.RFC3339, a.Until); err == nil {
				e.Expired = c.now().After(until)
			}
		}
		out = append(out, e)
	}
	return out
}

func (c *Config) acceptance(key string) *AcceptedRisk {
	for i := range c.file.Accepted {
		if c.file.Accepted[i].Key == key {
			return &c.file.Accepted[i]
		}
	}
	return nil
}

// Weakened returns the settings currently running weaker than their default.
//
// This is what the posture scan reports on. A value that was weakened by
// editing the file directly appears here with no acceptance, which is the
// case worth showing loudest: the difference between a decision and an
// accident is exactly whether somebody wrote down why.
func (c *Config) Weakened() []Effective {
	var out []Effective
	for _, e := range c.Effectives() {
		if e.Weaker {
			out = append(out, e)
		}
	}
	return out
}
