package site

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/store"
)

// Environments: staging, production, and whatever else a customer needs
// between them.
//
// This is the gap most enterprise CMS evaluations fail a product on, and the
// usual implementation is the reason it is worth doing differently. Elsewhere,
// staging and production are separate databases with a copy job between them,
// and "it worked in staging" is a hope rather than a statement — the copy can
// reorder, re-serialise, drop a field the schema no longer has, or run against
// a staging row somebody edited after the test.
//
// Here an environment is a ref, and content is addressed by the hash of itself.
// So promotion is a pointer moving to an object that already exists, and
// production ends up byte-identical to what was tested. Not equivalent. Not
// "the same content". The same bytes, provably, because the name of the thing
// is a hash of the thing.
//
// That also makes rollback and promotion the same operation in opposite
// directions, and makes "what is the difference between staging and
// production" a diff of two commits rather than a comparison of two databases.
//
// The ordering is the other half. Environments are a sequence, and promotion
// goes forwards along it: draft → staging → live. Promoting straight to
// production is possible and has to be asked for, because the whole point of
// having a staging environment is that things pass through it, and a pipeline
// that can skip it silently is a pipeline that will.

// Env is one deployment target.
type Env struct {
	Name string `json:"name"`
	// Ref is the store ref holding this environment's commit.
	Ref string `json:"ref"`
	// Order places it in the promotion sequence. Lower is earlier.
	Order int `json:"order"`
	// Production marks the environment the public sees. Exactly one, and it
	// is what decides where the gates are strictest.
	Production bool `json:"production,omitempty"`
	// Description is shown in listings.
	Description string `json:"description,omitempty"`
}

// Envs is the configured set.
type Envs struct {
	Environments []Env `json:"environments"`
}

var reEnvName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// Default is the environment set a store has before anybody configures one:
// production alone, under the ref that has always been called live.
//
// A store that has never heard of environments must keep working exactly as it
// did, which means the default set has to name the existing ref rather than
// introduce a new one. Renaming `live` would break every deployment in place
// to make an internal model tidier.
func DefaultEnvs() *Envs {
	return &Envs{Environments: []Env{{
		Name: "production", Ref: RefLive, Order: 100, Production: true,
		Description: "what the public sees",
	}}}
}

// Validate refuses a set that cannot work.
func (e *Envs) Validate() error {
	if len(e.Environments) == 0 {
		return fmt.Errorf("there must be at least one environment")
	}
	seen := map[string]bool{}
	refs := map[string]string{}
	prod := 0
	for _, env := range e.Environments {
		if !reEnvName.MatchString(env.Name) {
			return fmt.Errorf(
				"%q is not a usable environment name: lowercase letters, "+
					"digits and hyphens", env.Name)
		}
		if seen[env.Name] {
			return fmt.Errorf("%q is declared twice", env.Name)
		}
		seen[env.Name] = true

		if env.Ref == RefDraft {
			// The draft is where work happens and is not a deployment target.
			// An environment pointing at it would make every unsaved edit
			// live the moment it was typed.
			return fmt.Errorf(
				"%q cannot use the draft ref: the draft is where work in "+
					"progress lives, and an environment pointing at it would "+
					"publish every edit as it is typed", env.Name)
		}
		if other, clash := refs[env.Ref]; clash {
			// Two environments sharing a ref are one environment with two
			// names, and promoting to either moves both.
			return fmt.Errorf(
				"%q and %q both use the ref %q, so promoting to one would "+
					"move the other", env.Name, other, env.Ref)
		}
		refs[env.Ref] = env.Name

		if env.Production {
			prod++
		}
	}
	if prod != 1 {
		return fmt.Errorf(
			"%d environments are marked production; there must be exactly "+
				"one, because it is what decides where the gates are "+
				"strictest and what the public site serves", prod)
	}
	return nil
}

// Sorted returns the environments in promotion order.
func (e *Envs) Sorted() []Env {
	out := append([]Env(nil), e.Environments...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Lookup finds an environment by name.
func (e *Envs) Lookup(name string) (Env, bool) {
	for _, env := range e.Environments {
		if env.Name == name {
			return env, true
		}
	}
	return Env{}, false
}

// Production returns the environment the public sees.
func (e *Envs) Production() Env {
	for _, env := range e.Environments {
		if env.Production {
			return env
		}
	}
	// Validate refuses a set without one, so this is only reachable on a
	// hand-built value. The last in order is the least surprising guess.
	s := e.Sorted()
	return s[len(s)-1]
}

// Previous returns the environment immediately before this one, and whether
// there is one.
func (e *Envs) Previous(name string) (Env, bool) {
	sorted := e.Sorted()
	for i, env := range sorted {
		if env.Name == name {
			if i == 0 {
				return Env{}, false
			}
			return sorted[i-1], true
		}
	}
	return Env{}, false
}

// Promotion is what a promotion did.
type Promotion struct {
	From     string    `json:"from"`
	To       string    `json:"to"`
	Commit   string    `json:"commit"`
	Previous string    `json:"previous,omitempty"`
	Changes  []Change  `json:"changes,omitempty"`
	At       time.Time `json:"at"`
	// Identical is true when the target already held this commit, so nothing
	// moved. Reported rather than treated as an error: promoting twice is a
	// normal thing for a pipeline to do and should be idempotent.
	Identical bool `json:"identical,omitempty"`
}

// Promote moves one environment's ref to whatever another one holds.
//
// The whole operation is a ref pointing somewhere else. Nothing is copied,
// re-serialised or rebuilt, which is what makes the guarantee exact: the bytes
// production serves are the bytes staging served, because they are the same
// objects.
//
// Skipping ahead is possible and must be asked for. An environment sequence
// exists so that things pass through it, and a pipeline that can silently skip
// staging is one that eventually does — usually at the worst moment, by
// somebody in a hurry.
func Promote(s *store.Store, envs *Envs, from, to string, allowSkip bool) (
	Promotion, error) {

	src, ok := envs.Lookup(from)
	if !ok && from != RefDraft && from != "draft" {
		return Promotion{}, fmt.Errorf("there is no environment called %q", from)
	}
	dst, ok := envs.Lookup(to)
	if !ok {
		return Promotion{}, fmt.Errorf("there is no environment called %q", to)
	}

	srcRef := RefDraft
	srcName := "draft"
	if src.Name != "" {
		srcRef, srcName = src.Ref, src.Name
	}

	// Order is checked before anything moves. Promoting backwards is how a
	// production commit ends up in staging and everybody's mental model of
	// which is ahead stops being true.
	if src.Name != "" && src.Order >= dst.Order {
		return Promotion{}, fmt.Errorf(
			"%s is not before %s in the promotion order, so this would move "+
				"content backwards", srcName, dst.Name)
	}
	if !allowSkip {
		if prev, has := envs.Previous(dst.Name); has && prev.Name != srcName {
			return Promotion{}, fmt.Errorf(
				"%s comes after %s, not after %s.\n"+
					"  Promoting straight to %s skips the environment that "+
					"exists to catch this.\n"+
					"  If that is genuinely right: --skip",
				dst.Name, prev.Name, srcName, dst.Name)
		}
	}

	commit := s.GetRef(srcRef)
	if commit == "" {
		return Promotion{}, fmt.Errorf("%s holds nothing to promote", srcName)
	}

	var out Promotion
	err := s.WithRefLock(func() error {
		previous := s.GetRef(dst.Ref)
		if previous == commit {
			out = Promotion{From: srcName, To: dst.Name, Commit: commit,
				Previous: previous, Identical: true, At: time.Now()}
			return nil
		}
		changes, err := Diff(s, previous, commit)
		if err != nil {
			return err
		}
		if err := s.SetRef(dst.Ref, commit); err != nil {
			return err
		}
		out = Promotion{From: srcName, To: dst.Name, Commit: commit,
			Previous: previous, Changes: changes, At: time.Now()}
		return nil
	})
	return out, err
}

// Behind reports how each environment compares to the one before it, which is
// the question somebody actually asks: what is waiting to go out, and where.
type Behind struct {
	Env    Env    `json:"env"`
	Commit string `json:"commit"`
	// Pending counts the changes sitting in the previous environment that this
	// one does not have yet.
	Pending int `json:"pending"`
	// Same is true when this environment matches the previous one exactly.
	Same bool `json:"same"`
	// Empty is true when nothing has ever been promoted here.
	Empty bool `json:"empty"`
	// Ahead is true when the environment before this one holds nothing, so
	// there is nothing for this one to be waiting on.
	//
	// Separate from Pending being zero, because those are different
	// situations and the first version of this conflated them: an environment
	// inserted before one that is already live reported "0 change(s) waiting",
	// which reads as a state somebody should act on and is the opposite of
	// what is true.
	Ahead bool `json:"ahead,omitempty"`
}

// Status describes every environment.
func Status(s *store.Store, envs *Envs) ([]Behind, error) {
	sorted := envs.Sorted()
	out := make([]Behind, 0, len(sorted))

	// The draft is the source for the first environment, so the comparison
	// starts there rather than at nothing.
	prevCommit := s.GetRef(RefDraft)
	for _, env := range sorted {
		commit := s.GetRef(env.Ref)
		b := Behind{Env: env, Commit: commit, Empty: commit == ""}
		switch {
		case commit == "":
			if prevCommit != "" {
				changes, err := Diff(s, "", prevCommit)
				if err != nil {
					return nil, err
				}
				b.Pending = len(changes)
			}
		case commit == prevCommit:
			b.Same = true
		case prevCommit == "":
			// Nothing behind this one to be behind. An environment inserted
			// before another that is already live is in exactly this state:
			// staging holds nothing, production holds what was published
			// before staging existed, and production is not waiting on
			// anything.
			//
			// This branch was missing, and Diff was called with an empty
			// commit — which failed with "not an object id: \"\"" and took the
			// whole listing with it. `scrivet env list` and the publishing
			// screen both stopped working the moment somebody added a staging
			// environment to a site that was already published, which is the
			// first thing anybody does with this feature.
			b.Pending, b.Ahead = 0, true
		default:
			changes, err := Diff(s, commit, prevCommit)
			if err != nil {
				return nil, err
			}
			b.Pending = len(changes)
		}
		out = append(out, b)
		prevCommit = commit
	}
	return out, nil
}

// RefFor resolves an environment name to a ref, accepting "draft" as well so
// that every command taking an environment can also take the draft without
// each one special-casing it.
func (e *Envs) RefFor(name string) (string, error) {
	if name == "" || name == RefDraft {
		return RefDraft, nil
	}
	if env, ok := e.Lookup(name); ok {
		return env.Ref, nil
	}
	// A ref name that is not an environment is refused rather than passed
	// through. Accepting arbitrary refs would let a typo resolve to an empty
	// ref and serve an empty site, which looks like content loss.
	var names []string
	for _, env := range e.Sorted() {
		names = append(names, env.Name)
	}
	return "", fmt.Errorf("there is no environment called %q; there is %s and "+
		"draft", name, strings.Join(names, ", "))
}
