package a2a

import (
	"fmt"
	"net/url"
	"strings"
)

// Validate refuses a card that would not be read as A2A.
//
// # Why this exists rather than trusting the generator
//
// An API Evangelist survey in July 2026 found most published agent cards are
// not actually valid A2A. That is not carelessness — it is what happens when a
// card is written beside the thing it describes and nothing checks the two
// agree. A generator can be wrong in exactly the same way; the difference is
// whether anything says so.
//
// So the card is validated before it is served, and the validator is what the
// test asserts against. A deployment that would publish an invalid card serves
// nothing instead: a 404 is a site that has no card, which is true and
// harmless, and an invalid one is a site that looks discoverable and breaks
// whatever tried.
func (c Card) Validate() error {
	if c.ProtocolVersion == "" {
		return fmt.Errorf(
			"no protocolVersion, so a consumer has to guess which revision " +
				"this is — which is how most published cards end up invalid")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("a card with no name identifies nothing")
	}
	if err := absoluteHTTPS(c.URL, "url"); err != nil {
		return err
	}
	if c.PreferredTransport == "" {
		return fmt.Errorf(
			"no preferredTransport, so a caller does not know how to reach it")
	}
	if c.Version == "" {
		return fmt.Errorf("no version, so nothing can tell one card from the next")
	}
	if len(c.DefaultInputModes) == 0 || len(c.DefaultOutputModes) == 0 {
		return fmt.Errorf(
			"defaultInputModes and defaultOutputModes are both required; a " +
				"caller cannot tell what this accepts without them")
	}
	if c.Skills == nil {
		return fmt.Errorf(
			"skills is absent rather than empty. No agents is an answer; a " +
				"missing field looks like a card that failed to render one")
	}

	seen := map[string]bool{}
	for i, s := range c.Skills {
		if strings.TrimSpace(s.ID) == "" {
			return fmt.Errorf("skill %d has no id", i)
		}
		if seen[s.ID] {
			return fmt.Errorf(
				"two skills share the id %q, so which one a caller delegates "+
					"to would be decided by list order", s.ID)
		}
		seen[s.ID] = true
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("skill %q has no name", s.ID)
		}
		if strings.TrimSpace(s.Description) == "" {
			return fmt.Errorf(
				"skill %q has no description. A capability list nobody can "+
					"review against an intention is one nobody reviews", s.ID)
		}
	}

	// The half that is this project's own, and the half most worth checking:
	// a skill with no governance entry is a skill published without the thing
	// the card exists to carry.
	for _, s := range c.Skills {
		g, there := c.Governance[s.ID]
		if !there {
			return fmt.Errorf(
				"skill %q has no governance entry, so it is advertised with "+
					"none of what this card exists to publish", s.ID)
		}
		if len(g.Capabilities) == 0 {
			return fmt.Errorf(
				"skill %q declares no capabilities, which cannot be true of "+
					"an agent that was accepted for publication", s.ID)
		}
		if g.Autonomy == "" {
			return fmt.Errorf("skill %q states no autonomy", s.ID)
		}
		if g.Budget.Steps <= 0 || g.Budget.Duration == "" {
			return fmt.Errorf(
				"skill %q publishes no usable budget, so a caller cannot "+
					"price a delegation before making one", s.ID)
		}
		if err := absoluteHTTPS(g.Revocation, "revocation for "+s.ID); err != nil {
			return err
		}
	}
	// And nothing may be governed that is not offered — an entry for a skill
	// that is not published is a promise about something nobody can call.
	for id := range c.Governance {
		if !seen[id] {
			return fmt.Errorf(
				"governance is published for %q, which is not one of the "+
					"skills", id)
		}
	}
	return nil
}

// absoluteHTTPS refuses anything a stranger cannot fetch.
//
// https specifically: a card is read by software on another machine, and a
// discovery document served over plain http is one anybody on the path can
// rewrite — including the part that says what this agent is allowed to do.
func absoluteHTTPS(raw, what string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s is empty", what)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a URL: %w", what, err)
	}
	if u.Scheme == "http" {
		// Loopback is the exception, because that is where somebody develops.
		if h := u.Hostname(); h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
	}
	if u.Scheme != "https" {
		return fmt.Errorf(
			"%s is %q. A card is read by software on another machine, and one "+
				"served over plain http can be rewritten in transit — "+
				"including the part saying what this agent may do",
			what, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host, so it is not fetchable by anybody else", what)
	}
	return nil
}
