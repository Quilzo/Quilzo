// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package fleet is every agent an organisation runs or uses, Quilzo's own
// and other vendors', and the AI use nobody registered.
//
// Quilzo's own agents, the apps people connected, the tool servers and the
// model routes are already known to it. Other vendors' agents are not, and
// they are most of what a company runs: one in the CRM, one in the help
// desk, one somebody built. A2A gave them a common description, the agent
// card, so registering one is handing Quilzo its card's address: what it
// says it is and can do, who answers for it here, and whether the card has
// changed since somebody looked.
//
// The other half is what nobody registered. Every security event Quilzo
// collects (proxy and DNS logs, the identity provider's app grants, its own
// agents' connections) can show somebody reaching an AI service directly.
// Each such sighting is shadow AI: not forbidden by this package, but
// unseen by the gateway, the budget and the log, and so worth a person's
// look.
package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// External is another vendor's agent, known by its A2A card.
type External struct {
	Name        string    `json:"name"`
	CardURL     string    `json:"card_url"`
	Description string    `json:"description,omitempty"`
	Provider    string    `json:"provider,omitempty"`
	Version     string    `json:"version,omitempty"`
	Skills      []string  `json:"skills,omitempty"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	Sponsor     string    `json:"sponsor"`
	Added       time.Time `json:"added"`
	Checked     time.Time `json:"checked"`
	// Digest is the card's as it was registered; Changed says the card
	// now says something else.
	Digest  string `json:"digest"`
	Changed bool   `json:"changed,omitempty"`
}

// Registry is the other vendors' agents.
type Registry struct {
	Agents []External `json:"agents"`
}

// MaxCard bounds a card that is read.
const MaxCard = 64 << 10

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ReadCard reads an A2A agent card, of 1.0 or of 0.3: what an agent says it
// is. Everything in it is the far side's words, so it is kept short and
// shown as theirs.
func ReadCard(body []byte, cardURL string) (External, error) {
	if len(body) > MaxCard {
		return External{}, errors.New("the card is more than 64 kilobytes")
	}
	var c struct {
		Name            string `json:"name"`
		Description     string `json:"description"`
		Version         string `json:"version"`
		ProtocolVersion string `json:"protocolVersion"`
		URL             string `json:"url"`
		Provider        *struct {
			Organization string `json:"organization"`
		} `json:"provider"`
		SupportedInterfaces []struct {
			URL             string `json:"url"`
			ProtocolBinding string `json:"protocolBinding"`
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"supportedInterfaces"`
		Skills []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"skills"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return External{}, fmt.Errorf("that is not an agent card: %w", err)
	}
	if strings.TrimSpace(c.Name) == "" {
		return External{}, errors.New("the card names no agent")
	}
	e := External{CardURL: cardURL, Description: short(c.Description, 300), Version: short(c.Version, 40)}
	e.Name = slug(c.Name)
	if c.Provider != nil {
		e.Provider = short(c.Provider.Organization, 80)
	}
	switch {
	case len(c.SupportedInterfaces) > 0:
		e.Endpoint, e.Protocol = c.SupportedInterfaces[0].URL, "A2A "+short(nonEmpty(c.SupportedInterfaces[0].ProtocolVersion, "1.0"), 10)
		if b := c.SupportedInterfaces[0].ProtocolBinding; b != "" {
			e.Protocol += " " + short(b, 20)
		}
	case c.URL != "":
		e.Endpoint, e.Protocol = c.URL, "A2A "+short(nonEmpty(c.ProtocolVersion, "0.3"), 10)
	}
	if e.Endpoint != "" {
		if u, err := url.Parse(e.Endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			e.Endpoint = ""
		}
	}
	for _, s := range c.Skills {
		if len(e.Skills) == 32 {
			break
		}
		e.Skills = append(e.Skills, short(nonEmpty(s.Name, s.ID), 60))
	}
	sum := sha256.Sum256(body)
	e.Digest = hex.EncodeToString(sum[:])
	return e, nil
}

// Add registers an agent, refusing a name already taken.
func (r *Registry) Add(e External) error {
	if !reName.MatchString(e.Name) {
		return fmt.Errorf("%q is not a name for an agent: lower-case letters, digits and hyphens", e.Name)
	}
	for _, x := range r.Agents {
		if x.Name == e.Name {
			return fmt.Errorf("an agent called %s is already registered", e.Name)
		}
		if x.CardURL == e.CardURL {
			return fmt.Errorf("%s is already registered as %s", e.CardURL, x.Name)
		}
	}
	r.Agents = append(r.Agents, e)
	sort.Slice(r.Agents, func(i, j int) bool { return r.Agents[i].Name < r.Agents[j].Name })
	return nil
}

// Remove unregisters one.
func (r *Registry) Remove(name string) bool {
	for i, x := range r.Agents {
		if x.Name == name {
			r.Agents = append(r.Agents[:i], r.Agents[i+1:]...)
			return true
		}
	}
	return false
}

func short(s string, n int) string {
	s = strings.Join(strings.Fields(plaintext.Clean(s)), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 64 {
		out = strings.Trim(out[:64], "-")
	}
	return out
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
