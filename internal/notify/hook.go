// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/webhook"
)

// The channel for a customer whose own systems have to act.
//
// A large customer receiving a breach notice has work to do that nobody at
// this end can do for them: rotating what they issued, telling their own
// users, opening their own incident. An email to a shared inbox starts that
// an hour later than a signed POST to an endpoint they control.
//
// # Why this does not reuse the CMS webhook event
//
// internal/webhook's Event is a closed list of things a site does —
// published, rolled-back, submitted — and its whole design is to name what
// changed rather than carry it, so that a misconfigured endpoint cannot leak
// unpublished content. A notice is the opposite case: the content is what the
// receiver needs, and there is nothing to fetch later. The signature scheme
// is shared because it is good and because a customer who already verifies
// one kind of webhook from this system should not have to write a second
// verifier.
//
// # One contact per request
//
// The payload carries one notice and one recipient, which is what keeps a
// customer's endpoint from learning who else was affected. There is no batch
// form of this and there is not going to be one.

// Hook is the JSON a receiver gets.
type Hook struct {
	// ID is stable across retries so a receiver can deduplicate.
	ID     string `json:"id"`
	Notice string `json:"notice"`
	Kind   Kind   `json:"kind"`
	// Basis and Declinable are stated rather than left to be inferred. A
	// receiver building their own preference screen on top of this needs to
	// know which of these their users may turn off, and the answer is not
	// something they should have to derive from the kind.
	Basis      Basis  `json:"basis"`
	Declinable bool   `json:"declinable"`
	Subject    string `json:"subject"`
	Body       string `json:"body"`
	// Contact is who this is about, in their own namespace.
	Contact string `json:"contact"`
	// Occurred, Aware and, for a breach, the Article 33 deadline.
	Occurred     string `json:"occurred"`
	Aware        string `json:"aware"`
	AuthorityDue string `json:"authority_due,omitempty"`
	// The Article 34(2) fields, so a receiver can pass them on verbatim
	// rather than paraphrasing a legal notice.
	Nature       string `json:"nature,omitempty"`
	ContactPoint string `json:"contact_point,omitempty"`
	Consequences string `json:"consequences,omitempty"`
	Measures     string `json:"measures,omitempty"`
	At           string `json:"at"`
}

// NewHook renders a notice for one recipient.
func NewHook(n Notice, d Delivery, at time.Time) Hook {
	h := Hook{
		ID: d.Key, Notice: n.ID, Kind: n.Kind, Basis: n.Kind.Basis(),
		Declinable: n.Kind.Objectable(), Subject: n.Subject, Body: n.Body,
		Contact:  d.To.String(),
		Occurred: n.Occurred.UTC().Format(time.RFC3339),
		Aware:    n.Aware.UTC().Format(time.RFC3339),
		At:       at.UTC().Format(time.RFC3339),
	}
	if n.Kind == Breach {
		h.AuthorityDue = n.AuthorityDue().UTC().Format(time.RFC3339)
		h.Nature, h.ContactPoint = n.Nature, n.Contact
		h.Consequences, h.Measures = n.Consequences, n.Measures
	}
	return h
}

// HookSender posts a notice to a customer's endpoint.
type HookSender struct {
	// Post is the transport, the same interface internal/webhook uses.
	Post webhook.Sender
	// Secret is the HMAC key shared with the receiver. Where a deployment
	// holds a different secret per customer, Secrets is consulted first.
	Secret  string
	Secrets map[string]string
	At      func() time.Time
}

func (h HookSender) now() time.Time {
	if h.At != nil {
		return h.At()
	}
	return time.Now().UTC()
}

// Send delivers one notice to one endpoint.
func (h HookSender) Send(n Notice, d Delivery) error {
	if d.Channel != Webhook {
		return fmt.Errorf("%s is not a webhook delivery", d.Key)
	}
	u, err := url.Parse(strings.TrimSpace(d.Address))
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", d.Address, err)
	}
	if u.Scheme != "https" {
		// The same rule the mailer applies to STARTTLS, and there is no flag
		// here either. A breach notice describing what leaked, posted over
		// plaintext HTTP to a customer's endpoint, is a second disclosure.
		return fmt.Errorf(
			"%s is not https. A notice describing what leaked, posted in "+
				"the clear, is a second disclosure — and for a webhook the "+
				"signature proves who sent it, not that nobody read it",
			d.Address)
	}
	secret := h.Secret
	if s, ok := h.Secrets[d.To.String()]; ok {
		secret = s
	}
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf(
			"no signing secret for %s. An unsigned notice is one the "+
				"receiver cannot tell from an attacker's, and the attacker's "+
				"version of a breach notice is a phishing campaign with our "+
				"name on it", d.To)
	}
	at := h.now()
	body, err := json.Marshal(NewHook(n, d, at))
	if err != nil {
		return err
	}
	status, err := h.Post.Post(d.Address, body, map[string]string{
		"Content-Type":     "application/json",
		"User-Agent":       "quilzo-notify",
		"Quilzo-Delivery":  d.Key,
		"Quilzo-Timestamp": fmt.Sprint(at.Unix()),
		"Quilzo-Signature": webhook.Sign(secret, at, body),
		"Quilzo-Notice-Of": string(n.Kind),
		"Auto-Submitted":   "auto-generated",
	})
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("%s answered %d", d.Address, status)
	}
	return nil
}

// ByChannel routes a delivery to the sender for its channel.
//
// A channel with no sender is an error and never a silent fallback to
// another one. An email contact quietly given an in-app notice instead is a
// person who was recorded as told and was not — and the record is what the
// retry consults, so they are never told afterwards either.
type ByChannel map[Channel]Sender

// Send routes one delivery.
func (b ByChannel) Send(n Notice, d Delivery) error {
	s, ok := b[d.Channel]
	if !ok || s == nil {
		return fmt.Errorf(
			"nothing is configured to send on the %s channel, and %s is "+
				"reachable only there. They have not been told", d.Channel,
			d.To)
	}
	return s.Send(n, d)
}
