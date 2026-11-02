// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/pii"
)

// Text read aloud through the gateway, by the routes that speak
// (Route.Speaks), under the same budgets, ledger and shield as words.
//
// Text is masked for a route not allowed personal data, as words are; but
// what is masked cannot be put back into a voice, and a placeholder read
// aloud is a recording nobody wants. So text that would be masked for a
// route is not sent to it at all: it goes to a route allowed it, or the
// caller is told why it went nowhere.

// speaker is a model that reads text aloud.
type speaker interface {
	Speak(ctx context.Context, text, voice string) ([]byte, assist.Usage, error)
}

// Speaks reports whether any route reads text aloud.
func (g *Gateway) Speaks() bool {
	for _, r := range g.cfg.Routes {
		if r.Speaks {
			return true
		}
	}
	return false
}

// Speak reads text aloud through the routes that speak, in their order,
// and says which model's voice it is.
func (g *Gateway) Speak(ctx context.Context, consumers []string, text, voice string) ([]byte, string, Money, error) {
	if len(consumers) == 0 {
		return nil, "", 0, errors.New("speech is charged to somebody")
	}
	consumer, also := consumers[0], consumers[1:]
	in := len(text)
	if err := g.admit(consumers, in); err != nil {
		g.note(Usage{At: g.now(), Consumer: consumer, Also: also, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil && !errors.Is(err, ErrUnwritable) {
			g.OnTrouble("spent", consumer)
		}
		return nil, "", 0, err
	}
	var errs []string
	for _, r := range g.cfg.Routes {
		if !r.Speaks {
			continue
		}
		mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: codescan.SecretSpans}
		_, said, _ := visible("", text)
		said = mask.Mask(said, r.Personal)
		if held := mask.Masked(); len(held) > 0 {
			kinds := make([]string, 0, len(held))
			for k := range held {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			errs = append(errs, r.Name+": the text holds "+strings.Join(kinds, ", ")+
				", which this route may not be sent and a voice cannot leave out")
			continue
		}
		g.mu.Lock()
		down := g.now().Before(g.downTil[r.Name])
		g.mu.Unlock()
		if down {
			errs = append(errs, r.Name+": resting after repeated failures")
			continue
		}
		if g.Cut != nil && g.Cut(r.Name) {
			errs = append(errs, r.Name+": cut by the shield")
			continue
		}
		m, err := g.model(r)
		if err != nil {
			errs = append(errs, r.Name+": "+err.Error())
			continue
		}
		sm, ok := m.(speaker)
		if !ok {
			errs = append(errs, r.Name+": its model does not speak")
			continue
		}
		start := g.now()
		audio, used, err := sm.Speak(ctx, said, voice)
		took := g.now().Sub(start)
		if err != nil {
			kind := g.failure(ctx, r.Name, err)
			g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
				Model: r.Model, In: in, Millis: took.Milliseconds(), Outcome: kind.outcome()})
			if kind != unavailable {
				return nil, "", 0, err
			}
			errs = append(errs, r.Name+": "+err.Error())
			continue
		}
		g.mu.Lock()
		g.fails[r.Name] = 0
		g.mu.Unlock()
		pin, _, _ := r.prices()
		cost := costOf(pin, 0, used.In, 0)
		g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name, Model: r.Model, In: in,
			TokensIn: used.In, Estimated: true, Millis: took.Milliseconds(), Cost: cost, Outcome: "ok"})
		return audio, r.Model, cost, nil
	}
	if len(errs) == 0 {
		return nil, "", 0, fmt.Errorf("%w: no route speaks (quilzo gateway route add NAME --speaks ...)", ErrNoRoute)
	}
	return nil, "", 0, fmt.Errorf("%w: %s", ErrNoRoute, strings.Join(errs, "; "))
}
