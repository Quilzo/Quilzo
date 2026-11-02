// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/pii"
)

// Video made from a prompt, by the routes that make it (Route.Films), under
// the same budgets, ledger, masking and shield as pictures: a prompt is
// masked for a route not allowed personal data, and what the route costs a
// video is charged once it is made.

type filmer interface {
	Film(ctx context.Context, prompt, aspect string) ([]byte, assist.Usage, error)
}

// Films reports whether any route makes video.
func (g *Gateway) Films() bool {
	for _, r := range g.cfg.Routes {
		if r.Films {
			return true
		}
	}
	return false
}

// Film makes a video through the routes that make video, in their order,
// and says which model made it.
func (g *Gateway) Film(ctx context.Context, consumers []string, prompt, aspect string) ([]byte, string, Money, error) {
	if len(consumers) == 0 {
		return nil, "", 0, errors.New("a video is charged to somebody")
	}
	consumer, also := consumers[0], consumers[1:]
	in := len(prompt)
	if err := g.admit(consumers, in); err != nil {
		g.note(Usage{At: g.now(), Consumer: consumer, Also: also, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil && !errors.Is(err, ErrUnwritable) {
			g.OnTrouble("spent", consumer)
		}
		return nil, "", 0, err
	}
	var errs []string
	for _, r := range g.cfg.Routes {
		if !r.Films {
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
		fm, ok := m.(filmer)
		if !ok {
			errs = append(errs, r.Name+": its model does not make video")
			continue
		}
		mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: codescan.SecretSpans}
		_, said, hidden := visible("", prompt)
		said = mask.Mask(said, r.Personal)
		masked := mask.Masked()
		if hidden > 0 {
			masked["invisible"] = hidden
		}
		if len(masked) > 0 && g.OnMasked != nil {
			g.OnMasked(consumer, r.Name, masked)
		}
		start := g.now()
		video, used, err := fm.Film(ctx, said, aspect)
		took := g.now().Sub(start)
		if err != nil {
			kind := g.failure(ctx, r.Name, err)
			g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
				Model: r.Model, In: in, Millis: took.Milliseconds(), Masked: masked, Outcome: kind.outcome()})
			if kind != unavailable {
				return nil, "", 0, err
			}
			errs = append(errs, r.Name+": "+err.Error())
			continue
		}
		g.mu.Lock()
		g.fails[r.Name] = 0
		g.mu.Unlock()
		var cost Money
		if r.PriceVideo != "" {
			cost, _ = ParseMoney(r.PriceVideo)
		}
		g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name, Model: r.Model, In: in,
			TokensIn: used.In, Millis: took.Milliseconds(), Cost: cost, Masked: masked, Outcome: "ok"})
		return video, r.Model, cost, nil
	}
	if len(errs) == 0 {
		return nil, "", 0, fmt.Errorf("%w: no route makes video (quilzo gateway route add NAME --films --provider google-veo|fal ...)", ErrNoRoute)
	}
	return nil, "", 0, fmt.Errorf("%w: %s", ErrNoRoute, strings.Join(errs, "; "))
}
