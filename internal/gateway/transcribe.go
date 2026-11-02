// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/quilzo/quilzo/internal/assist"
)

// Recordings to text through the gateway, by the routes that transcribe
// (Route.Transcribes), under the same budgets, ledger and shield as words.
//
// A recording goes only to a route allowed personal data. Text is masked
// before it leaves; a voice cannot be: whatever somebody says in a video,
// their name, their address, a customer's account, goes as it was said.
// So it is the rule a picture in a conversation follows (chat.go), for
// the same reason.

// transcriber is a model that transcribes.
type transcriber interface {
	Transcribe(ctx context.Context, audio []byte, name, lang string) (string, assist.Usage, error)
}

// ErrRecordingNotAllowed is a recording with no route allowed personal
// data to transcribe it.
var ErrRecordingNotAllowed = errors.New("a recording cannot be checked for personal data, " +
	"so it is transcribed only by a route allowed personal data (--personal)")

// Transcribes reports whether any route transcribes, and whether one of
// them may be sent a recording.
func (g *Gateway) Transcribes() (any, allowed bool) {
	for _, r := range g.cfg.Routes {
		if r.Transcribes {
			any = true
			allowed = allowed || r.Personal
		}
	}
	return any, allowed
}

// Transcribe turns a recording into timed text, WebVTT, through the
// routes that transcribe and may be sent it, in their order. seconds is
// how long it runs, for its price; zero when nobody knows.
func (g *Gateway) Transcribe(ctx context.Context, consumers []string, audio []byte, name, lang string,
	seconds float64) (string, string, Money, error) {
	if len(consumers) == 0 {
		return "", "", 0, errors.New("a transcription is charged to somebody")
	}
	consumer, also := consumers[0], consumers[1:]
	// What a budget of characters counts it as: about what its words come
	// to, at a hundred and fifty a minute.
	in := int(math.Ceil(seconds/60)) * 900
	if err := g.admit(consumers, in); err != nil {
		g.note(Usage{At: g.now(), Consumer: consumer, Also: also, In: in, Outcome: "over-budget"})
		if g.OnTrouble != nil && !errors.Is(err, ErrUnwritable) {
			g.OnTrouble("spent", consumer)
		}
		return "", "", 0, err
	}
	any, allowed := g.Transcribes()
	switch {
	case !any:
		return "", "", 0, fmt.Errorf("%w: no route transcribes (quilzo gateway route add NAME --transcribes --personal ...)", ErrNoRoute)
	case !allowed:
		return "", "", 0, ErrRecordingNotAllowed
	}
	var errs []string
	for _, r := range g.cfg.Routes {
		if !r.Transcribes || !r.Personal {
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
		tm, ok := m.(transcriber)
		if !ok {
			errs = append(errs, r.Name+": its model does not transcribe")
			continue
		}
		start := g.now()
		text, used, err := tm.Transcribe(ctx, audio, name, lang)
		took := g.now().Sub(start)
		if err != nil {
			kind := g.failure(ctx, r.Name, err)
			g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name,
				Model: r.Model, In: in, Millis: took.Milliseconds(), Outcome: kind.outcome()})
			if kind != unavailable {
				return "", "", 0, err
			}
			errs = append(errs, r.Name+": "+err.Error())
			continue
		}
		g.mu.Lock()
		g.fails[r.Name] = 0
		g.mu.Unlock()
		var cost Money
		if r.PriceMinute != "" && seconds > 0 {
			if per, perr := ParseMoney(r.PriceMinute); perr == nil {
				cost = Money(math.Ceil(float64(per) * seconds / 60))
			}
		}
		g.note(Usage{At: start, Consumer: consumer, Also: also, Route: r.Name, Model: r.Model,
			In: in, Out: len(text), TokensOut: used.Out, Estimated: true, Millis: took.Milliseconds(),
			Cost: cost, Outcome: "ok"})
		return text, r.Model, cost, nil
	}
	return "", "", 0, fmt.Errorf("%w: %s", ErrNoRoute, strings.Join(errs, "; "))
}
