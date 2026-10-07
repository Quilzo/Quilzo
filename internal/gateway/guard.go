// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gateway

import (
	"context"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/pii"
)

// Guarded is a model reached without the gateway's routes (the single
// model an install configures with QUILZO_MODEL_URL) behind the same
// privacy guard: what may not leave is masked before the prompt does, and
// put back in the answer.
type Guarded struct {
	Model assist.Model
	// Personal says it may receive personal data.
	Personal   bool
	OwnDomains []string
	OnMasked   func(counts map[string]int)
}

func (g Guarded) Name() string { return g.Model.Name() }

func (g Guarded) Complete(ctx context.Context, system, user string) (string, error) {
	out, _, err := g.CompleteMetered(ctx, system, user)
	return out, err
}

func (g Guarded) CompleteMetered(ctx context.Context, system, user string) (string, assist.Usage, error) {
	mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: codescan.SecretSpans}
	sys, usr, hidden := visible(system, user)
	sys, usr = mask.Mask(sys, g.Personal), mask.Mask(usr, g.Personal)
	var out string
	var used assist.Usage
	var err error
	if mm, ok := g.Model.(assist.Metered); ok {
		out, used, err = mm.CompleteMetered(ctx, sys, usr)
	} else {
		out, err = g.Model.Complete(ctx, sys, usr)
		used = assist.Estimate(sys+usr, out)
	}
	counts := mask.Masked()
	if hidden > 0 {
		counts["invisible"] = hidden
	}
	if len(counts) > 0 && g.OnMasked != nil {
		g.OnMasked(counts)
	}
	return mask.Restore(out), used, err
}
