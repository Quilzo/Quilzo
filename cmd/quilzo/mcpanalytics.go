// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"time"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
)

// Site analytics, for an agent: totals only, which is all there is.

func registerAnalyticsOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(mcp.Operation{
		Name: "site_analytics", NeedsRole: "reader",
		Summary: "page views, visitors, referrers and conversions, by day",
		Detail: "Counted at the server with no cookie; visitors are per day " +
			"and cannot be joined across days. Prefetched pages are counted " +
			"apart from views.",
		Args:     map[string]string{"days": "optional, 1 to 90, default 30"},
		Keywords: []string{"analytics", "traffic", "views", "visitors", "conversions"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		days := 30
		if n, ok := a["days"].(float64); ok && n >= 1 && n <= 90 {
			days = int(n)
		}
		d, err := analytics.Read(analyticsDir(root), days, time.Now())
		if err != nil {
			return nil, err
		}
		s := analytics.Summarise(d)
		b, err := json.Marshal(map[string]any{"views": s.Views, "visitors": s.Visitors,
			"prefetched": s.Prefetch, "pages": s.Pages, "referrers": s.Referrers,
			"goals": s.Goals})
		return string(b), err
	})
}
