// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
)

// Site analytics without a script or a cookie. See internal/analytics.

func analyticsDir(root string) string { return filepath.Join(root, "analytics") }

func cmdAnalytics(root string, args []string) error {
	fs := flag.NewFlagSet("analytics", flag.ContinueOnError)
	days := fs.Int("days", 30, "how many days, ending today")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	d, err := analytics.Read(analyticsDir(root), *days, time.Now())
	if err != nil {
		return err
	}
	s := analytics.Summarise(d)
	if w.JSON(map[string]any{"views": s.Views, "visitors": s.Visitors,
		"prefetched": s.Prefetch, "pages": s.Pages, "referrers": s.Referrers,
		"goals": s.Goals}) {
		return nil
	}
	w.Human("%s%d views, %d visitor-days over %d days%s  %s(+%d prefetched)%s\n",
		bold, s.Views, s.Visitors, *days, reset, dim, s.Prefetch, reset)
	for i, p := range s.Pages {
		if i == 10 {
			break
		}
		w.Human("  %6d  %s\n", p.Count, p.Name)
	}
	for _, g := range s.Goals {
		w.Human("  %sgoal%s %s  %d\n", dim, reset, g.Name, g.Count)
	}
	return nil
}

func analyticsCapability(root string) *admin.Analytics {
	return &admin.Analytics{Read: func(days int) ([]analytics.Day, error) {
		return analytics.Read(analyticsDir(root), days, time.Now())
	}}
}
