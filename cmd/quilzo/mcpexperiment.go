// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"time"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/experiment"
	"github.com/quilzo/quilzo/internal/mcp"
)

// Experiment results, for an agent. Reading only: starting a test changes
// what every visitor sees, and is a person's call.

func registerExperimentOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(mcp.Operation{
		Name: "experiment_report", NeedsRole: "reader",
		Summary: "the site's A/B tests and what can be concluded from each",
		Detail: "The verdict is only given once every variant has enough " +
			"visitors; before that it says so. Do not report a leader early.",
		Keywords: []string{"experiment", "ab test", "conversion", "variant"},
	}, func(map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		set, err := experiment.Load(experimentsPath(root))
		if err != nil {
			return nil, err
		}
		days, err := analytics.Read(analyticsDir(root), 90, time.Now())
		if err != nil {
			return nil, err
		}
		var out []experiment.Report
		for _, e := range set.Experiments {
			out = append(out, experiment.Measure(e, days))
		}
		b, err := json.Marshal(out)
		return string(b), err
	})
}
