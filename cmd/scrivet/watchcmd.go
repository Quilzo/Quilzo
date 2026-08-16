package main

import (
	"fmt"
	"time"

	"github.com/lithoform/lithoform/internal/agentwatch"
	"github.com/lithoform/lithoform/internal/audit"
	"github.com/lithoform/lithoform/internal/out"
)

// cmdAgents reports on what models have been doing.
func cmdAgents(root string, args []string) error {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	reports := agentwatch.Look(events, time.Now())

	if w.Mode == out.JSON {
		w.JSON(map[string]any{
			"agents": reports, "flagged": len(agentwatch.Flagged(reports)),
		})
		if len(agentwatch.Flagged(reports)) > 0 {
			return errBlocked{fmt.Errorf("%d agent(s) flagged",
				len(agentwatch.Flagged(reports)))}
		}
		return nil
	}

	if len(reports) == 0 {
		w.Human("no model has acted in the last %s\n", agentwatch.Window)
		return nil
	}

	for _, r := range reports {
		state, colour := "ok", green
		if r.Flagged {
			state, colour = "flagged", red
		} else if len(r.Strikes) > 0 {
			state, colour = "watch", yellow
		}
		w.Human("  %s%-8s%s %-18s %s%s%s\n", colour, state, reset, r.Principal,
			dim, r.Model, reset)
		w.Human("           %s%s%s\n", dim, r.Summary, reset)

		for _, s := range r.Strikes {
			if s.Seq == 0 {
				w.Human("           %s· %s%s\n", dim, s.Why, reset)
				continue
			}
			w.Human("           %s· seq %d  %s %s — %s%s\n",
				dim, s.Seq, s.Action, s.Resource, s.Why, reset)
		}
	}

	if n := len(agentwatch.Flagged(reports)); n > 0 {
		w.Human("\n  %s%d agent(s) crossed the threshold%s\n", red, n, reset)
		w.Human("  %snothing has been revoked. This is a report, not a decision:\n"+
			"  automatic revocation on a heuristic means a busy afternoon of\n"+
			"  legitimate work looks like an incident, and then somebody turns\n"+
			"  the detector off%s\n", dim, reset)
		w.Human("  %severy strike names an audit entry, so each one can be "+
			"checked%s\n", dim, reset)
		return errBlocked{fmt.Errorf("%d agent(s) flagged", n)}
	}
	return nil
}
