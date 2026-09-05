package main

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/egress"
)

// What this program would connect to, and whether it may.
//
// The question an isolated deployment has to be able to answer, and the one it
// could not: the network use was spread across six packages with no list of
// them. This prints the list, the mode, and what each purpose costs to refuse
// -- so turning the network off is a decision somebody weighs rather than one
// they discover the consequences of a week later.

func cmdNetwork(root string, args []string) error {
	if len(args) > 0 && args[0] != "show" {
		return fmt.Errorf("usage: quilzo network [show]")
	}

	// The mode as configured, so this reports the deployment rather than the
	// state this particular process happens to be in.
	if cfg, err := loadConfig(root); err == nil {
		if m := cfg.Raw("network.mode"); m != "" {
			if serr := egress.SetMode(egress.Mode(m)); serr != nil {
				return fmt.Errorf("network.mode is %q; it is open or offline", m)
			}
		}
	}

	if w.JSON(map[string]any{
		"mode":     string(egress.Current()),
		"purposes": egress.Purposes,
		"refused":  egress.Refusals(),
	}) {
		return nil
	}
	w.Human("%s", egress.Report())
	if egress.Current() == egress.Open {
		w.Human("  %sto refuse everything that would leave this host:%s\n",
			dim, reset)
		w.Human("    quilzo config set network.mode offline\n")
	}
	return nil
}
