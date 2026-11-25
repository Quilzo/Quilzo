// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/quilzo/quilzo/internal/config"
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
		return errMisused{fmt.Errorf("usage: quilzo network [show]")}
	}
	// And nothing after show, which was not looked at.
	if len(args) > 0 {
		if err := noArguments(args[1:]); err != nil {
			return err
		}
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

// configuredNetworkMode is network.mode as the store's configuration says it,
// "" where it is not written, and an error when the configuration cannot say,
// which holds the command offline.
//
// From the file itself when it does not load, because the boundary is asked
// before any command runs and has to hold for the command whose own reading
// of the configuration then fails. Taking the default whenever the file did
// not load turned an offline deployment open on the command line for one
// unknown key, a value of the wrong type or a truncated file.
func configuredNetworkMode(root string) (string, error) {
	cfg, err := loadConfig(root)
	if err == nil {
		return strings.TrimSpace(cfg.Raw("network.mode")), nil
	}
	if body, rerr := os.ReadFile(configPath(root)); rerr == nil {
		if m, known := config.ValueIn(body, "network.mode"); known {
			return strings.TrimSpace(m), nil
		}
	}
	return "", fmt.Errorf("network.mode cannot be read (%v), so this command is held offline "+
		"until the configuration loads", err)
}
