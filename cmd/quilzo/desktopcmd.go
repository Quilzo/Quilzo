// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/portal"
)

// The person's own desktop: the sixth tier of the computer-use plan, the
// weakest isolation of all, and off by default — there is no setting to
// turn on yet, because what a run may do with a person's hands is a
// decision that has not been made, and these commands exist to say
// honestly what is reachable, and to ask the person's consent when
// somebody at a desk wants to try what asking feels like.
//
// The consent is the portal's dialog, not this program's word: nothing is
// assumed, nothing is remembered, and a session lives exactly as long as
// the person's desktop says it does.

func cmdDesktop(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return desktopStatus(root)
	case "consent":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return desktopConsent(root)
	}
	return fmt.Errorf("unknown desktop command %q; try status or consent", args[0])
}

func desktopStatus(root string) error {
	// Whether a session bus is addressed, as one document under --json.
	// This printed its prose whatever was asked for, so a script asking
	// whether a desktop could be reached was given sentences to parse.
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		if w.JSON(map[string]bool{"session_bus": false}) {
			return nil
		}
		fmt.Printf("  %sno session bus is addressed here, so no desktop can be reached%s\n", yellow, reset)
		fmt.Printf("  the sixth tier is off for everyone, which is its default and its design\n")
		return nil
	}
	caller := resolveCaller(root, "")
	record(root, caller.auditRecord("desktop.status", "/", audit.Success,
		map[string]string{"bus": "addressed"}))
	if w.JSON(map[string]bool{"session_bus": true}) {
		return nil
	}
	fmt.Printf("  %sa session bus is addressed here%s\n", green, reset)
	fmt.Printf("  whether the desktop's portal answers, and whether a person consents,\n")
	fmt.Printf("  is `quilzo desktop consent`, which shows the desktop's own dialog\n")
	return nil
}

// desktopConsent asks the person for their desktop and reports what they
// allowed, then gives it straight back: a consent that ended in a session
// doing nothing is the honest demonstration, and the only one this
// offers.
func desktopConsent(root string) error {
	caller := resolveCaller(root, "")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	fmt.Printf("  %sasking the desktop's portal for the keyboard and the pointer…%s\n", dim, reset)
	fmt.Printf("  the dialog is the desktop's own; nothing happens until it is answered\n")
	d, err := portal.Consent(ctx)
	outcome, detail := audit.Success, map[string]string{"asked": "keyboard,pointer"}
	switch {
	case err != nil:
		// Returned, and not only printed. It fell through to closing a
		// desktop it never had, which is nil, so the command exited 0 and a
		// script or an agent was told the person had been asked when the
		// question never reached them. main prints it once, as a failure.
		detail["why"] = clip(err.Error(), 300)
		record(root, caller.auditRecord("desktop.consent", "/", audit.Failure, detail))
		return fmt.Errorf("the desktop could not be asked: %w", err)
	case d == nil:
		fmt.Printf("  %sthe person declined, and that is an answer%s\n", yellow, reset)
		record(root, caller.auditRecord("desktop.consent", "/", audit.Denied, detail))
		return nil
	default:
		kb, ptr := d.Devices()
		if kb {
			detail["granted"] = "keyboard"
		}
		if ptr {
			detail["granted"] = detail["granted"] + ",pointer"
		}
		fmt.Printf("  %sthe person allowed their %s desktop, for as long as the portal says%s\n",
			green, detail["granted"], reset)
		fmt.Printf("  given straight back: no run may use this yet, by design\n")
	}
	record(root, caller.auditRecord("desktop.consent", "/", outcome, detail))
	return d.Close()
}
