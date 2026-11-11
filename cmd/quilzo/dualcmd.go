// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/scim"
)

// Privileged changes that wait for a second administrator (internal/dual):
// where they are proposed from the command line, and `quilzo pending`,
// where they are decided.

func dualStore(root string) *dual.Store {
	return &dual.Store{Path: filepath.Join(root, "dual.json")}
}

// proposeSecond records a privileged change for a second administrator.
// It reports whether the caller should apply it now: true when the caller
// is the only administrator, whose request is approved as it is made;
// false when it waits, and the person has been told how it is approved.
func proposeSecond(root string, c *Caller, kind, what string, payload any, why string) (bool, error) {
	now := time.Now()
	alone := onlyAdministrator(root, c.Name)
	r, err := dualStore(root).Propose(kind, what, payload, why, c.Name, alone, now)
	if err != nil {
		return false, err
	}
	detail := map[string]string{"request": r.ID, "kind": kind, "what": what}
	maps.Copy(detail, r.About())
	if alone {
		detail["alone"] = "true"
		if err := recordE(root, c.auditRecord("dual.approved", "/", audit.Success, detail)); err != nil {
			return false, err
		}
		w.Human("%syou are the only administrator, so this is approved as you make it; the record says so%s\n",
			yellow, reset)
		return true, nil
	}
	if err := recordE(root, c.auditRecord("dual.proposed", "/", audit.Success, detail)); err != nil {
		return false, err
	}
	// The only administrator, whose request would have been approved as
	// they made it, a moment after another administrator was removed.
	if rm := aloneRefusal(root, c.Name, now); rm != nil {
		w.Human("%s%s%s\n", yellow, refuseAlone(root, c, rm, map[string]string{"request": r.ID, "kind": kind}), reset)
	}
	if w.JSON(r) {
		return false, nil
	}
	w.Human("%swaiting for a second administrator%s: %s (request %s)\n", yellow, reset, what, r.ID)
	w.Human("  %sanother administrator approves it with quilzo pending approve %s%s\n", dim, r.ID, reset)
	return false, nil
}

// applyDual makes an approved change, as by. A token, an enrolment link or
// a provisioning token is not made here: the person who asked for it
// receives it (quilzo pending redeem).
func applyDual(root string, r dual.Request, by string) error {
	switch r.Kind {
	case dual.Grant:
		var ch dual.GrantChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		_, err := updatePolicy(root, func(p *auth.Policy) error {
			for _, b := range ch.Bindings {
				if err := p.Grant(b); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	case dual.Setting:
		var ch dual.SettingChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		c, err := loadConfig(root)
		if err != nil {
			return err
		}
		if err := c.Set(ch.Key, ch.Value, ch.Reason, r.By); err != nil {
			return err
		}
		return saveConfig(root, c)
	case dual.AuditLog:
		var ch dual.AuditLogChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		// Written to the old log before the pointer moves, so the change is
		// in the record that was being kept at the time.
		record(root, resolveCaller(root, "").auditRecord("auditlog.dir", "/", audit.Success,
			map[string]string{"from": auditDir(root), "to": ch.Dir, "request": r.ID, "approved_by": by}))
		return setAuditDir(root, ch.Dir)
	case dual.Mapping:
		var ch dual.MappingChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		if err := scimMap(root, ch.Group, ch.To); err != nil {
			return err
		}
		return recordE(root, resolveCaller(root, "").auditRecord("scim.mapped", "/", audit.Success,
			map[string]string{"group": ch.Group + " → " + ch.To, "request": r.ID}))
	case dual.Pay:
		var ch dual.PayChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		caller := resolveCaller(root, "")
		if err := applyPay(root, ch, []string{r.By, by}, caller); err != nil {
			return err
		}
		syncPayAfterLive(root, caller)
		return nil
	case dual.Approval:
		var ch dual.ApprovalChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		return saveApprovalPolicy(root, resolveCaller(root, ""), collab.Policy{Required: ch.Required,
			RequiredHumans: ch.RequiredHumans, Approvers: ch.Approvers, RequireHumanForAI: true},
			map[string]string{"request": r.ID, "approved_by": by})
	case dual.Token, dual.Enrol, dual.SCIMToken:
		return nil
	}
	return fmt.Errorf("request %s is a %q, which this version does not know how to apply", r.ID, r.Kind)
}

// cmdPending is `quilzo pending [list] | approve ID | decline ID |
// withdraw ID | redeem ID`.
func cmdPending(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	store := dualStore(root)
	c := resolveCaller(root, "")
	now := time.Now()
	if args[0] == "list" {
		pend, err := store.Pending(now)
		if err != nil {
			return err
		}
		// Somebody's own requests, and everybody's to whoever may decide
		// them, as `auth list` lists grants (listedFor). The list asks only
		// to view, so that whoever asked for something can watch it wait,
		// and it printed the whole queue, with each payload under --json,
		// to a reader refused `pending show` and People for the same
		// requests: who was about to be made an administrator, which
		// enrolment links were asked for, which settings were being
		// weakened.
		who, everybody := listedFor(root, auth.ActGrant)
		if !everybody {
			pend = slices.DeleteFunc(pend, func(r dual.Request) bool { return !mine(r.By, who) })
		}
		if w.JSON(pend) {
			return nil
		}
		if !everybody {
			w.Human("  %syour own; everybody's are listed to whoever may grant%s\n", dim, reset)
		}
		if len(pend) == 0 {
			w.Human("nothing is waiting for a second administrator\n")
			return nil
		}
		for _, r := range pend {
			w.Human("%s%s%s  %s\n  %sby %s at %s; %s%s\n", bold, r.ID, reset, r.What, dim, r.By,
				r.At.UTC().Format("15:04 2 Jan"), dual.StateWords(r, now), reset)
			if r.Why != "" {
				w.Human("  %swhy: %s%s\n", dim, r.Why, reset)
			}
			if a := r.Approvers(); a != "" {
				w.Human("  %sapprovals would count only from: %s%s\n", dim, a, reset)
			}
			if r.Kind == dual.Mapping && r.Open(now) {
				w.Human("  %squilzo pending show %s lists the provisioning tokens it lets make administrators%s\n",
					dim, r.ID, reset)
			}
		}
		return nil
	}
	if len(args) != 2 {
		return errors.New("usage: quilzo pending [list] | show ID | approve ID | decline ID | withdraw ID | redeem ID")
	}
	id := args[1]
	switch args[0] {
	case "show":
		return showPending(root, id, now)
	case "approve", "decline":
		approve := args[0] == "approve"
		if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
			return err
		}
		// Their own request, approved alone: not for a day after another
		// administrator stopped being one.
		if mine, gerr := store.Get(id); approve && gerr == nil && auth.SamePerson(mine.By, c.Name) {
			if rm := aloneRefusal(root, c.Name, now); rm != nil {
				return refuseAlone(root, c, rm, map[string]string{"request": mine.ID, "kind": mine.Kind})
			}
		}
		r, err := store.Decide(id, c.Name, approve, onlyAdministrator(root, c.Name), now)
		if err != nil {
			return err
		}
		// Where the head keys were, for a move of the audit log, which the
		// approver is told of as its proposer would be (sayKeysLeftBehind).
		oldKeys := headKeysPath(root)
		if approve {
			if err := applyDual(root, r, c.Name); err != nil {
				return fmt.Errorf("approved, and applying it failed: %w", err)
			}
		}
		detail := map[string]string{"request": r.ID, "kind": r.Kind, "what": r.What, "proposed_by": r.By}
		maps.Copy(detail, r.About())
		if r.Alone {
			detail["alone"] = "true"
		}
		if err := recordE(root, c.auditRecord(map[bool]string{true: "dual.approved", false: "dual.declined"}[approve],
			"/", audit.Success, detail)); err != nil {
			return err
		}
		if w.JSON(r) {
			return nil
		}
		w.Human("%s: %s\n", dual.StateWords(r, now), r.What)
		if approve && r.Kind == dual.AuditLog {
			sayKeysLeftBehind(oldKeys, auditDir(root))
		}
		if approve && dual.Received(r.Kind) {
			w.Human("  %s%s receives it with quilzo pending redeem %s, within a day%s\n", dim, r.By, r.ID, reset)
		}
		return nil
	case "withdraw":
		r, err := store.Withdraw(id, c.Name, now)
		if err != nil {
			return err
		}
		w.Human("withdrawn: %s\n", r.What)
		return recordE(root, c.auditRecord("dual.withdrawn", "/", audit.Success,
			map[string]string{"request": r.ID, "kind": r.Kind}))
	case "redeem":
		r, err := store.Get(id)
		if err != nil {
			return err
		}
		if r.Kind == dual.Enrol {
			return redeemEnrolment(root, r, c, now)
		}
		if r.Kind == dual.SCIMToken {
			var ch dual.SCIMTokenChange
			if err := json.Unmarshal(r.Payload, &ch); err != nil {
				return err
			}
			if _, err := store.Redeem(id, c.Name, now); err != nil {
				return err
			}
			if err := recordE(root, c.auditRecord("dual.redeemed", "/", audit.Success,
				map[string]string{"request": r.ID, "kind": r.Kind, "approved_by": r.DecidedBy})); err != nil {
				return err
			}
			days := ch.Days
			if days == 0 {
				days = scimTokenDays
			}
			return giveSCIMToken(root, days, c, tokenMadeBy(c.Name, r))
		}
		if r.Kind != dual.Token {
			return fmt.Errorf("request %s is not a token: an approved %s is already done", r.ID, r.Kind)
		}
		var ch dual.TokenChange
		if err := json.Unmarshal(r.Payload, &ch); err != nil {
			return err
		}
		if _, err := store.Redeem(id, c.Name, now); err != nil {
			return err
		}
		if err := recordE(root, c.auditRecord("dual.redeemed", "/", audit.Success,
			map[string]string{"request": r.ID, "approved_by": r.DecidedBy})); err != nil {
			return err
		}
		return tokenIssueAs(root, ch.Args, true)
	}
	return errors.New("usage: quilzo pending [list] | show ID | approve ID | decline ID | withdraw ID | redeem ID")
}

// showPending is `quilzo pending show ID`: one request, as a person
// deciding it reads it.
//
// A group mapped to make administrators lets whoever holds the
// provisioning token make them, by putting people in the group, so its
// request lists every live token: who made it, when, and how it was
// approved. One made while no group made administrators was made by one
// person and stays valid once the mapping is approved; whoever approved
// the mapping could not see it.
func showPending(root, id string, now time.Time) error {
	r, err := dualStore(root).Get(id)
	if err != nil {
		return err
	}
	var live []scim.LiveToken
	if r.Kind == dual.Mapping {
		if live, err = liveSCIMTokens(root, now); err != nil {
			return fmt.Errorf("the provisioning token could not be read, and approving this lets it make administrators: %w", err)
		}
	}
	if w.JSON(map[string]any{"request": r, "state": dual.StateWords(r, now), "provisioning_tokens": live}) {
		return nil
	}
	w.Human("%s%s%s  %s\n  %sasked by %s at %s; %s%s\n", bold, r.ID, reset, r.What, dim, r.By,
		r.At.UTC().Format("15:04 2 Jan 2006 UTC"), dual.StateWords(r, now), reset)
	if r.Why != "" {
		w.Human("  %swhy: %s%s\n", dim, r.Why, reset)
	}
	if a := r.Approvers(); a != "" {
		w.Human("  %sapprovals would count only from: %s%s\n", dim, a, reset)
	}
	if r.Kind != dual.Mapping {
		return nil
	}
	if len(live) == 0 {
		w.Human("  no provisioning token works now; one made from now on takes two administrators\n")
		return nil
	}
	w.Human("  %sapproving this lets the provisioning token make administrators:%s\n", yellow, reset)
	for _, t := range live {
		w.Human("    %s\n", t.Words())
	}
	w.Human("  %sif that is not who should hold it, decline, or revoke it first: quilzo scim token --revoke%s\n", dim, reset)
	return nil
}

// tokenMadeBy is how a provisioning token given to by on request r was
// approved.
func tokenMadeBy(by string, r dual.Request) scim.TokenMade {
	if r.Alone {
		return scim.TokenMade{By: by, Approval: scim.Alone}
	}
	return scim.TokenMade{By: by, Approval: scim.ByTwo, ApprovedBy: r.DecidedBy}
}
