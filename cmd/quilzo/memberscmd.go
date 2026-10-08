// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/member"
)

// quilzo member: the site's accounts, from a terminal.
//
// The same operations as the Members screen, on the same store. Staff can
// see that an account exists, disable it, delete it, and invite somebody;
// they cannot sign in as a member or read a passkey, because there is
// nothing stored that would let anybody do either.

func memberUsage() error {
	return fmt.Errorf("usage: quilzo member list | show ID | disable ID | enable ID | " +
		"remove ID | invite [--note TEXT] | invites | revoke-invite HASH")
}

func cmdMember(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	store, err := openMembers(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	done := func(action, id string) error {
		return recordE(root, caller.auditRecord(action, "/account", audit.Success,
			map[string]string{"member": id}))
	}
	switch args[0] {
	case "list":
		all, err := store.List()
		if err != nil {
			return err
		}
		if w.JSON(map[string]any{"members": memberRows(store, all)}) {
			return nil
		}
		if cfg, cerr := loadConfig(root); cerr == nil {
			w.Human("  accounts are %s\n", membersMode(cfg))
		}
		if len(all) == 0 {
			w.Human("  no members\n")
			return nil
		}
		for _, m := range all {
			state := ""
			if m.Disabled {
				state = "  disabled"
			}
			w.Human("  %s  %-20s %d passkey(s), joined %s, seen %s%s\n", m.ID,
				onOneLine(m.Name), len(m.Passkeys), m.Created.Format("2 Jan 2006"),
				m.LastSeen.Format("2 Jan 2006"), state)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return memberUsage()
		}
		m, err := store.Get(args[1])
		if err != nil {
			return err
		}
		if w.JSON(memberRows(store, []member.Member{m})[0]) {
			return nil
		}
		w.Human("%s%s%s  %s\n", bold, onOneLine(m.Name), reset, m.ID)
		w.Human("  joined %s, last seen %s, %d session(s), %d unused recovery code(s)\n",
			m.Created.Format("2 Jan 2006 15:04 UTC"), m.LastSeen.Format("2 Jan 2006 15:04 UTC"),
			store.Sessions(m.ID), m.Recovery)
		for _, c := range m.Passkeys {
			used := "never used"
			if c.LastUsed > 0 {
				used = "last used " + time.Unix(c.LastUsed, 0).UTC().Format("2 Jan 2006")
			}
			w.Human("  passkey  %s, added %s, %s\n", onOneLine(c.Label),
				time.Unix(c.CreatedAt, 0).UTC().Format("2 Jan 2006"), used)
		}
		if m.Disabled {
			w.Human("  %sdisabled: cannot sign in%s\n", dim, reset)
		}
		return nil
	case "disable", "enable":
		if len(args) != 2 {
			return memberUsage()
		}
		if err := store.SetDisabled(args[1], args[0] == "disable"); err != nil {
			return err
		}
		w.Human("%sd %s; %s\n", args[0], args[1], map[string]string{
			"disable": "its sessions are ended and it cannot sign in",
			"enable":  "it can sign in again"}[args[0]])
		return done("member."+args[0]+"d", args[1])
	case "remove":
		if len(args) != 2 {
			return memberUsage()
		}
		if posts, perr := openPosts(root); perr == nil {
			posts.RemoveAuthor(args[1])
		}
		if err := store.Delete(args[1]); err != nil {
			return err
		}
		w.Human("removed %s, with its passkeys, recovery codes, sessions and posts\n", args[1])
		return done("member.removed", args[1])
	case "invite":
		fs := flag.NewFlagSet("member invite", flag.ContinueOnError)
		note := fs.String("note", "", "who it is for, to recognise it in the list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		code, inv, err := store.NewInvite(caller.Name, *note)
		if err != nil {
			return err
		}
		if !w.JSON(map[string]any{"code": code, "hash": inv.Hash, "expires": inv.Expires}) {
			w.Human("%s\n", code)
			w.Human("  %sone account, until %s; shown once, kept only as a hash%s\n",
				dim, inv.Expires.Format("2 Jan 2006"), reset)
		}
		return done("member.invited", inv.Hash[:12])
	case "invites":
		all := store.Invites()
		if w.JSON(map[string]any{"invites": all}) {
			return nil
		}
		if len(all) == 0 {
			w.Human("  no unused invitations\n")
		}
		for _, inv := range all {
			w.Human("  %s  by %s, until %s  %s\n", inv.Hash[:12], onOneLine(inv.By),
				inv.Expires.Format("2 Jan 2006"), onOneLine(inv.Note))
		}
		return nil
	case "revoke-invite":
		if len(args) != 2 || len(strings.TrimSpace(args[1])) < 6 {
			return fmt.Errorf("usage: quilzo member revoke-invite HASH (at least six characters of it)")
		}
		if err := store.RevokeInvite(args[1]); err != nil {
			return err
		}
		w.Human("revoked\n")
		return done("member.invite-revoked", args[1])
	}
	return memberUsage()
}

// memberRows is what a listing says about each account: never a passkey,
// only that it exists.
func memberRows(store *member.Store, ms []member.Member) []map[string]any {
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, map[string]any{
			"id": m.ID, "name": m.Name, "created": m.Created, "last_seen": m.LastSeen,
			"disabled": m.Disabled, "passkeys": len(m.Passkeys),
			"recovery_codes": m.Recovery, "sessions": store.Sessions(m.ID),
		})
	}
	return out
}
