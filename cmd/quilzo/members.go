// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/member"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/throttle"
	"github.com/quilzo/quilzo/internal/webauthn"
)

// Accounts for a site's visitors, wired into the site and the admin. See
// internal/member and internal/public/members.go.

func membersDir(root string) string { return filepath.Join(root, "members") }

func openMembers(root string) (*member.Store, error) {
	return member.Open(membersDir(root))
}

// membersMode is site.members, or "off" for anything it does not recognise:
// a typo must not open sign-up to the world.
func membersMode(cfg *config.Config) string {
	switch m := strings.TrimSpace(cfg.Raw("site.members")); m {
	case "open", "invite":
		return m
	}
	return "off"
}

// memberParty is the site as a passkey relying party, from its address.
//
// A passkey is bound to a domain, and a browser offers one only to a page
// served from it over HTTPS — or from localhost, for trying it out. So
// accounts need site.base_url, and refuse one they cannot work with rather
// than starting and failing at every sign-in.
func memberParty(base string) (webauthn.Party, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Host == "" {
		return webauthn.Party{}, fmt.Errorf("accounts need site.base_url, the address the site is served at")
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return webauthn.Party{}, fmt.Errorf("a passkey belongs to a domain, and %s is an address; use a domain name, or localhost to try it", host)
	}
	if u.Scheme != "https" && host != "localhost" {
		return webauthn.Party{}, fmt.Errorf("browsers offer passkeys only over HTTPS, and %s is not", u.Scheme+"://"+u.Host)
	}
	return webauthn.Party{ID: host, Origin: u.Scheme + "://" + u.Host}, nil
}

// siteMembers is the public site's accounts, or nil when there are none.
func siteMembers(root string, cfg *config.Config, base string) *public.Members {
	mode := membersMode(cfg)
	if mode == "off" {
		return nil
	}
	party, err := memberParty(base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accounts are off: %v\n", err)
		return nil
	}
	store, err := openMembers(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accounts are off: %v\n", err)
		return nil
	}
	store.Sweep()
	return &public.Members{
		Store: store, Mode: mode, Party: party,
		Limit: throttle.New(throttlePolicy(cfg)),
		Audit: func(action, id, source string, ok bool) {
			outcome := audit.Success
			if !ok {
				outcome = audit.Denied
			}
			// The account's random id and where the request came from.
			// Never the name, which an erased account must not leave here.
			principal := source
			if id != "" {
				principal = "member:" + id
			}
			record(root, audit.Record{Action: action, Resource: "/account",
				Outcome: outcome, Principal: principal, Kind: audit.KindUnknown,
				Detail: map[string]string{"source": source}})
		},
	}
}

// membersHooks is the admin's Members screen, over the same store and the
// same audit records as `quilzo member`.
func membersHooks(root string) *admin.MembersAdmin {
	store, err := openMembers(root)
	if err != nil {
		return nil
	}
	note := func(action, by, id string) error {
		return recordE(root, audit.Record{Action: action, Resource: "/account",
			Outcome: audit.Success, Principal: by, Kind: audit.KindHuman,
			Detail: map[string]string{"member": id}})
	}
	return &admin.MembersAdmin{
		Mode: func() string {
			if cfg, err := loadConfig(root); err == nil {
				return membersMode(cfg)
			}
			return "off"
		},
		List:     store.List,
		Sessions: store.Sessions,
		SetDisabled: func(id string, disabled bool, by string) error {
			if err := store.SetDisabled(id, disabled); err != nil {
				return err
			}
			action := "member.enabled"
			if disabled {
				action = "member.disabled"
			}
			return note(action, by, id)
		},
		Remove: func(id, by string) error {
			// What they wrote first: an erased account's posts go with it.
			if posts, perr := openPosts(root); perr == nil {
				posts.RemoveAuthor(id)
			}
			if err := store.Delete(id); err != nil {
				return err
			}
			return note("member.removed", by, id)
		},
		Invite: func(by, why string) (string, member.Invite, error) {
			code, inv, err := store.NewInvite(by, why)
			if err != nil {
				return "", inv, err
			}
			return code, inv, note("member.invited", by, inv.Hash[:12])
		},
		Invites: store.Invites,
		Revoke: func(hash, by string) error {
			if err := store.RevokeInvite(hash); err != nil {
				return err
			}
			return note("member.invite-revoked", by, hash[:min(12, len(hash))])
		},
	}
}
