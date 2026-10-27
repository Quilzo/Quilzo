// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/webhook"
)

// The state the public site writes, each in a directory of its own.
//
// The site runs confined (siteconfine.go): it reads the store and writes
// only where its own state is kept. A file it wrote at the store's root
// could not be confined that way, because replacing a file takes the right
// to create and remove files in its directory, and at the root that is the
// right to replace policy.json and tokens.json. So the shield's state, the
// site's followers, the model ledger and the webhook deliveries moved, and
// moveSiteState carries an existing store's across.

// siteStateMoves are the files that moved, from where to where.
var siteStateMoves = []struct{ from, to string }{
	{"shield.json", "shield/state.json"},
	{"followers.json", "fediverse/followers.json"},
	{"announced.json", "fediverse/announced.json"},
	{"model-usage.jsonl", "usage/models.jsonl"},
}

// moveSiteState moves what an older version kept at the store's root to
// where it is kept now. Every command runs it first, so the move is made by
// whichever runs first after an upgrade, before anything reads the files.
// A file already in its new place is the one in use, and an old one left
// beside it is left for a person to look at rather than overwritten.
func moveSiteState(root string) error {
	var errs []error
	for _, m := range siteStateMoves {
		from, to := filepath.Join(root, m.from), filepath.Join(root, filepath.FromSlash(m.to))
		if _, err := os.Stat(from); err != nil {
			continue
		}
		if _, err := os.Stat(to); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.Rename(from, to); err != nil {
			errs = append(errs, err)
			continue
		}
		_ = os.Remove(from + ".lock")
	}
	if err := moveDeliveries(root); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("moving the public site's state into its own directories: %w", err)
	}
	return nil
}

// deliveriesPath is where webhook deliveries are kept: apart from the
// endpoints and their secrets in webhooks.json, which the site reads to
// sign what it sends and is not let change.
func deliveriesPath(root string) string {
	return filepath.Join(root, "webhook-deliveries", "deliveries.json")
}

type deliveryFile struct {
	Deliveries []webhook.Delivery `json:"deliveries"`
}

// moveDeliveries moves deliveries an older version kept in webhooks.json to
// their own file.
func moveDeliveries(root string) error {
	if _, err := os.Stat(hooksPath(root)); err != nil {
		return nil
	}
	f := &hookFile{}
	if err := loadJSON(hooksPath(root), f); err != nil || len(f.Deliveries) == 0 {
		return nil
	}
	return updateHooks(root, func(f *hookFile) error {
		if len(f.Deliveries) == 0 {
			return atomicfile.ErrUnchanged
		}
		if err := keepDeliveries(root, f.Deliveries); err != nil {
			return err
		}
		f.Deliveries = nil
		return nil
	})
}

// keepDeliveries adds deliveries to the record of them, keeping the last
// hundred, so a failure is visible without the file growing without bound.
func keepDeliveries(root string, sent []webhook.Delivery) error {
	return atomicfile.Update(deliveriesPath(root), func(d *deliveryFile) error {
		d.Deliveries = append(d.Deliveries, sent...)
		if n := len(d.Deliveries); n > 100 {
			d.Deliveries = d.Deliveries[n-100:]
		}
		return nil
	})
}
