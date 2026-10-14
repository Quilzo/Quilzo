// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assist"
)

// todayModel is the model Today's brief or answers are written by while
// the setting is on: through the gateway when one is declared, charged to
// the use and to the person, each against its own budget, and the one
// configured model otherwise. None when no model is set up.
func todayModel(root string, cc *configCache, setting string) func(person string) assist.Model {
	return func(person string) assist.Model {
		if !cc.get().Bool(setting) {
			return nil
		}
		gw, _, err := modelGateway(root)
		if err != nil {
			return nil
		}
		if gw != nil {
			return gw.For("today:"+person, "person:"+person)
		}
		m, err := directModel(root)
		if err != nil {
			return nil
		}
		return m
	}
}

func todayBrief(root string, cc *configCache) *admin.Brief {
	return &admin.Brief{Model: todayModel(root, cc, "today.brief")}
}

// todayViewsPath keeps the views people pinned to Today: questions and the
// cards answering them, by person, never the values.
func todayViewsPath(root string) string { return filepath.Join(root, "today", "views.json") }

var todayViewsMu sync.Mutex

func todayAsk(root string, cc *configCache) *admin.Ask {
	load := func() (map[string][]admin.SavedView, error) {
		all := map[string][]admin.SavedView{}
		err := loadJSON(todayViewsPath(root), &all)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		return all, err
	}
	return &admin.Ask{
		Model: todayModel(root, cc, "today.ask"),
		Load: func(person string) ([]admin.SavedView, error) {
			todayViewsMu.Lock()
			defer todayViewsMu.Unlock()
			all, err := load()
			return all[person], err
		},
		Save: func(person string, views []admin.SavedView) error {
			todayViewsMu.Lock()
			defer todayViewsMu.Unlock()
			all, err := load()
			if err != nil {
				return err
			}
			if len(views) == 0 {
				delete(all, person)
			} else {
				all[person] = views
			}
			if err := os.MkdirAll(filepath.Dir(todayViewsPath(root)), 0o700); err != nil {
				return err
			}
			return saveJSON(todayViewsPath(root), all)
		},
	}
}
