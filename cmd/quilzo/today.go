// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assist"
)

// todayBrief is the model each person's brief on Today is written by:
// through the gateway when one is declared, charged to the brief and to
// the person, each against its own budget, and the one configured model
// otherwise. None while today.brief is off or no model is set up.
func todayBrief(root string, cc *configCache) *admin.Brief {
	return &admin.Brief{Model: func(person string) assist.Model {
		if !cc.get().Bool("today.brief") {
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
	}}
}
