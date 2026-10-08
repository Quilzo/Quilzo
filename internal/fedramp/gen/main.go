// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Command gen writes internal/fedramp/ksi.json from FedRAMP's consolidated
// rules (github.com/FedRAMP/rules, fedramp-consolidated-rules.json): the
// Key Security Indicators, each with its statement and the SP 800-53
// controls FedRAMP relates to it, and the version and date of the rules
// they came from. Run it when FedRAMP publishes a new version:
//
//	go run ./internal/fedramp/gen fedramp-consolidated-rules.json > internal/fedramp/ksi.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type rules struct {
	Info struct {
		Title       string `json:"title"`
		Version     string `json:"version"`
		LastUpdated string `json:"last_updated"`
	} `json:"info"`
	KSI map[string]struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		Indicators map[string]struct {
			Name          string   `json:"name"`
			Statement     string   `json:"statement"`
			Controls      []string `json:"controls"`
			VariesByClass map[string]struct {
				Statement string `json:"statement"`
			} `json:"varies_by_class"`
		} `json:"indicators"`
	} `json:"KSI"`
}

type indicator struct {
	ID          string   `json:"id"`
	Theme       string   `json:"theme"`
	ThemeName   string   `json:"theme_name"`
	Name        string   `json:"name"`
	Statement   string   `json:"statement"`
	Controls    []string `json:"controls"`
	OptionalFor []string `json:"optional_for,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen fedramp-consolidated-rules.json")
		os.Exit(2)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var r rules
	if err := json.Unmarshal(b, &r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var out []indicator
	for _, t := range r.KSI {
		for id, in := range t.Indicators {
			ctl := append([]string(nil), in.Controls...)
			sort.Strings(ctl)
			ind := indicator{ID: id, Theme: t.ID, ThemeName: t.Name, Name: in.Name,
				Statement: in.Statement, Controls: ctl}
			// Some indicators are worded per class: optional at one,
			// required at another. The required wording is kept, and the
			// classes where it is optional are named.
			var classes []string
			for c := range in.VariesByClass {
				classes = append(classes, c)
			}
			sort.Strings(classes)
			for _, c := range classes {
				st := in.VariesByClass[c].Statement
				if strings.HasPrefix(st, "**Optional:**") {
					ind.OptionalFor = append(ind.OptionalFor, c)
				} else if ind.Statement == "" {
					ind.Statement = st
				}
			}
			out = append(out, ind)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	doc := map[string]any{
		"source":     map[string]string{"title": r.Info.Title, "version": r.Info.Version, "last_updated": r.Info.LastUpdated, "url": "https://github.com/FedRAMP/rules"},
		"indicators": out,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
