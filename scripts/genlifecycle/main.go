// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Command genlifecycle refreshes internal/lifecycle/lifecycle.json from
// endoflife.date, whose data is MIT-licensed, for the operating systems a
// device inventory reports. Run it by hand; the program never fetches it.
//
//	go run ./scripts/genlifecycle > internal/lifecycle/lifecycle.json
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type release struct {
	Name        string  `json:"name"`
	Label       string  `json:"label"`
	ReleaseDate string  `json:"releaseDate"`
	EOLFrom     *string `json:"eolFrom"`
	Latest      *struct {
		Name string  `json:"name"`
		Date *string `json:"date"`
	} `json:"latest"`
}

// Cycle is one release line of an operating system.
type Cycle struct {
	Cycle      string `json:"cycle"`
	Label      string `json:"label"`
	Released   string `json:"released"`
	EOL        string `json:"eol,omitempty"`
	Latest     string `json:"latest,omitempty"`
	LatestDate string `json:"latest_date,omitempty"`
}

func main() {
	out := struct {
		Source   string             `json:"source"`
		Licence  string             `json:"licence"`
		Fetched  string             `json:"fetched"`
		Products map[string][]Cycle `json:"products"`
	}{"https://endoflife.date", "MIT", time.Now().UTC().Format("2006-01-02"), map[string][]Cycle{}}
	client := &http.Client{Timeout: 30 * time.Second}
	for _, p := range []string{"macos", "windows", "ios", "ipados", "android"} {
		resp, err := client.Get("https://endoflife.date/api/v1/products/" + p + "/")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var body struct {
			Result struct {
				Releases []release `json:"releases"`
			} `json:"result"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, p, err)
			os.Exit(1)
		}
		for _, r := range body.Result.Releases {
			c := Cycle{Cycle: r.Name, Label: r.Label, Released: r.ReleaseDate}
			if r.EOLFrom != nil {
				c.EOL = *r.EOLFrom
			}
			if r.Latest != nil {
				c.Latest = r.Latest.Name
				if r.Latest.Date != nil {
					c.LatestDate = *r.Latest.Date
				}
			}
			out.Products[p] = append(out.Products[p], c)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
