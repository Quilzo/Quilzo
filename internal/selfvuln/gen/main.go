// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Command gen writes the two files internal/selfvuln embeds, at release:
//
//	go run ./internal/selfvuln/gen -vulndb vulndb.zip
//
// stdlib.json.gz is the Go vulnerability database's records for the
// standard library and toolchain, from the database's own zip
// (https://vuln.go.dev/vulndb.zip), with the long descriptions left out.
// features.json is which of this program's features use which standard
// library packages, read from its source (selfvuln.Map).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/selfvuln"
)

func main() {
	db := flag.String("vulndb", "", "the Go vulnerability database's zip")
	out := flag.String("out", "internal/selfvuln", "where to write")
	src := flag.String("src", ".", "the module root to map")
	flag.Parse()
	if err := run(*db, *out, *src); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(db, out, src string) error {
	m, err := selfvuln.Map(src)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "features.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	if db == "" {
		return nil
	}
	gz, snap, err := selfvuln.FromZip(db)
	if err != nil {
		return err
	}
	fmt.Printf("%d standard-library records, database of %s, %d bytes\n", len(snap.Records), snap.Modified.Format("2 January 2006"), len(gz))
	return os.WriteFile(filepath.Join(out, "stdlib.json.gz"), gz, 0o644)
}
