// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/quilzo/quilzo/internal/geo"
)

// Where sign-ins are placed from is said as a sentence for any number of
// named networks, with or without the city database.
func TestWhereSignInsArePlacedFromReadsForAnyNumber(t *testing.T) {
	root := t.TempDir()
	for _, c := range []struct {
		networks []geo.Network
		want     string
	}{
		{nil, "No office or VPN is named (quilzo geo network add); with no city database, " +
			"other addresses are not placed (quilzo geo help)."},
		{[]geo.Network{{Prefix: "203.0.113.0/24"}}, "Places come from the 1 network you declared; with no city database, " +
			"other addresses are not placed (quilzo geo help)."},
		{[]geo.Network{{Prefix: "203.0.113.0/24"}, {Prefix: "198.51.100.0/24"}}, "Places come from the 2 networks you declared; with no " +
			"city database, other addresses are not placed (quilzo geo help)."},
	} {
		b, _ := json.Marshal(geoConfig{Networks: c.networks})
		if err := os.WriteFile(geoPath(root), b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, desc, err := loadGeo(root)
		if err != nil || desc != c.want {
			t.Errorf("%d networks: %q %v", len(c.networks), desc, err)
		}
	}
}
