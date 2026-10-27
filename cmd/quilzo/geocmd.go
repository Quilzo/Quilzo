// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/geo"
)

// Where sign-ins come from (internal/geo), and the store of each person's
// recent ones (internal/travel) that signinpolicy.go judges a sign-in
// against.

func signinsPath(root string) string { return filepath.Join(root, "signins") }
func geoPath(root string) string     { return filepath.Join(root, "geo.json") }
func geoDBPath(root string) string   { return filepath.Join(root, "geo", "city.mmdb") }
func geoASNPath(root string) string  { return filepath.Join(root, "geo", "asn.mmdb") }
func geoTorPath(root string) string  { return filepath.Join(root, "geo", "tor-exits.txt") }

type geoConfig struct {
	Networks []geo.Network `json:"networks"`
}

func loadGeo(root string) (*geo.Locator, string, error) {
	var c geoConfig
	if b, err := os.ReadFile(geoPath(root)); err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, "", fmt.Errorf("geo.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	l := &geo.Locator{Networks: c.Networks}
	// Where places come from, said as a sentence for any number of
	// networks: "the 0 networks you declared" is how a screen reads when
	// it was written for the case somebody tested.
	var from []string
	switch n := len(c.Networks); n {
	case 0:
	case 1:
		from = append(from, "the 1 network you declared")
	default:
		from = append(from, fmt.Sprintf("the %d networks you declared", n))
	}
	cityDB := false
	if b, err := os.ReadFile(geoDBPath(root)); err == nil {
		db, oerr := geo.Open(b)
		if oerr != nil {
			return nil, "", fmt.Errorf("%s: %w", geoDBPath(root), oerr)
		}
		l.DB = db
		cityDB = true
		from = append(from, db.Type+" (DB-IP, CC BY 4.0)")
	}
	desc := "Places come from " + strings.Join(from, " and ")
	if len(from) == 0 {
		desc = "No office or VPN is named (quilzo geo network add)"
	}
	if !cityDB {
		desc += "; with no city database, other addresses are not placed (quilzo geo help)"
	}
	if b, err := os.ReadFile(geoASNPath(root)); err == nil {
		db, oerr := geo.Open(b)
		if oerr != nil {
			return nil, "", fmt.Errorf("%s: %w", geoASNPath(root), oerr)
		}
		l.ASNDB = db
		desc += "; networks named from " + db.Type
	}
	if b, err := os.ReadFile(geoTorPath(root)); err == nil {
		l.Tor = geo.ParseTorExits(b)
		desc += fmt.Sprintf("; %d Tor exits known", len(l.Tor))
	}
	return l, desc + ".", nil
}

// geoCache keeps the locator and reloads it only when the networks file
// or the city database changes: the database is tens of megabytes, and a
// sign-in must not read it.
type geoCache struct {
	mu          sync.Mutex
	cfgAt, dbAt time.Time
	dbSize      int64
	loc         *geo.Locator
	desc        string
	err         error
	loaded      bool
}

var (
	geoCachesMu sync.Mutex
	geoCaches   = map[string]*geoCache{}
)

func cachedGeo(root string) (*geo.Locator, string, error) {
	geoCachesMu.Lock()
	c := geoCaches[root]
	if c == nil {
		c = &geoCache{}
		geoCaches[root] = c
	}
	geoCachesMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	var cfgAt, dbAt time.Time
	var dbSize int64
	if fi, err := os.Stat(geoPath(root)); err == nil {
		cfgAt = fi.ModTime()
	}
	// Any of the data files changing reloads them all.
	for _, p := range []string{geoDBPath(root), geoASNPath(root), geoTorPath(root)} {
		if fi, err := os.Stat(p); err == nil {
			if fi.ModTime().After(dbAt) {
				dbAt = fi.ModTime()
			}
			dbSize += fi.Size()
		}
	}
	if !c.loaded || !cfgAt.Equal(c.cfgAt) || !dbAt.Equal(c.dbAt) || dbSize != c.dbSize {
		c.loc, c.desc, c.err = loadGeo(root)
		c.cfgAt, c.dbAt, c.dbSize, c.loaded = cfgAt, dbAt, dbSize, true
	}
	return c.loc, c.desc, c.err
}

func geoUsage() error {
	return fmt.Errorf("usage: quilzo geo status | network add PREFIX NAME --kind office|vpn [--city C --country CC --lat N --lon N] | network remove PREFIX | help")
}

// cmdGeo says where sign-ins are placed from, and names networks.
func cmdGeo(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	var c geoConfig
	if b, err := os.ReadFile(geoPath(root)); err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("geo.json: %w", err)
		}
	}
	saveGeo := func(action, prefix string) error {
		sort.Slice(c.Networks, func(i, j int) bool { return c.Networks[i].Prefix < c.Networks[j].Prefix })
		b, err := json.MarshalIndent(c, "", " ")
		if err != nil {
			return err
		}
		if err := atomicfile.Write(geoPath(root), b, 0o600); err != nil {
			return err
		}
		// Naming a network an office or a VPN changes which sign-ins are
		// stepped up, so it is on the record.
		caller := resolveCaller(root, "")
		return recordE(root, caller.auditRecord(action, "/", audit.Success, map[string]string{"network": prefix}))
	}
	switch args[0] {
	case "status":
		_, desc, err := loadGeo(root)
		if err != nil {
			return err
		}
		w.Human("  %s\n", desc)
		for _, n := range c.Networks {
			w.Human("  %s  %s  %s\n", n.Prefix, n.Network, n.Place.String())
		}
		return nil
	case "help":
		w.Human("  Sign-ins are placed from networks you name first, then a city database.\n"+
			"  The database: download DB-IP's free IP to City Lite in MMDB form from\n"+
			"  https://db-ip.com/db/download/ip-to-city-lite (CC BY 4.0), unpack it, and put it at\n"+
			"  %s. It is never fetched by this program, and no lookup leaves the machine.\n\n"+
			"  Optional, beside it:\n"+
			"    %s  DB-IP's IP to ASN Lite (MMDB): names the network a sign-in came\n"+
			"      from, so a new provider and a hosting provider can be told apart from home\n"+
			"    %s  the Tor Project's bulk exit list, one address a line, from\n"+
			"      https://check.torproject.org/torbulkexitlist; refresh it daily\n", geoDBPath(root), geoASNPath(root), geoTorPath(root))
		return nil
	case "network":
		if len(args) < 3 {
			return geoUsage()
		}
		switch args[1] {
		case "remove":
			kept := c.Networks[:0]
			for _, n := range c.Networks {
				if n.Prefix != args[2] {
					kept = append(kept, n)
				}
			}
			c.Networks = kept
			return saveGeo("geo.network-removed", args[2])
		case "add":
			if len(args) < 4 {
				return geoUsage()
			}
			n := geo.Network{Prefix: args[2]}
			n.Network = args[3]
			for i := 4; i+1 < len(args); i += 2 {
				v := args[i+1]
				switch args[i] {
				case "--kind":
					if v != "office" && v != "vpn" {
						return fmt.Errorf("--kind is office or vpn")
					}
					n.Kind = v
				case "--city":
					n.City = v
				case "--country":
					n.Country = strings.ToUpper(v)
				case "--lat":
					f, err := strconv.ParseFloat(v, 64)
					if err != nil {
						return err
					}
					n.Lat = f
				case "--lon":
					f, err := strconv.ParseFloat(v, 64)
					if err != nil {
						return err
					}
					n.Lon = f
				default:
					return geoUsage()
				}
			}
			if _, err := netip.ParsePrefix(n.Prefix); err != nil {
				return fmt.Errorf("%q is not a network: %w", n.Prefix, err)
			}
			c.Networks = append(c.Networks, n)
			return saveGeo("geo.network-added", n.Prefix)
		}
	}
	return geoUsage()
}
