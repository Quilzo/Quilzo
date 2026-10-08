// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package geo

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"runtime"
	"strings"
	"testing"
)

// -- a minimal MMDB writer, so the reader is tested against the format ----

type enc struct{ bytes.Buffer }

// ctrl writes a control byte and its size, as the format does: sizes
// under 29 inline, then 29 plus one byte, 285 plus two, 65821 plus three.
func (e *enc) ctrl(typ, size int) {
	field, extra := size, []byte(nil)
	switch {
	case size >= 65821:
		n := size - 65821
		field, extra = 31, []byte{byte(n >> 16), byte(n >> 8), byte(n)}
	case size >= 285:
		n := size - 285
		field, extra = 30, []byte{byte(n >> 8), byte(n)}
	case size >= 29:
		field, extra = 29, []byte{byte(size - 29)}
	}
	if typ > 7 {
		e.WriteByte(byte(field))
		e.WriteByte(byte(typ - 7))
	} else {
		e.WriteByte(byte(typ<<5 | field))
	}
	e.Write(extra)
}
func (e *enc) str(s string) { e.ctrl(2, len(s)); e.WriteString(s) }
func (e *enc) dbl(f float64) {
	e.ctrl(3, 8)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], math.Float64bits(f))
	e.Write(b[:])
}
func (e *enc) u(typ int, n uint64, width int) {
	e.ctrl(typ, width)
	for i := width - 1; i >= 0; i-- {
		e.WriteByte(byte(n >> (8 * uint(i))))
	}
}
func (e *enc) m(n int) { e.ctrl(7, n) }

func cityRecord(e *enc, city, country string, lat, lon float64) {
	e.m(3)
	e.str("city")
	e.m(1)
	e.str("names")
	e.m(1)
	e.str("en")
	e.str(city)
	e.str("country")
	e.m(1)
	e.str("iso_code")
	e.str(country)
	e.str("location")
	e.m(2)
	e.str("latitude")
	e.dbl(lat)
	e.str("longitude")
	e.dbl(lon)
}

// buildDB writes an IPv4 database holding the given networks.
func buildDB(t *testing.T, nets map[string]func(*enc)) []byte {
	t.Helper()
	type node struct{ rec [2]int64 } // -1 empty, >=0 node, <= -10 data offset
	nodes := []node{{[2]int64{-1, -1}}}
	var data enc
	for prefix, write := range nets {
		pfx := netip.MustParsePrefix(prefix)
		off := data.Len()
		write(&data)
		a := pfx.Addr().As4()
		cur := 0
		for i := 0; i < pfx.Bits(); i++ {
			bit := int(a[i/8]>>(7-uint(i%8))) & 1
			if i == pfx.Bits()-1 {
				nodes[cur].rec[bit] = -10 - int64(off)
				break
			}
			if nodes[cur].rec[bit] < 0 {
				nodes = append(nodes, node{[2]int64{-1, -1}})
				nodes[cur].rec[bit] = int64(len(nodes) - 1)
			}
			cur = int(nodes[cur].rec[bit])
		}
	}
	count := uint32(len(nodes))
	var tree bytes.Buffer
	for _, n := range nodes {
		for _, r := range n.rec {
			v := uint32(count)
			switch {
			case r >= 0:
				v = uint32(r)
			case r <= -10:
				v = count + 16 + uint32(-10-r)
			}
			tree.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	var meta enc
	meta.m(5)
	meta.str("node_count")
	meta.u(6, uint64(count), 4)
	meta.str("record_size")
	meta.u(5, 24, 2)
	meta.str("ip_version")
	meta.u(5, 4, 2)
	meta.str("database_type")
	meta.str("Test-City")
	meta.str("build_epoch")
	meta.u(9, 1759363200, 8)
	out := append(tree.Bytes(), make([]byte, 16)...)
	out = append(out, data.Bytes()...)
	out = append(out, metaMarker...)
	return append(out, meta.Bytes()...)
}

func testDB(t *testing.T) []byte {
	return buildDB(t, map[string]func(*enc){
		"81.2.69.0/24": func(e *enc) { cityRecord(e, "London", "GB", 51.5074, -0.1278) },
		"1.128.0.0/11": func(e *enc) { cityRecord(e, "Sydney", "AU", -33.8688, 151.2093) },
	})
}

func TestTheCityDatabaseIsReadByTheFormat(t *testing.T) {
	db, err := Open(testDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if db.Type != "Test-City" || db.Built != 1759363200 {
		t.Errorf("metadata read as %q %d", db.Type, db.Built)
	}
	l := &Locator{DB: db}
	for _, c := range []struct{ ip, want string }{
		{"81.2.69.142", "London, GB"}, {"1.150.3.4", "Sydney, AU"}, {"::ffff:81.2.69.1", "London, GB"},
	} {
		p, ok := l.Locate(c.ip)
		if !ok || p.String() != c.want || !p.HasCoordinates() {
			t.Errorf("%s: %v %+v", c.ip, ok, p)
		}
	}
	for _, ip := range []string{"8.8.8.8", "10.0.0.1", "127.0.0.1", "2001:db8::1", "nonsense"} {
		if p, ok := l.Locate(ip); ok {
			t.Errorf("%s was placed at %v", ip, p)
		}
	}
}

// What the organisation names comes first, the most specific name wins,
// and a VPN is said to be a VPN rather than wherever its server is.
func TestDeclaredNetworksComeFirst(t *testing.T) {
	db, _ := Open(testDB(t))
	l := &Locator{DB: db, Networks: []Network{
		{Prefix: "81.2.0.0/16", Place: Place{Network: "Wide office range", Kind: "office", City: "Leeds", Country: "GB"}},
		{Prefix: "81.2.69.0/26", Place: Place{Network: "Corporate VPN", Kind: "vpn"}},
		{Prefix: "10.20.0.0/16", Place: Place{Network: "Lisbon office", Kind: "office", City: "Lisbon", Country: "PT", Lat: 38.72, Lon: -9.14}},
	}}
	if p, _ := l.Locate("81.2.69.10"); p.Kind != "vpn" || p.Network != "Corporate VPN" {
		t.Errorf("the VPN range lost to a wider one: %+v", p)
	}
	if p, _ := l.Locate("81.2.70.1"); p.City != "Leeds" {
		t.Errorf("a declared range lost to the database: %+v", p)
	}
	if p, ok := l.Locate("10.20.4.5"); !ok || p.String() != "Lisbon office (Lisbon, PT)" {
		t.Errorf("a private range the organisation named is not placed: %v %+v", ok, p)
	}
}

func TestDistancesAreGreatCircles(t *testing.T) {
	london, sydney, paris := Place{Lat: 51.5074, Lon: -0.1278}, Place{Lat: -33.8688, Lon: 151.2093}, Place{Lat: 48.8566, Lon: 2.3522}
	if d := Km(london, sydney); math.Abs(d-16990) > 30 {
		t.Errorf("London to Sydney is %.0f km", d)
	}
	if d := Km(london, paris); math.Abs(d-344) > 5 {
		t.Errorf("London to Paris is %.0f km", d)
	}
	if Km(paris, paris) != 0 {
		t.Error("a place is not at no distance from itself")
	}
}

// A pointer refers back into the data, as the file uses for repeated keys.
func TestPointersAreFollowed(t *testing.T) {
	var e enc
	e.str("shared")     // offset 0
	e.WriteByte(1 << 5) // pointer, size 0, vvv 0
	e.WriteByte(0)      // to offset 0
	v, next, err := decode(e.Bytes(), 7, 0)
	if err != nil || v != "shared" || next != 9 {
		t.Errorf("pointer decoded as %v, next %d, %v", v, next, err)
	}
}

// A damaged file fails; it does not crash, loop or read out of bounds.
func TestEveryTruncationFailsCleanly(t *testing.T) {
	full := testDB(t)
	for i := 0; i < len(full); i++ {
		db, err := Open(full[:i])
		if err == nil && db != nil {
			_, _ = db.Lookup(netip.MustParseAddr("81.2.69.1"))
		}
	}
	// A pointer that points at itself is refused, not followed for ever.
	loop := []byte{1 << 5, 0}
	if _, _, err := decode(loop, 0, 0); err == nil {
		t.Error("a pointer loop was followed to an answer")
	}
}

// Whatever the file holds, opening it and looking an address up returns an
// answer or an error, and never panics or hangs.
func FuzzOpenAndLookup(f *testing.F) {
	f.Add(testDBForFuzz())
	f.Add([]byte{})
	f.Add(append([]byte{0xab, 0xcd, 0xef}, metaMarker...))
	f.Fuzz(func(t *testing.T, b []byte) {
		db, err := Open(b)
		if err != nil {
			return
		}
		for _, ip := range []string{"81.2.69.1", "1.150.3.4", "::1", "2001:db8::1"} {
			_, _ = db.Lookup(netip.MustParseAddr(ip))
		}
	})
}

func testDBForFuzz() []byte {
	t := &testing.T{}
	return testDB(t)
}

// A header claiming millions of entries allocates for what is there.
func TestAClaimedHugeMapDoesNotAllocateForIt(t *testing.T) {
	var e enc
	e.WriteByte(7<<5 | 31) // a map whose size takes three more bytes
	e.Write([]byte{0xff, 0xff, 0xff})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, _ = decode(e.Bytes(), 0, 0)
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Errorf("%d bytes allocated for a map with nothing in it", grew)
	}
	if _, _, err := decode(e.Bytes(), 0, 0); err == nil {
		t.Error("a map claiming entries it does not have decoded")
	}
}

func asnRecord(e *enc, n uint64, org string) {
	e.m(2)
	e.str("autonomous_system_number")
	e.u(6, n, 4)
	e.str("autonomous_system_organization")
	e.str(org)
}

// The network: its number and name, Tor from the exit list, and hosting
// from the name of whoever runs it.
func TestTheNetworkIsNamedAndJudged(t *testing.T) {
	asn, err := Open(buildDB(t, map[string]func(*enc){
		"81.2.69.0/24":   func(e *enc) { asnRecord(e, 2856, "British Telecommunications PLC") },
		"5.6.7.0/24":     func(e *enc) { asnRecord(e, 14061, "DIGITALOCEAN-ASN") },
		"185.220.0.0/16": func(e *enc) { asnRecord(e, 4224, "Calyx Institute") },
	}))
	if err != nil {
		t.Fatal(err)
	}
	l := &Locator{ASNDB: asn, Tor: ParseTorExits([]byte("185.220.101.4\n\nnot an address\n"))}
	for _, c := range []struct {
		ip   string
		want NetInfo
	}{
		{"81.2.69.9", NetInfo{2856, "British Telecommunications PLC", ""}},
		{"5.6.7.8", NetInfo{14061, "DIGITALOCEAN-ASN", "hosting"}},
		{"185.220.101.4", NetInfo{4224, "Calyx Institute", "tor"}},
		{"185.220.101.5", NetInfo{4224, "Calyx Institute", ""}},
		{"nonsense", NetInfo{}},
	} {
		if got := l.Net(c.ip); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.ip, got, c.want)
		}
	}
}

// Long values use the format's longer size forms, and read back whole.
func TestLongValuesReadBackWhole(t *testing.T) {
	for _, n := range []int{28, 29, 284, 285, 300, 70000} {
		var e enc
		want := strings.Repeat("x", n)
		e.str(want)
		v, next, err := decode(e.Bytes(), 0, 0)
		if err != nil || v != want || next != e.Len() {
			t.Errorf("%d bytes: err %v, next %d of %d", n, err, next, e.Len())
		}
	}
}
