// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package geo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
)

// A reader for the MaxMind DB format (MMDB), the file DB-IP's free city
// database ships as, written from the published specification
// (maxmind.github.io/MaxMind-DB) rather than taken from a library: the file
// is a binary search tree over address bits, a separator, a data section of
// typed values, and a metadata map at the end.
//
// Every offset read from the file is bounds-checked before it is used, and
// a pointer chain is limited in depth, because the file is input like any
// other and a corrupt or hostile one must fail, not crash or loop.

var metaMarker = []byte("\xab\xcd\xefMaxMind.com")

// DB is an opened database.
type DB struct {
	buf        []byte
	nodeCount  uint32
	recordSize uint16
	ipVersion  uint16
	data       []byte
	ipv4Start  uint32
	// Type is the database's own name for itself, such as DBIP-City-Lite.
	Type string
	// Built is when the file says it was made, in seconds since 1970.
	Built uint64
}

// Open reads a database from its bytes.
func Open(buf []byte) (*DB, error) {
	i := bytes.LastIndex(buf, metaMarker)
	if i < 0 {
		return nil, errors.New("not a MaxMind DB file: no metadata marker")
	}
	d := &DB{buf: buf}
	meta, _, err := decode(buf[i+len(metaMarker):], 0, 0)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	m, ok := meta.(map[string]any)
	if !ok {
		return nil, errors.New("metadata is not a map")
	}
	num := func(k string) uint64 {
		switch v := m[k].(type) {
		case uint64:
			return v
		}
		return 0
	}
	d.nodeCount, d.recordSize, d.ipVersion = uint32(num("node_count")), uint16(num("record_size")), uint16(num("ip_version"))
	d.Type, _ = m["database_type"].(string)
	d.Built = num("build_epoch")
	if d.recordSize != 24 && d.recordSize != 28 && d.recordSize != 32 {
		return nil, fmt.Errorf("record size %d is not one the format has", d.recordSize)
	}
	tree := uint64(d.nodeCount) * uint64(d.recordSize) * 2 / 8
	if tree+16 > uint64(i) {
		return nil, errors.New("the search tree is larger than the file")
	}
	d.data = buf[tree+16 : i]
	if d.ipVersion == 6 {
		// IPv4 lives under ::/96: follow 96 zero bits once.
		node := uint32(0)
		for b := 0; b < 96 && node < d.nodeCount; b++ {
			if node, err = d.record(node, 0); err != nil {
				return nil, err
			}
		}
		d.ipv4Start = node
	}
	return d, nil
}

func (d *DB) record(node uint32, bit int) (uint32, error) {
	size := uint32(d.recordSize) * 2 / 8
	off := uint64(node) * uint64(size)
	if off+uint64(size) > uint64(len(d.buf)) {
		return 0, errors.New("node outside the tree")
	}
	b := d.buf[off : off+uint64(size)]
	switch d.recordSize {
	case 24:
		if bit == 0 {
			return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
		}
		return uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5]), nil
	case 28:
		if bit == 0 {
			return uint32(b[3]>>4)<<24 | uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
		}
		return uint32(b[3]&0x0f)<<24 | uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]), nil
	default:
		if bit == 0 {
			return binary.BigEndian.Uint32(b[0:4]), nil
		}
		return binary.BigEndian.Uint32(b[4:8]), nil
	}
}

// Lookup finds the record for an address, or nil when the file has none.
func (d *DB) Lookup(ip netip.Addr) (map[string]any, error) {
	ip = ip.Unmap()
	var bits []byte
	node := uint32(0)
	switch {
	case ip.Is4() && d.ipVersion == 6:
		a := ip.As4()
		bits, node = a[:], d.ipv4Start
	case ip.Is4():
		a := ip.As4()
		bits = a[:]
	case d.ipVersion == 4:
		return nil, nil
	default:
		a := ip.As16()
		bits = a[:]
	}
	for i := 0; i < len(bits)*8 && node < d.nodeCount; i++ {
		bit := int(bits[i/8]>>(7-uint(i%8))) & 1
		var err error
		if node, err = d.record(node, bit); err != nil {
			return nil, err
		}
	}
	switch {
	case node == d.nodeCount:
		return nil, nil
	case node < d.nodeCount:
		return nil, errors.New("the tree ran out of address bits")
	}
	off := uint64(node-d.nodeCount) - 16
	if off >= uint64(len(d.data)) {
		return nil, errors.New("a record points outside the data section")
	}
	v, _, err := decode(d.data, int(off), 0)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	return m, nil
}

// decode reads one value at off, returning it and the offset after it.
func decode(b []byte, off, depth int) (any, int, error) {
	if depth > 32 {
		return nil, 0, errors.New("values nest too deeply")
	}
	if off >= len(b) {
		return nil, 0, errors.New("value outside the data")
	}
	ctrl := b[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 1 { // pointer
		ss, vvv := int(ctrl>>3)&3, int(ctrl&7)
		need := ss + 1
		if off+need > len(b) {
			return nil, 0, errors.New("pointer outside the data")
		}
		var p int
		switch ss {
		case 0:
			p = vvv<<8 | int(b[off])
		case 1:
			p = (vvv<<16 | int(b[off])<<8 | int(b[off+1])) + 2048
		case 2:
			p = (vvv<<24 | int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])) + 526336
		default:
			p = int(binary.BigEndian.Uint32(b[off : off+4]))
		}
		v, _, err := decode(b, p, depth+1)
		return v, off + need, err
	}
	if typ == 0 {
		if off >= len(b) {
			return nil, 0, errors.New("extended type outside the data")
		}
		typ = 7 + int(b[off])
		off++
	}
	size := int(ctrl & 0x1f)
	switch {
	case size == 29:
		if off >= len(b) {
			return nil, 0, errors.New("size outside the data")
		}
		size = 29 + int(b[off])
		off++
	case size == 30:
		if off+2 > len(b) {
			return nil, 0, errors.New("size outside the data")
		}
		size = 285 + int(binary.BigEndian.Uint16(b[off:off+2]))
		off += 2
	case size == 31:
		if off+3 > len(b) {
			return nil, 0, errors.New("size outside the data")
		}
		size = 65821 + (int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2]))
		off += 3
	}
	payload := func() ([]byte, error) {
		if size < 0 || off+size > len(b) {
			return nil, errors.New("a value runs past the end of the data")
		}
		return b[off : off+size], nil
	}
	readUint := func() (uint64, int, error) {
		p, err := payload()
		if err != nil || len(p) > 8 {
			return 0, 0, errors.New("an integer is too long")
		}
		var n uint64
		for _, c := range p {
			n = n<<8 | uint64(c)
		}
		return n, off + size, nil
	}
	switch typ {
	case 2: // UTF-8 string
		p, err := payload()
		return string(p), off + size, err
	case 3: // double
		if size != 8 || off+8 > len(b) {
			return nil, 0, errors.New("a double is not 8 bytes")
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b[off : off+8])), off + 8, nil
	case 4: // bytes
		p, err := payload()
		return append([]byte(nil), p...), off + size, err
	case 5, 6, 9: // unsigned 16, 32, 64
		return readUint()
	case 8: // signed 32
		n, next, err := readUint()
		return int64(int32(uint32(n))), next, err
	case 10: // unsigned 128: kept as bytes
		p, err := payload()
		return append([]byte(nil), p...), off + size, err
	case 7: // map
		// Capacity from what the remaining bytes could hold, never from the
		// size the file claims: every entry takes at least a byte, and a
		// header saying sixteen million must not allocate for them.
		m := make(map[string]any, capHint(size, len(b)-off))
		for i := 0; i < size; i++ {
			k, next, err := decode(b, off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, 0, errors.New("a map key is not a string")
			}
			v, after, err := decode(b, next, depth+1)
			if err != nil {
				return nil, 0, err
			}
			m[ks], off = v, after
		}
		return m, off, nil
	case 11: // array
		a := make([]any, 0, capHint(size, len(b)-off))
		for i := 0; i < size; i++ {
			v, next, err := decode(b, off, depth+1)
			if err != nil {
				return nil, 0, err
			}
			a, off = append(a, v), next
		}
		return a, off, nil
	case 14: // boolean, in the size
		return size != 0, off, nil
	case 15: // float
		if size != 4 || off+4 > len(b) {
			return nil, 0, errors.New("a float is not 4 bytes")
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b[off : off+4]))), off + 4, nil
	}
	return nil, 0, fmt.Errorf("type %d is not one this reader knows", typ)
}

func capHint(claimed, room int) int {
	if room < 0 {
		return 0
	}
	if claimed > room {
		return room
	}
	return claimed
}
