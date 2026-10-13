// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package portal reaches the person's own desktop, when they say so:
// the sixth tier of the computer-use plan, the weakest isolation of all
// and therefore the last, and off by default.
//
// # What this is
//
// A D-Bus client in the standard library alone, and the RemoteDesktop
// portal's session on top of it: CreateSession, SelectDevices, Start —
// which is the person's consent, a dialog they see and answer — and then
// the Notify methods that move their pointer and press their keys. The
// portal is the only sanctioned door to another session's input on a
// modern Linux desktop, and consent is the portal's to obtain, not this
// program's to assume: no dialog answered, no session, nothing moves.
//
// # What this is not
//
// A general D-Bus implementation. It speaks method calls with the
// signatures the portal needs, reads the replies and the one signal the
// portal answers on, and refuses everything it does not understand rather
// than guessing — an unknown signature in a reply is a closed
// conversation, because a guess about what a desktop said is a guess
// about what a person's machine did. It cannot read the screen's tree
// (that is AT-SPI, another service), and it does not capture video: this
// is the hands, not the eyes, until the eyes can be had under the same
// consent.
package portal

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Variant is one D-Bus variant: a signature and the value it describes.
type Variant struct {
	Sig   string
	Value any
}

// The header field codes this reads and writes.
const (
	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSignature   = 8
)

// message is one D-Bus message, header and body.
type message struct {
	kind    byte // 1 call, 2 return, 3 error, 4 signal
	serial  uint32
	path    string
	iface   string
	member  string
	dest    string
	error   string
	replyTo uint32
	sig     string
	body    []byte
}

// conn is a D-Bus connection over a stream, authenticated the way a
// session bus wants: as the process's own uid, which is the person at
// the desk, and that is the point.
type conn struct {
	r        *bufio.Reader
	w        *bufio.Writer
	closer   ioCloser
	deadline func(time.Time) error
	next     atomic.Uint32
}

type ioCloser interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// ioReadFull is io.ReadFull, named so the import says what it is for.
var ioReadFull = io.ReadFull

// errAuth is the bus refusing who we are.
var errAuth = errors.New("the session bus did not accept this process as itself")

// dialSessionBus reaches the session bus from its address in the
// environment, the only place it is truthfully known.
func dialSessionBus() (*conn, error) {
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" {
		return nil, errors.New("no session bus is addressed here (DBUS_SESSION_BUS_ADDRESS), so there is no desktop to reach")
	}
	path := ""
	for _, part := range strings.Split(strings.TrimPrefix(addr, "unix:"), ",") {
		if v, ok := strings.CutPrefix(part, "path="); ok {
			path = v
		}
	}
	if path == "" {
		return nil, fmt.Errorf("the session bus address %q names no socket path", clipStr(addr, 80))
	}
	c, err := netDial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("the session bus: %w", err)
	}
	return authenticate(c)
}

// netDial is the one socket call, alone so a test can hand in its own.
var netDial = func(network, addr string) (ioCloser, error) {
	var d net.Dialer
	c, err := d.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// authenticate performs the SASL handshake the bus wants before any
// message: null byte, EXTERNAL with the uid hex-encoded, BEGIN.
func authenticate(c ioCloser) (*conn, error) {
	dc := &conn{r: bufio.NewReader(c), w: bufio.NewWriter(c), closer: c,
		deadline: func(time.Time) error { return nil }}
	if d, ok := c.(interface{ SetDeadline(t time.Time) error }); ok {
		dc.deadline = d.SetDeadline
	}
	uid := strconv.Itoa(os.Getuid())
	hexed := ""
	for _, b := range []byte(uid) {
		hexed += fmt.Sprintf("%02x", b)
	}
	if _, err := dc.w.Write([]byte("\x00AUTH EXTERNAL " + hexed + "\r\n")); err != nil {
		c.Close()
		return nil, err
	}
	if err := dc.w.Flush(); err != nil {
		c.Close()
		return nil, err
	}
	line, err := dc.r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "OK") {
		c.Close()
		return nil, errAuth
	}
	if _, err := dc.w.Write([]byte("BEGIN\r\n")); err != nil {
		c.Close()
		return nil, err
	}
	if err := dc.w.Flush(); err != nil {
		c.Close()
		return nil, err
	}
	dc.next.Store(1)
	return dc, nil
}

// close ends the conversation.
func (c *conn) close() error { return c.closer.Close() }

// call sends one method call and reads the reply that answers it:
// method returns, or the error the bus or the far side named.
func (c *conn) call(dest, path, iface, member, sig string, body []byte) (message, error) {
	serial := c.next.Add(1)
	m := message{kind: 1, serial: serial, path: path, iface: iface, member: member, dest: dest, sig: sig, body: body}
	if err := c.write(m); err != nil {
		return message{}, err
	}
	for {
		reply, err := c.read()
		if err != nil {
			return message{}, err
		}
		if reply.kind == 2 && reply.replyTo == serial {
			return reply, nil
		}
		if reply.kind == 3 && reply.replyTo == serial {
			why := reply.error
			if len(reply.body) > 0 {
				if strings, err := decodeStrings(reply.body); err == nil && len(strings) > 0 {
					why = why + ": " + strings[0]
				}
			}
			return message{}, errors.New(why)
		}
		// Anything else — a signal nobody asked for, a reply to a call
		// that has gone — is skipped, and the caller that wants signals
		// reads them on the same connection before its call.
	}
}

// write marshals one message onto the wire.
func (c *conn) write(m message) error {
	var e encoder
	e.byte('l') // little-endian, said once and honoured below
	e.byte(m.kind)
	e.byte(0) // no flags: no auto-start, no reply-expected games
	e.byte(1) // the protocol version
	lenAt := e.placeholder32()
	e.u32(m.serial)
	// The header fields, as an array of (byte, variant). Each entry is a
	// struct, and a struct begins 8-aligned; the length counts only the
	// entries' bytes, never the padding the array itself gets.
	var fields encoder
	field := func(code byte, sig string, put func(*encoder)) {
		fields.align(8)
		fields.byte(code)
		fields.signature(sig)
		put(&fields)
	}
	if m.path != "" {
		field(fieldPath, "o", func(e *encoder) { e.string(m.path) })
	}
	if m.iface != "" {
		field(fieldInterface, "s", func(e *encoder) { e.string(m.iface) })
	}
	if m.member != "" {
		field(fieldMember, "s", func(e *encoder) { e.string(m.member) })
	}
	if m.error != "" {
		field(fieldErrorName, "s", func(e *encoder) { e.string(m.error) })
	}
	if m.replyTo != 0 {
		field(fieldReplySerial, "u", func(e *encoder) { e.u32(m.replyTo) })
	}
	if m.dest != "" {
		field(fieldDestination, "s", func(e *encoder) { e.string(m.dest) })
	}
	if m.sig != "" {
		field(fieldSignature, "g", func(e *encoder) { e.signature(m.sig) })
	}
	e.u32(uint32(len(fields.b)))
	e.align(8)
	e.raw(fields.b)
	e.align(8)
	e.raw(m.body)
	e.fill32(lenAt, uint32(len(m.body)))
	if _, err := c.w.Write(e.b); err != nil {
		return err
	}
	return c.w.Flush()
}

// read unmarshals one message off the wire.
func (c *conn) read() (message, error) {
	head := make([]byte, 16)
	if _, err := ioReadFull(c.r, head); err != nil {
		return message{}, err
	}
	if head[0] != 'l' {
		return message{}, errors.New("the bus speaks an endianness this does not")
	}
	bodyLen := binary.LittleEndian.Uint32(head[4:8])
	serial := binary.LittleEndian.Uint32(head[8:12])
	fieldsLen := binary.LittleEndian.Uint32(head[12:16])
	// Header fields are a few short strings: a path, a name, a signature.
	// A length beyond that is refused before it is allocated.
	if fieldsLen > 1<<16 {
		return message{}, fmt.Errorf("the bus sent %d bytes of header fields, over what this reads", fieldsLen)
	}
	if bodyLen > 1<<22 {
		return message{}, fmt.Errorf("the bus sent a %d byte body, over what this reads", bodyLen)
	}
	fields := make([]byte, int(fieldsLen))
	if _, err := ioReadFull(c.r, fields); err != nil {
		return message{}, err
	}
	m := message{kind: head[1], serial: serial}
	if err := parseFields(fields, &m); err != nil {
		return message{}, err
	}
	pad := (8 - (int(fieldsLen) % 8)) % 8
	if pad > 0 {
		if _, err := ioReadFull(c.r, make([]byte, pad)); err != nil {
			return message{}, err
		}
	}
	m.body = make([]byte, int(bodyLen))
	if _, err := ioReadFull(c.r, m.body); err != nil {
		return message{}, err
	}
	return m, nil
}

// parseFields walks the header fields for the ones this understands.
func parseFields(b []byte, m *message) error {
	d := &decoder{b: b}
	for d.more() {
		// The entry is a struct and begins 8-aligned, as the encoder
		// wrote it; the length the array named stops before any trailing
		// padding.
		if err := d.align(8); err != nil {
			return err
		}
		if d.pos >= len(d.b) {
			break
		}
		code, err := d.byte()
		if err != nil {
			return err
		}
		sig, err := d.signature()
		if err != nil {
			return err
		}
		v, err := d.value(sig)
		if err != nil {
			return err
		}
		s, _ := v.(string)
		switch code {
		case fieldPath:
			m.path = s
		case fieldInterface:
			m.iface = s
		case fieldMember:
			m.member = s
		case fieldErrorName:
			m.error = s
		case fieldDestination:
			m.dest = s
		case fieldReplySerial:
			if u, ok := v.(uint32); ok {
				m.replyTo = u
			}
		case fieldSignature:
			if sg, ok := v.(string); ok {
				m.sig = sg
			}
		}
	}
	return nil
}

// encoder builds D-Bus wire bytes, alignment and all.
type encoder struct {
	b []byte
}

func (e *encoder) raw(p []byte) { e.b = append(e.b, p...) }
func (e *encoder) byte(v byte)  { e.b = append(e.b, v) }
func (e *encoder) align(n int) {
	for len(e.b)%n != 0 {
		e.b = append(e.b, 0)
	}
}
func (e *encoder) placeholder32() int { p := len(e.b); e.b = append(e.b, 0, 0, 0, 0); return p }
func (e *encoder) fill32(at int, v uint32) {
	binary.LittleEndian.PutUint32(e.b[at:at+4], v)
}
func (e *encoder) u32(v uint32) {
	e.align(4)
	e.raw([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}
func (e *encoder) i32(v int32) { e.u32(uint32(v)) }
func (e *encoder) boolean(v bool) {
	if v {
		e.u32(1)
		return
	}
	e.u32(0)
}
func (e *encoder) string(s string) {
	e.u32(uint32(len(s)))
	e.raw([]byte(s))
	e.byte(0)
}
func (e *encoder) signature(s string) {
	e.byte(byte(len(s)))
	e.raw([]byte(s))
	e.byte(0)
}
func (e *encoder) double(v float64) {
	e.align(8)
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(v))
	e.raw(buf[:])
}

// variant writes a variant: its signature, then the value under it.
func (e *encoder) variant(v Variant) {
	e.signature(v.Sig)
	switch t := v.Value.(type) {
	case string:
		e.string(t)
	case uint32:
		e.u32(t)
	case int32:
		e.i32(t)
	case bool:
		e.boolean(t)
	case float64:
		e.double(t)
	default:
		panic("portal: a variant this cannot encode")
	}
}

// dictSV writes one a{sv} entry.
func (e *encoder) dictSV(key string, v Variant) {
	e.align(8)
	e.string(key)
	e.variant(v)
}

// dictSVArray writes a whole a{sv} body.
func (e *encoder) dictSVArray(pairs ...struct {
	key string
	val Variant
}) {
	var inner encoder
	for _, p := range pairs {
		inner.dictSV(p.key, p.val)
	}
	e.u32(uint32(len(inner.b)))
	e.align(8)
	e.raw(inner.b)
}

// decoder walks wire bytes; it errors on what it does not know, which is
// the whole safety argument of reading a desktop's answers.
type decoder struct {
	b   []byte
	pos int
	// depth is how many containers deep the value being read is.
	depth int
}

func (d *decoder) more() bool { return d.pos < len(d.b) }

// align skips forward to a boundary counted from the start of the
// message. Every buffer this decodes begins at an 8-aligned offset in its
// message — the fixed header ends at 16, bodies at an 8 boundary — so the
// buffer's own origin can stand for the message's.
func (d *decoder) align(n int) error {
	for d.pos%n != 0 && d.pos < len(d.b) {
		d.pos++
	}
	return nil
}
func (d *decoder) byte() (byte, error) {
	if d.pos >= len(d.b) {
		return 0, errors.New("the message ended early")
	}
	v := d.b[d.pos]
	d.pos++
	return v, nil
}
func (d *decoder) u32() (uint32, error) {
	d.align(4)
	if d.pos+4 > len(d.b) {
		return 0, errors.New("the message ended early")
	}
	v := binary.LittleEndian.Uint32(d.b[d.pos:])
	d.pos += 4
	return v, nil
}
func (d *decoder) string() (string, error) {
	n, err := d.u32()
	if err != nil || d.pos+int(n)+1 > len(d.b) {
		return "", errors.New("the message ended early")
	}
	s := string(d.b[d.pos : d.pos+int(n)])
	d.pos += int(n) + 1
	return s, nil
}
func (d *decoder) signature() (string, error) {
	n, err := d.byte()
	if err != nil || d.pos+int(n)+1 > len(d.b) {
		return "", errors.New("the message ended early")
	}
	s := string(d.b[d.pos : d.pos+int(n)])
	d.pos += int(n) + 1
	return s, nil
}

// value decodes one value of a known signature. The set is the portal's:
// anything else is refused.
func (d *decoder) value(sig string) (any, error) {
	if sig == "" {
		return nil, errors.New("an empty signature where a value was")
	}
	// The specification's own limit on nesting, so a message of variants
	// inside variants cannot take the stack.
	if d.depth >= maxDepth {
		return nil, errors.New("a value nested deeper than the bus allows")
	}
	d.depth++
	defer func() { d.depth-- }()
	switch sig[0] {
	case 's', 'o':
		return d.string()
	case 'g':
		return d.signature()
	case 'u':
		return d.u32()
	case 'b':
		v, err := d.u32()
		return v != 0, err
	case 'v':
		inner, err := d.signature()
		if err != nil {
			return nil, err
		}
		return d.value(inner)
	case 'a':
		if len(sig) < 2 {
			return nil, errors.New("an array signature with no element")
		}
		elem := sig[1:]
		n, err := d.u32()
		if err != nil {
			return nil, err
		}
		end := d.pos + int(n)
		if end > len(d.b) {
			return nil, errors.New("an array longer than the message")
		}
		var out []any
		if strings.HasPrefix(elem, "{") {
			// Dict entries only as this needs them: a{sv}.
			if elem != "{sv}" {
				return nil, fmt.Errorf("a map this cannot read: a%s", elem)
			}
			for d.pos < end {
				d.align(8)
				k, err := d.string()
				if err != nil {
					return nil, err
				}
				v, err := d.value("v")
				if err != nil {
					return nil, err
				}
				out = append(out, Pair{Key: k, Value: v})
			}
		} else {
			for d.pos < end {
				v, err := d.value(elem)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
		}
		d.pos = end
		return out, nil
	}
	return nil, fmt.Errorf("a value this cannot read: signature %q", sig)
}

// maxDepth is the D-Bus specification's limit on nesting, arrays and
// variants together.
const maxDepth = 64

// Pair is one dict entry, the only map shape the portal needs.
type Pair struct {
	Key   string
	Value any
}

// decodeStrings pulls the strings out of an error body ("s" or "sus").
func decodeStrings(body []byte) ([]string, error) {
	d := &decoder{b: body}
	if !d.more() {
		return nil, nil
	}
	v, err := d.value("s")
	if err != nil {
		return nil, err
	}
	s, _ := v.(string)
	return []string{s}, nil
}

func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
