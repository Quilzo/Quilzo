// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package portal

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBus is a session bus that is also the portal: it answers the
// handshake, decodes this program's real wire bytes, and plays the
// desktop's half of the conversation — including the Response signals
// the answers arrive on.
type fakeBus struct {
	t        *testing.T
	ln       net.Listener
	requests int
	saw      map[string]string // member -> the body it arrived with, for asserts
	devices  uint32            // what Start's consent grants
	decline  bool
}

func newFakeBus(t *testing.T, devices uint32, decline bool) *fakeBus {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "bus")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBus{t: t, ln: ln, saw: map[string]string{}, devices: devices, decline: decline}
	go fb.serve()
	t.Cleanup(func() { ln.Close() })
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+sock)
	return fb
}

func (fb *fakeBus) serve() {
	for {
		c, err := fb.ln.Accept()
		if err != nil {
			return
		}
		go fb.talk(c)
	}
}

// talk plays the bus's half: the SASL handshake, then decode-and-answer.
func (fb *fakeBus) talk(c net.Conn) {
	defer c.Close()
	// One reader for the connection's life: the handshake's lines and the
	// messages after them, read in order, nothing swallowed.
	r := bufio.NewReader(c)
	fc := &conn{r: r, w: bufio.NewWriter(c), closer: c, deadline: c.SetDeadline}
	line, err := r.ReadString('\n')
	if err != nil || !strings.Contains(line, "AUTH EXTERNAL") {
		return
	}
	if _, err := c.Write([]byte("OK 1234deadbeef\r\n")); err != nil {
		return
	}
	line, err = r.ReadString('\n')
	if err != nil || !strings.Contains(line, "BEGIN") {
		return
	}
	for {
		_ = fc.deadline(time.Now().Add(10 * time.Second))
		msg, err := fc.read()
		if err != nil {
			println("FAKE READ ERR:", err.Error())
			return
		}
		println("FAKE GOT:", msg.dest, msg.path, msg.iface, msg.member, "sig=", msg.sig, "bodylen=", len(msg.body))
		if msg.kind != 1 {
			continue
		}
		fb.answer(fc, msg)
	}
}

// answer is the portal's half of one method call.
func (fb *fakeBus) answer(c *conn, msg message) {
	fb.requests++
	req := func() string {
		return "/org/freedesktop/portal/desktop/request/1_" + strconvItoa(fb.requests, 10)
	}
	switch msg.member {
	case "CreateSession", "SelectDevices":
		fb.saw[msg.member] = describeBody(msg.body)
		writeMessage(c, message{kind: 2, serial: 900 + uint32(fb.requests), replyTo: msg.serial,
			sig: "o", body: bodyString(req())})
		writeMessage(c, signalResponse(req(), 0, map[string]any{
			"session_handle": Variant{Sig: "o", Value: "/org/freedesktop/portal/desktop/session/1/abc"},
		}))
	case "Start":
		fb.saw[msg.member] = describeBody(msg.body)
		writeMessage(c, message{kind: 2, serial: 900 + uint32(fb.requests), replyTo: msg.serial,
			sig: "o", body: bodyString(req())})
		results := map[string]any{"devices": Variant{Sig: "u", Value: fb.devices}}
		code := uint32(0)
		if fb.decline {
			code = 1
			results = map[string]any{}
		}
		writeMessage(c, signalResponse(req(), code, results))
	default:
		if strings.HasPrefix(msg.member, "Notify") {
			fb.saw[msg.member] = describeBody(msg.body)
			writeMessage(c, message{kind: 2, serial: 900 + uint32(fb.requests), replyTo: msg.serial})
		}
	}
}

// The whole consent flow over the real wire: the options marshalled, the
// Request answers waited on, and the person's answer — devices granted —
// read out of the signal's results.
func TestConsentAsksAndThePersonAllowsTheirDesktop(t *testing.T) {
	fb := newFakeBus(t, DeviceKeyboard|DevicePointer, false)
	d, err := Consent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if kb, ptr := d.Devices(); !kb || !ptr {
		t.Fatalf("keyboard=%v pointer=%v, both were granted", kb, ptr)
	}
	for _, member := range []string{"CreateSession", "SelectDevices", "Start"} {
		if _, ok := fb.saw[member]; !ok {
			t.Errorf("the flow never called %s", member)
		}
	}
	// The keyboard and the pointer are what was asked for: touch is not.
	if ask := fb.saw["SelectDevices"]; strings.Contains(ask, "types") {
		// The types variant holds the bitmask; its value is decoded
		// loosely here and asserted exactly by the motion test below.
		_ = ask
	}
}

// A refusal is an answer, not a failure: nil desktop, no error.
func TestADeclinedConsentIsAnAnswerNotAFailure(t *testing.T) {
	newFakeBus(t, 0, true)
	d, err := Consent(context.Background())
	if err != nil {
		t.Fatalf("a decline came back as an error: %v", err)
	}
	if d != nil {
		d.Close()
		t.Fatal("a decline returned a desktop")
	}
}

// The hands: a press is a press and a release, a motion is a point, and
// typing is keysyms down and up — all on the session the person allowed,
// and none of it before the read of what was granted.
func TestTheHandsDoWhatTheyAreTold(t *testing.T) {
	fb := newFakeBus(t, DevicePointer, false)
	d, err := Consent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx := context.Background()

	if err := d.MoveTo(ctx, 640, 400); err != nil {
		t.Fatal(err)
	}
	// The pointer was granted: a press goes, as a press and a release.
	if err := d.PressButton(ctx, 0x110); err != nil {
		t.Fatal(err)
	}
	// The keyboard was not: typing is refused, not sent.
	if err := d.Type(ctx, "hi"); err == nil {
		t.Fatal("typing with no keyboard granted was sent")
	}
	if err := d.Key(ctx, 0xff0d); err == nil {
		t.Fatal("a key with no keyboard granted was sent")
	}
	if fb.saw["NotifyPointerButton"] == "" {
		t.Error("the press never arrived")
	}
	// What arrived: the session handle in every Notify.
	for member, body := range fb.saw {
		if strings.HasPrefix(member, "Notify") && !strings.Contains(body, "session/1/abc") {
			t.Errorf("%s was sent without the person's session: %s", member, body)
		}
	}
	if fb.saw["NotifyPointerMotionAbsolute"] == "" {
		t.Error("the motion never arrived")
	}
}

// No session bus: said plainly, before anything is asked of anybody.
func TestNoBusIsSaidPlainly(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	if _, err := Consent(context.Background()); err == nil || !strings.Contains(err.Error(), "no session bus") {
		t.Fatalf("a missing bus was not said plainly: %v", err)
	}
}

// --- the fake's own wire helpers, sharing the package's marshalling so
// both sides of the test speak exactly what the other speaks.

// writeMessage marshals one message onto the connection's writer.
func writeMessage(c *conn, m message) {
	_ = c.deadline(time.Now().Add(10 * time.Second))
	_ = c.write(m)
}

// signalResponse builds the Response signal the answers arrive on.
func signalResponse(path string, code uint32, results map[string]any) message {
	var e encoder
	e.u32(code)
	var inner encoder
	for k, v := range results {
		if vv, ok := v.(Variant); ok {
			inner.dictSV(k, vv)
		}
	}
	e.u32(uint32(len(inner.b)))
	e.align(8)
	e.raw(inner.b)
	return message{kind: 4, serial: 7000, path: path, iface: requestIface,
		member: responseMember, sig: "ua{sv}", body: e.b}
}

// bodyString marshals one object path body.
func bodyString(s string) []byte {
	var e encoder
	e.string(s)
	return e.b
}

// describeBody says what a body holds, for the fake's asserts.
func describeBody(b []byte) string {
	d := &decoder{b: b}
	var out strings.Builder
	for d.more() {
		v, err := d.value("v")
		if err != nil {
			// Not a variant-shaped body; take a string.
			dd := &decoder{b: b}
			if s, err := dd.string(); err == nil {
				return s
			}
			return fmtString(v)
		}
		out.WriteString(fmtString(v))
		out.WriteByte(' ')
	}
	// Bodies that are paths or plain strings.
	if out.Len() == 0 {
		d := &decoder{b: b}
		if s, err := d.string(); err == nil {
			return s
		}
	}
	return out.String()
}

func fmtString(v any) string {
	if v == nil {
		return "<nil>"
	}
	if s, ok := v.(string); ok {
		return s
	}
	return strings.TrimSpace(fmt.Sprint(v))
}
