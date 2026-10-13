// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package portal

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"
)

// The RemoteDesktop portal: the person's consent, then their pointer and
// keyboard, under the desktop's own door.
//
// The flow is the portal's, and the consent is real: Start puts the
// dialog on the person's screen and nothing of this program touches the
// desktop until they answer it. A session is the answer's child — it
// lives as long as the portal says, the person can close it from their
// desktop's own interface at any time, and a Notify after that fails,
// which is the revocability the plan demanded rather than a promise of
// it.

// The portal's names on the bus.
const (
	portalDest     = "org.freedesktop.portal.Desktop"
	portalPath     = "/org/freedesktop/portal/desktop"
	remoteIface    = "org.freedesktop.portal.RemoteDesktop"
	requestIface   = "org.freedesktop.portal.Request"
	responseMember = "Response"
)

// Devices the portal may grant.
const (
	DeviceKeyboard    = 1
	DevicePointer     = 2
	DeviceTouchscreen = 4
)

// Desktop is one consented session with the person's own desktop.
type Desktop struct {
	c       *conn
	session string
	devices uint32
}

// Consent asks the person for their desktop: a session is created, the
// keyboard and pointer requested, and Start shows the dialog. The
// returned Desktop is nil with no error when the person declined — a
// refusal is an answer, not a failure — and an error when the desktop
// never answered or something broke on the way to asking.
func Consent(ctx context.Context) (*Desktop, error) {
	c, err := dialSessionBus()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Desktop, error) {
		c.close()
		return nil, err
	}
	token := "quilzo" + strconvItoa(int(time.Now().UnixNano()&0xffffff), 16)

	// CreateSession: the portal answers on a Request object, with a
	// session handle in the response.
	handle, err := c.portalCall(ctx, "CreateSession", "a{sv}",
		optionsFor("session_handle_token", variantString(token)))
	if err != nil {
		return fail(err)
	}
	if handle.code != 0 {
		return fail(errors.New("the desktop made no session: " + handle.why()))
	}
	session, ok := handle.results["session_handle"]
	if !ok {
		return fail(errors.New("the portal made a session and named none"))
	}
	sessionPath, _ := session.(string)

	// SelectDevices: the keyboard and the pointer, and nothing else —
	// touch and clipboard are not this program's to ask for.
	selected, err := c.portalCall(ctx, "SelectDevices", "oa{sv}", sessionPath,
		optionsFor("types", Variant{Sig: "u", Value: uint32(DeviceKeyboard | DevicePointer)}))
	if err != nil {
		return fail(err)
	}
	if selected.code != 0 {
		return fail(errors.New("the desktop refused the devices: " + selected.why()))
	}

	// Start: the dialog. This is the person's answer, and the whole of
	// the permission this package ever has.
	started, err := c.portalCall(ctx, "Start", "osa{sv}", sessionPath, "",
		optionsFor("handle_token", variantString(token+"s")))
	if err != nil {
		return fail(err)
	}
	switch {
	case started.code == 1:
		// Cancelled at the dialog: an answer, recorded as one.
		c.close()
		return nil, nil
	case started.code != 0:
		return fail(errors.New("the desktop could not start the session: " + started.why()))
	}
	devices, ok := started.results["devices"]
	if !ok {
		return fail(errors.New("the portal answered without saying what was allowed"))
	}
	granted, _ := devices.(uint32)
	if granted == 0 {
		// Nothing allowed: as good as declined, and honest the same way.
		c.close()
		return nil, nil
	}
	return &Desktop{c: c, session: sessionPath, devices: granted}, nil
}

// Close ends the session, giving back what was consented.
func (d *Desktop) Close() error {
	if d == nil || d.c == nil {
		return nil
	}
	return d.c.close()
}

// Devices says what the person allowed: the keyboard and pointer bits.
func (d *Desktop) Devices() (keyboard, pointer bool) {
	return d.devices&DeviceKeyboard != 0, d.devices&DevicePointer != 0
}

// PressButton presses and releases a pointer button, by its evdev code:
// 0x110 left, 0x111 right, 0x112 middle.
func (d *Desktop) PressButton(ctx context.Context, evdev int32) error {
	if d.devices&DevicePointer == 0 {
		return errors.New("the person allowed no pointer")
	}
	if err := d.notify(ctx, "NotifyPointerButton", "ia{sv}u", evdev, pressedState); err != nil {
		return err
	}
	time.Sleep(30 * time.Millisecond)
	return d.notify(ctx, "NotifyPointerButton", "ia{sv}u", evdev, releasedState)
}

// MoveTo moves the pointer to a point of the person's screen.
func (d *Desktop) MoveTo(ctx context.Context, x, y float64) error {
	if d.devices&DevicePointer == 0 {
		return errors.New("the person allowed no pointer")
	}
	return d.notify(ctx, "NotifyPointerMotionAbsolute", "da{sv}dd", x, y)
}

// Type puts text where the desktop holds its focus. A character is its
// keysym: Latin-1 as itself, the rest of Unicode at 0x01000000 above its
// code point, as X defines them. Control characters are keys, not text,
// and are refused.
func (d *Desktop) Type(ctx context.Context, text string) error {
	if d.devices&DeviceKeyboard == 0 {
		return errors.New("the person allowed no keyboard")
	}
	for _, r := range text {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return errors.New("typed text carries no control characters; press keys by name")
		}
	}
	for _, r := range text {
		if err := d.Key(ctx, keysymOf(r)); err != nil {
			return err
		}
	}
	return nil
}

// keysymOf is a printable character's X keysym.
func keysymOf(r rune) int32 {
	if r <= 0xff {
		return int32(r)
	}
	return 0x01000000 | int32(r)
}

// The four named keys, by keysym.
const (
	KeyReturn    int32 = 0xff0d
	KeyTab       int32 = 0xff09
	KeyEscape    int32 = 0xff1b
	KeyBackSpace int32 = 0xff08
)

// Key presses one key by its keysym: the four the governed surfaces name,
// or a printable character. Anything else, a modifier or a function key,
// is refused rather than pressed.
func (d *Desktop) Key(ctx context.Context, keysym int32) error {
	if d.devices&DeviceKeyboard == 0 {
		return errors.New("the person allowed no keyboard")
	}
	switch {
	case keysym == KeyReturn, keysym == KeyTab, keysym == KeyEscape, keysym == KeyBackSpace:
	case keysym >= 0x20 && keysym <= 0xff && keysym != 0x7f:
	case keysym > 0x01000100 && keysym <= 0x0110ffff && !unicode.IsControl(rune(keysym&0xffffff)):
	default:
		return fmt.Errorf("keysym %#x is not one of the four named keys or a character", keysym)
	}
	if err := d.notify(ctx, "NotifyKeyboardKeysym", "ia{sv}u", keysym, pressedState); err != nil {
		return err
	}
	return d.notify(ctx, "NotifyKeyboardKeysym", "ia{sv}u", keysym, releasedState)
}

const (
	pressedState  = 1
	releasedState = 0
)

// notify sends one Notify method with the session and its options.
func (d *Desktop) notify(ctx context.Context, member, sig string, args ...any) error {
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(10 * time.Second)
	}
	_ = d.c.deadline(deadline)
	var e encoder
	e.string(d.session)
	// The options are empty; the marshal must still say them.
	e.u32(0)
	e.align(8)
	for _, a := range args {
		switch t := a.(type) {
		case int32:
			e.i32(t)
		case uint32:
			e.u32(t)
		case float64:
			e.double(t)
		}
	}
	return d.c.sendNotify(member, sig, e.b)
}

// portalCall makes one portal call and waits for its Request's Response,
// which is a signal: the answer to the dialog, not the reply to the
// method (that only names the Request).
func (c *conn) portalCall(ctx context.Context, member, sig string, args ...any) (response, error) {
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(2 * time.Minute)
	}
	_ = c.deadline(deadline)
	// The Request this call will answer on is derived from the token in
	// its options; the reply names it, so the call is sent, the Request
	// path read from the reply, and the Response signal read next.
	handle, body, err := c.callBody(portalDest, portalPath, remoteIface, member, sig, args)
	if err != nil {
		return response{}, err
	}
	_ = body
	return c.waitResponse(ctx, handle)
}

// response is what a Request's Response said.
type response struct {
	code    uint32
	results map[string]any
}

// why is the message the desktop gave with an answer that was not a yes.
func (r response) why() string {
	if s, ok := r.results["message"].(string); ok && s != "" {
		return s
	}
	if r.code == 1 {
		return "the person cancelled at the dialog"
	}
	return "the desktop gave no reason"
}

// waitResponse reads messages until the Response signal for a Request.
func (c *conn) waitResponse(ctx context.Context, requestPath string) (response, error) {
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(2 * time.Minute)
	}
	for {
		if ctx.Err() != nil {
			return response{}, ctx.Err()
		}
		if time.Now().After(deadline) {
			return response{}, errors.New("the desktop never answered: the person may still be looking at the dialog, or it never showed")
		}
		m, err := c.read()
		if err != nil {
			return response{}, err
		}
		if m.kind != 4 || m.iface != requestIface || m.member != responseMember || m.path != requestPath {
			continue
		}
		d := &decoder{b: m.body}
		v, err := d.value("u")
		if err != nil {
			return response{}, err
		}
		code, _ := v.(uint32)
		res := response{code: code, results: map[string]any{}}
		if d.more() {
			pairs, err := d.value("a{sv}")
			if err != nil {
				return response{}, err
			}
			if list, ok := pairs.([]any); ok {
				for _, p := range list {
					if pair, ok := p.(Pair); ok {
						var val any
						if pair.Value != nil {
							// Variants arrive as their inner value.
							val = pair.Value
							if v, ok := val.(Variant); ok {
								val = v.Value
							}
						}
						res.results[pair.Key] = val
					}
				}
			}
		}
		return res, nil
	}
}

// optionsFor builds one a{sv} argument, the token the portal needs to
// name its Request objects.
func optionsFor(key string, v Variant) []any {
	return []any{[]Pair{{Key: key, Value: v}}}
}

func variantString(s string) Variant { return Variant{Sig: "s", Value: s} }

// callBody sends a method call and returns the reply's Request path plus
// its decoded strings.
func (c *conn) callBody(dest, path, iface, member, sig string, args []any) (string, []string, error) {
	var e encoder
	for _, a := range args {
		switch t := a.(type) {
		case string:
			e.string(t)
		case []Pair:
			// The a{sv} options.
			var inner encoder
			for _, p := range t {
				inner.dictSV(p.Key, variantOf(p.Value))
			}
			e.u32(uint32(len(inner.b)))
			e.align(8)
			e.raw(inner.b)
		case Variant:
			e.variant(t)
		case uint32:
			e.u32(t)
		case int32:
			e.i32(t)
		case float64:
			e.double(t)
		}
	}
	reply, err := c.call(dest, path, iface, member, sig, e.b)
	if err != nil {
		return "", nil, err
	}
	d := &decoder{b: reply.body}
	var out []string
	if d.more() {
		if v, err := d.value("o"); err == nil {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	if len(out) == 0 {
		return "", nil, fmt.Errorf("%s answered without a Request to read", member)
	}
	return out[0], nil, nil
}

func variantOf(v any) Variant {
	if vv, ok := v.(Variant); ok {
		return vv
	}
	switch t := v.(type) {
	case string:
		return Variant{Sig: "s", Value: t}
	case uint32:
		return Variant{Sig: "u", Value: t}
	case bool:
		return Variant{Sig: "b", Value: t}
	}
	return Variant{Sig: "s", Value: fmt.Sprint(v)}
}

// sendNotify sends one Notify method and checks only that it was taken.
func (c *conn) sendNotify(member, sig string, body []byte) error {
	_, err := c.call(portalDest, portalPath, remoteIface, member, sig, body)
	return err
}

// strconvItoa in the base wanted, without importing strconv twice.
func strconvItoa(v, base int) string {
	if v == 0 {
		return "0"
	}
	digits := "0123456789abcdef"
	out := ""
	for v > 0 {
		out = string(digits[v%base]) + out
		v /= base
	}
	return out
}
