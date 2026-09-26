// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/quilzo/quilzo/internal/sframe"
)

// End-to-end media encryption, and what it costs on the wire.
//
// SFrame sits above RTP so that a selective forwarding unit can route and
// drop and rewrite without being able to read anything. Three of its five
// cipher suites exist only to make the tag shorter than a GCM tag, which
// matters at thirty frames a second and does not matter anywhere else — so
// the first thing this command does is put the arithmetic in front of
// whoever is choosing.

func cmdSframe(args []string) error {
	if len(args) == 0 {
		args = []string{"suites"}
	}
	switch args[0] {
	case "suites":
		return sframeSuites(args[1:])
	case "check":
		return sframeCheck(args[1:])
	default:
		return fmt.Errorf("unknown sframe command %q; try suites or check",
			args[0])
	}
}

func sframeSuites(args []string) error {
	fs := flag.NewFlagSet("suites", flag.ContinueOnError)
	fps := fs.Int("fps", 30, "frames a second, for the overhead arithmetic")
	streams := fs.Int("streams", 1, "how many streams")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// A two-byte header is the ordinary case: a key identifier under eight
	// and a counter that has grown past it.
	const header = 2

	type row struct {
		Suite     string `json:"suite"`
		Tag       int    `json:"tag_bytes"`
		PerFrame  int    `json:"per_frame_bytes"`
		PerSecond int    `json:"bytes_per_second"`
	}
	var rows []row
	for _, s := range sframe.Suites() {
		per := s.Overhead(header)
		rows = append(rows, row{Suite: s.String(), Tag: s.TagBytes(),
			PerFrame: per, PerSecond: per * *fps * *streams})
	}
	if w.JSON(rows) {
		return nil
	}
	w.Human("%sRFC 9605 cipher suites%s\n", bold, reset)
	w.Human("  %sat %d frame(s) a second across %d stream(s), with a "+
		"two-byte header%s\n\n", dim, *fps, *streams, reset)
	for _, r := range rows {
		w.Human("%s%-28s%s %2d-byte tag  %2d bytes a frame  %d bytes a "+
			"second\n", bold, r.Suite, reset, r.Tag, r.PerFrame,
			r.PerSecond)
	}
	w.Human("\n  %sthe truncated suites exist for that last column. A "+
		"four-byte tag gives a forgery one chance in 2^32 per attempt, "+
		"which is defensible for a video frame discarded in 33 "+
		"milliseconds and is not defensible for anything durable%s\n",
		dim, reset)
	w.Human("  %sSFrame protects the media and nothing else: who is in the "+
		"call, who is speaking and for how long are all still visible to "+
		"whatever forwards the packets%s\n", dim, reset)
	return nil
}

// sframeCheck proves this build encrypts and decrypts correctly.
//
// Useful on a machine rather than in a test: a build against a different
// cryptographic module, on a different architecture, or with a different
// toolchain is a different binary, and the question "does the crypto in this
// one work" is answered by running it.
func sframeCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	which := fs.Int("suite", int(sframe.AES128GCMSHA256128),
		"which cipher suite to exercise")
	if err := fs.Parse(args); err != nil {
		return err
	}
	suite := sframe.Suite(*which)
	if !suite.Known() {
		return fmt.Errorf("%d is not a registered cipher suite", *which)
	}

	base := make([]byte, 32)
	if _, err := rand.Read(base); err != nil {
		return err
	}
	key, err := sframe.Derive(suite, 0x123, base)
	if err != nil {
		return err
	}
	plaintext := []byte("a frame of media")
	metadata := []byte("routing")
	frame, err := key.Seal(0x4567, plaintext, metadata)
	if err != nil {
		return err
	}
	back, header, err := sframe.Open(suite, base, frame, metadata)
	if err != nil {
		return err
	}
	if string(back) != string(plaintext) {
		return fmt.Errorf(
			"this build sealed a frame and opened it to something else")
	}
	// And a single altered byte has to fail, because a round trip on its
	// own would pass with no authentication at all.
	tampered := append([]byte(nil), frame...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := sframe.Open(suite, base, tampered,
		metadata); err == nil {
		return fmt.Errorf(
			"this build opened a frame with an altered byte, so the " +
				"authentication is not working")
	}

	if w.JSON(map[string]any{
		"suite": suite.String(), "kid": header.KID, "ctr": header.CTR,
		"frame": len(frame), "plaintext": len(plaintext),
		"overhead": len(frame) - len(plaintext),
	}) {
		return nil
	}
	w.Human("%s%s%s\n", green, suite, reset)
	w.Human("  %s%d bytes of media became %d on the wire%s\n", dim,
		len(plaintext), len(frame), reset)
	w.Human("  %sheader %s, key %d, counter %d%s\n", dim,
		hex.EncodeToString(frame[:len(frame)-len(plaintext)-
			suite.TagBytes()]), header.KID, header.CTR, reset)
	w.Human("  %sa frame with one byte changed was refused%s\n", dim, reset)
	return nil
}
