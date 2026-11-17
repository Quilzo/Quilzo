// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// screenFigures is what `quilzo screen cost --json` answers.
type screenFigures struct {
	Keystroke int    `json:"keystroke"`
	Still     int    `json:"still"`
	Cipher    string `json:"cipher"`
	Overhead  int    `json:"cipher_overhead"`
	Typing    int    `json:"typing_bytes_per_second"`
	Idle      int    `json:"idle_bytes_per_second"`
}

func screenCostJSON(t *testing.T, args ...string) screenFigures {
	t.Helper()
	o, e, code := cliRun(t, "", "", append([]string{"--json", "screen", "cost"}, args...)...)
	if code != 0 {
		t.Fatalf("screen cost --json exited %d: %s", code, firstLines(e, 3))
	}
	var f screenFigures
	if err := json.Unmarshal([]byte(o), &f); err != nil {
		t.Fatalf("screen cost --json is not JSON: %v", err)
	}
	return f
}

// What `screen cost` prints is what the codec makes, and nothing is added to
// it. The figures once carried the bytes frame encryption puts on every
// frame; that encryption left Quilzo with calls, and a rate that still
// counted it would be the cost of something this program does not do. So a
// second of typing is the keystroke times the frames, a still second the
// still frame times the frames, and the answer says nothing is added, in
// the fields a script reads and in the sentence a person does.
func TestScreenCostIsTheCodecsFiguresAlone(t *testing.T) {
	for _, fps := range []int{30, 60} {
		f := screenCostJSON(t, "--fps", strconv.Itoa(fps))
		if f.Typing != f.Keystroke*fps || f.Idle != f.Still*fps {
			t.Errorf("at %d frames a second a keystroke of %d bytes and a still of %d make %d and %d "+
				"bytes a second: something is added to the codec's figures",
				fps, f.Keystroke, f.Still, f.Typing, f.Idle)
		}
		if f.Cipher != "none" || f.Overhead != 0 {
			t.Errorf("the answer names cipher %q with %d bytes a frame, and none is applied", f.Cipher, f.Overhead)
		}
	}
	o, _, code := cliRun(t, "", "", "screen", "cost")
	if code != 0 || !strings.Contains(o, "the codec's figures alone") {
		t.Errorf("screen cost (exit %d) does not say its figures are the codec's alone: %s", code, firstLines(o, 12))
	}
	// --suite chose the encryption. It is still taken, so a script that
	// passes it goes on working, and it changes no figure.
	if with := screenCostJSON(t, "--suite", "4"); with != screenCostJSON(t) {
		t.Errorf("--suite changed the figures: %+v", with)
	}
}

// The line a person reads agrees with the figures a script reads.
//
// "about N KB/s" was the rate divided by 1024 and cut off, not rounded.
// With the encryption gone a second of typing at the default size is 8130
// bytes, which is 7.9 KB and was printed as "about 7 KB/s", while the
// documentation, working from the same figure, says just under 8.
func TestScreenCostsSummaryIsTheNearestKilobyte(t *testing.T) {
	line := regexp.MustCompile(`typing: about (\d+) KB/s\.\s+idle: about (\d+) KB/s`)
	for _, size := range [][]string{nil, {"--width", "1280", "--height", "720"}, {"--fps", "60"}} {
		f := screenCostJSON(t, size...)
		o, _, code := cliRun(t, "", "", append([]string{"screen", "cost"}, size...)...)
		m := line.FindStringSubmatch(o)
		if code != 0 || m == nil {
			t.Fatalf("screen cost %v (exit %d) has no summary line: %s", size, code, firstLines(o, 12))
		}
		for i, exact := range []int{f.Typing, f.Idle} {
			said, _ := strconv.Atoi(m[i+1])
			if off := said*1024 - exact; off > 512 || off < -512 {
				t.Errorf("screen cost %v says about %d KB/s of %d bytes a second, which is %.1f KB",
					size, said, exact, float64(exact)/1024)
			}
		}
	}
}
