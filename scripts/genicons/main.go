// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Command genicons writes internal/icons/icons_gen.go: a chosen set of
// Material Symbols (Google, Apache-2.0) in each style a site can choose,
// as the single path each SVG holds. Run it by hand; the program never
// fetches an icon.
//
//	go run ./scripts/genicons > internal/icons/icons_gen.go
package main

import (
	"fmt"
	"go/format"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// names are the icons a site may use: what feature lists, steps, contact
// blocks and pricing tables reach for. A closed list, so a name in content
// is either one of these or nothing.
var names = []string{
	"accessibility_new", "account_balance", "add_circle", "analytics", "apartment", "arrow_forward",
	"article", "auto_awesome", "bolt", "brush", "build", "calendar_month", "call", "campaign",
	"celebration", "chat", "check_circle", "cloud", "cloud_upload", "code",
	"description", "devices", "directions_car", "done_all", "download", "eco", "edit", "encrypted",
	"favorite", "fingerprint", "fitness_center", "flight", "folder", "forum", "groups", "handshake",
	"health_and_safety", "history", "home", "image", "insights", "inventory_2", "key", "language",
	"lightbulb", "local_cafe", "local_shipping", "location_on", "lock", "mail", "map", "menu_book", "mic",
	"music_note", "notifications", "open_in_new", "palette", "payments", "person", "pets",
	"photo_camera", "psychology", "public", "receipt_long", "recycling", "redeem", "restaurant",
	"rocket_launch", "savings", "schedule", "school", "science", "search", "security", "sell",
	"settings", "shield", "shopping_cart", "smart_toy", "speed", "star", "stop_circle", "storefront", "sunny",
	"support_agent", "sync", "terminal", "thumb_up", "translate", "trending_up", "tune",
	"verified", "videocam", "visibility", "volume_up", "water_drop", "wifi", "workspace_premium",
}

var styles = []struct{ key, dir, suffix string }{
	{"rounded", "materialsymbolsrounded", "_24px.svg"},
	{"rounded-filled", "materialsymbolsrounded", "_fill1_24px.svg"},
	{"outlined", "materialsymbolsoutlined", "_24px.svg"},
	{"outlined-filled", "materialsymbolsoutlined", "_fill1_24px.svg"},
	{"sharp", "materialsymbolssharp", "_24px.svg"},
	{"sharp-filled", "materialsymbolssharp", "_fill1_24px.svg"},
}

var rePath = regexp.MustCompile(`<path d="([^"]+)"`)
var reSafe = regexp.MustCompile(`^[0-9MmLlHhVvCcSsQqTtAaZz .,-]+$`)

var (
	reViewBox = regexp.MustCompile(`<svg[^>]*\sviewBox="([^"]+)"`)
	reWidth   = regexp.MustCompile(`<svg[^>]*\swidth="([^"]+)"`)
	reHeight  = regexp.MustCompile(`<svg[^>]*\sheight="([^"]+)"`)
	reToken   = regexp.MustCompile(`[A-Za-z]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?`)
)

// box is the set's viewBox, which internal/icons serves every icon in.
const box = "0 -960 960 960"

// inTheBox is an icon's path drawn in the set's box.
//
// Most of the source is drawn in the 960-unit box. A few icons are only
// there in its older drawing, 24 units square with no viewBox: insights and
// auto_awesome were, and were kept as they came, so they drew a speck in a
// corner off the box the page shows and every product site's third card had
// an empty tile. Those are scaled into the box here, and anything drawn in a
// box of some other shape is refused rather than kept wrong.
func inTheBox(svg []byte, d string) (string, error) {
	vb := ""
	if m := reViewBox.FindSubmatch(svg); m != nil {
		vb = strings.Join(strings.Fields(string(m[1])), " ")
	} else if w, h := reWidth.FindSubmatch(svg), reHeight.FindSubmatch(svg); w != nil && h != nil {
		vb = "0 0 " + string(w[1]) + " " + string(h[1])
	}
	switch vb {
	case box:
		return d, nil
	case "0 0 24 24":
		return rescale(d, 40, -960)
	}
	return "", fmt.Errorf("drawn in the box %q, which is not %q or 24 units square", vb, box)
}

// rescale draws a path k times larger and dy lower: every absolute point is
// scaled and moved, every relative one only scaled. Only the commands the
// source uses are read; an arc, whose flags are not coordinates, is refused.
func rescale(d string, k, dy float64) (string, error) {
	arity := map[byte]int{'M': 2, 'L': 2, 'T': 2, 'H': 1, 'V': 1, 'C': 6, 'S': 4, 'Q': 4}
	tokens := reToken.FindAllString(d, -1)
	num := func(v float64) string {
		return strconv.FormatFloat(math.Round(v*1000)/1000, 'f', -1, 64)
	}
	var b strings.Builder
	var cmd byte
	lettered, written := false, false
	for i := 0; i < len(tokens); {
		if isCommand(tokens[i]) {
			cmd = tokens[i][0]
			written = cmd >= 'a'
			// The first move of a path is from the origin, so its point is
			// a point in the box however it is written.
			if i == 0 && cmd == 'm' {
				cmd = 'M'
			}
			b.WriteByte(cmd)
			lettered = true
			i++
			if cmd == 'Z' || cmd == 'z' {
				continue
			}
		}
		upper := cmd &^ 0x20
		n, known := arity[upper]
		if !known || i+n > len(tokens) {
			return "", fmt.Errorf("cannot rescale %q", string(cmd))
		}
		relative := cmd != upper
		for a := 0; a < n; a++ {
			v, err := strconv.ParseFloat(tokens[i+a], 64)
			if err != nil {
				return "", err
			}
			v *= k
			if !relative && (upper == 'V' || (upper != 'H' && a%2 == 1)) {
				v += dy
			}
			if !lettered || (a > 0 && v >= 0) {
				b.WriteByte(' ')
			}
			lettered = false
			b.WriteString(num(v))
		}
		i += n
		// Pairs after a move are lines, relative after a relative move. Said
		// with a letter, because the first move may have changed case.
		if upper == 'M' && i < len(tokens) && !isCommand(tokens[i]) {
			cmd = 'L'
			if written {
				cmd = 'l'
			}
			b.WriteByte(cmd)
			lettered = true
		}
	}
	return b.String(), nil
}

func isCommand(t string) bool {
	c := t[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func main() {
	type job struct{ name, style, url string }
	var jobs []job
	for _, n := range names {
		for _, s := range styles {
			jobs = append(jobs, job{n, s.key, "https://raw.githubusercontent.com/google/material-design-icons/master/symbols/web/" +
				n + "/" + s.dir + "/" + n + s.suffix})
		}
	}
	out := map[string]map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	client := &http.Client{Timeout: 30 * time.Second}
	failed := false
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := client.Get(j.url)
			if err != nil || res.StatusCode != 200 {
				mu.Lock()
				status := 0
				if res != nil {
					status = res.StatusCode
				}
				fmt.Fprintf(os.Stderr, "%s %s: %v (status %d)\n", j.name, j.style, err, status)
				failed = true
				mu.Unlock()
				return
			}
			defer res.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
			m := rePath.FindSubmatch(b)
			// Only path data: numbers and commands. Anything else is not
			// an icon this program will put on a page.
			if m == nil || !reSafe.Match(m[1]) {
				mu.Lock()
				fmt.Fprintf(os.Stderr, "%s %s: no usable path\n", j.name, j.style)
				failed = true
				mu.Unlock()
				return
			}
			d, err := inTheBox(b, string(m[1]))
			if err != nil {
				mu.Lock()
				fmt.Fprintf(os.Stderr, "%s %s: %v\n", j.name, j.style, err)
				failed = true
				mu.Unlock()
				return
			}
			mu.Lock()
			if out[j.name] == nil {
				out[j.name] = map[string]string{}
			}
			out[j.name][j.style] = d
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	if failed {
		os.Exit(1)
	}
	var b strings.Builder
	b.WriteString("// SPDX-FileCopyrightText: 2026 Rashik Adhikari\n")
	b.WriteString("// SPDX-FileCopyrightText: Google LLC\n")
	b.WriteString("// SPDX-License-Identifier: Apache-2.0\n\n")
	b.WriteString("// Code generated by scripts/genicons. DO NOT EDIT.\n\n")
	b.WriteString("// Material Symbols, by Google, under the Apache License 2.0\n")
	b.WriteString("// (internal/admin/assets/icons/LICENSE). Only each SVG's path is kept.\n\n")
	b.WriteString("package icons\n\nvar paths = map[string]map[string]string{\n")
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "\t%q: {\n", k)
		for _, s := range styles {
			fmt.Fprintf(&b, "\t\t%q: %q,\n", s.key, out[k][s.key])
		}
		b.WriteString("\t},\n")
	}
	b.WriteString("}\n")
	src, err := format.Source([]byte(b.String()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(src)
}
