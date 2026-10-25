// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every audit record the admin writes names who acted.
//
// The record is written with detail["by"] as its principal, and the log
// refuses a record with none (AU-3): publishing from the browser, a note,
// a media edit and a token exchange were each written without one, so the
// log kept none of them while the code read as though it did. A record
// with nobody signed in is a refusal at the door, and is listed here by
// name; anything else has to say who.
func TestEveryAdminRecordNamesWhoActed(t *testing.T) {
	atTheDoor := map[string]bool{"enrol.refused": true, "signin.saml.refused": true,
		"account.locked": true, "account.disabled": true}
	call := regexp.MustCompile(`s\.audit\(`)
	files, _ := filepath.Glob("*.go")
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, m := range call.FindAllStringIndex(src, -1) {
			depth, end := 1, m[1]
			for depth > 0 && end < len(src) {
				switch src[end] {
				case '(':
					depth++
				case ')':
					depth--
				}
				end++
			}
			args := src[m[1] : end-1]
			checked++
			if strings.Contains(args, `"by"`) {
				continue
			}
			action := ""
			if q := regexp.MustCompile(`^"([^"]+)"`).FindStringSubmatch(strings.TrimSpace(args)); q != nil {
				action = q[1]
			}
			if atTheDoor[action] {
				continue
			}
			// A detail built beforehand is checked where it is built.
			fn := src[strings.LastIndex(src[:m[0]], "\nfunc "):m[0]]
			if regexp.MustCompile(`(detail|d)\s*(:=\s*map\[string\]string\{[^}]*"by"|\["by"\]\s*(,[^=]*)?=)`).MatchString(fn) ||
				regexp.MustCompile(`detail\["by"\],`).MatchString(fn+args) {
				continue
			}
			line := strings.Count(src[:m[0]], "\n") + 1
			t.Errorf("%s:%d writes %q without saying who acted; the log refuses it", f, line, action)
		}
	}
	if checked < 50 {
		t.Fatalf("only %d records found; the scan has stopped finding them", checked)
	}
}
