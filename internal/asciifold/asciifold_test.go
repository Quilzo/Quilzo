// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package asciifold

import (
	"strings"
	"testing"
)

// The offsets are the text's own, whatever the text around a match lowers
// to, and they are the same offsets strings.ToLower gave wherever it gave
// the text's own.
func TestTheOffsetIsIntoTheTextItself(t *testing.T) {
	for _, c := range []struct {
		s, sub      string
		first, last int
	}{
		{"<title>İstanbul</title></HEAD>", "</head>", 24, 24},
		{"300 \u212A</head>", "</head>", 7, 7},
		{"\u023A\u023A</Head>", "</head>", 4, 4},
		{"caf\xe9</HEAD>", "</head>", 4, 4},
		{"<BODY>a</body><body>", "<body", 0, 14},
		{"no tag here", "</head>", -1, -1},
		{"", "</head>", -1, -1},
		{"abc", "", 0, 3},
		{"short", "longer than s", -1, -1},
		// Only ASCII letters fold. İ lowers to i and the Kelvin sign to k in
		// strings.ToLower, and neither is the letter in HTML's eyes.
		{"<İmg src=x>", "<img", -1, -1},
		{"<lin\u212A rel=x>", "<link", -1, -1},
		{"HREF=x href=y", "href=", 0, 7},
		{"aaa", "aa", 0, 1},
	} {
		if got := Index(c.s, c.sub); got != c.first {
			t.Errorf("Index(%q, %q) = %d, want %d", c.s, c.sub, got, c.first)
		}
		if got := LastIndex(c.s, c.sub); got != c.last {
			t.Errorf("LastIndex(%q, %q) = %d, want %d", c.s, c.sub, got, c.last)
		}
	}
	for _, c := range []struct {
		s, prefix string
		want      bool
	}{
		{"DOI:10.1/x", "doi:", true},
		{"doİ:10.1/x", "doi:", false},
		{"do", "doi:", false},
		{"https://Doi.org/x", "https://doi.org/", true},
	} {
		if got := HasPrefix(c.s, c.prefix); got != c.want {
			t.Errorf("HasPrefix(%q, %q) = %v", c.s, c.prefix, got)
		}
	}
}

// Nothing is copied, which is half of why this exists: the old searches
// lowered the whole page, every time.
func TestSearchingAllocatesNothing(t *testing.T) {
	page := strings.Repeat("<p>İstanbul — £5 ©</p>\n", 2000) + "</HEAD></body>"
	if n := testing.AllocsPerRun(10, func() {
		Index(page, "</head>")
		LastIndex(page, "<P>")
		HasPrefix(page, "<p>")
	}); n != 0 {
		t.Errorf("%v allocations a search", n)
	}
}

// naiveIndex is the definition, written the slow way: every offset, every
// byte, A to Z folded and nothing else.
func naiveIndex(s, sub string, last bool) int {
	at := -1
	for i := 0; i+len(sub) <= len(s); i++ {
		if asciiLower(s[i:i+len(sub)]) == asciiLower(sub) {
			if !last {
				return i
			}
			at = i
		}
	}
	return at
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Every offset returned is a real match in the text given, and the first or
// the last one there is; on ASCII, where strings.ToLower changes no lengths,
// the answer is the one the searches it replaced gave.
func FuzzIndexFoldReturnsOnlyRealMatches(f *testing.F) {
	for _, seed := range [][2]string{
		{"<title>İstanbul, İzmir</title></head>", "</head>"},
		{"300 \u212A <Body class=x>", "<body"},
		{"\u023A\u023A\u023A</BODY>", "</body>"},
		{"caf\xe9 </form>", "</form"},
		{"<FORM action=/search>", "<form"},
		{"aAaA", "aa"},
		{"", ""},
		{"x", ""},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, s, sub string) {
		first, last := Index(s, sub), LastIndex(s, sub)
		for _, at := range []int{first, last} {
			if at >= 0 && (at+len(sub) > len(s) || asciiLower(s[at:at+len(sub)]) != asciiLower(sub)) {
				t.Fatalf("%d is not a match of %q in %q", at, sub, s)
			}
		}
		if want := naiveIndex(s, sub, false); first != want {
			t.Fatalf("Index(%q, %q) = %d, the first match is at %d", s, sub, first, want)
		}
		if want := naiveIndex(s, sub, true); sub != "" && last != want {
			t.Fatalf("LastIndex(%q, %q) = %d, the last match is at %d", s, sub, last, want)
		}
		if sub == "" && last != len(s) {
			t.Fatalf("LastIndex(%q, \"\") = %d, as strings.LastIndex it is %d", s, last, len(s))
		}
		if HasPrefix(s, sub) != (first == 0) {
			t.Fatalf("HasPrefix(%q, %q) disagrees with Index's %d", s, sub, first)
		}
		if isASCII(s) && isASCII(sub) {
			if old := strings.Index(strings.ToLower(s), strings.ToLower(sub)); first != old {
				t.Fatalf("on ASCII Index(%q, %q) = %d, where the old search gave %d", s, sub, first, old)
			}
			if old := strings.LastIndex(strings.ToLower(s), strings.ToLower(sub)); last != old {
				t.Fatalf("on ASCII LastIndex(%q, %q) = %d, where the old search gave %d", s, sub, last, old)
			}
		}
	})
}
