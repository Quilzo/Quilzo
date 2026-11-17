// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package asciifold

import "unicode"

// Spell is how a letter outside ASCII is written in ASCII letters, lower
// case, for a page link made from words: ü is u, ß is ss, ł is l, Greek σ is
// s and χ ch, Cyrillic ж zh. ok is false for anything this has no spelling
// for, which a link-maker treats as it treats punctuation. A combining mark
// (the dot İ lowers to) and the Cyrillic hard and soft signs are spelled as
// nothing, with ok true, so they join the letters beside them rather than
// break a word.
//
// This is a different question from the rest of this package, which
// matches ASCII and nothing else. It is here because it is the other half of
// folding text to ASCII, and both slug rules (sheet.Slug and export.Slug)
// need the one answer.
//
// Every letter outside ASCII was a break between words or nothing at all, so
// a Turkish shop's Ürünler was /r-nler, Café was /caf, and a Greek or Russian
// title left no address and was refused as if none had been given. The
// spellings are the plain ones a reader of the language recognises: Latin
// letters lose their marks, Greek follows ELOT 743 and Cyrillic the
// passport romanisation, without the marks either adds. A script with no
// such spelling here (Arabic, Hebrew, the scripts of India and East Asia)
// has none, and a caller names the page another way.
func Spell(r rune) (spelled string, ok bool) {
	if r < 0x80 {
		return "", false
	}
	if unicode.Is(unicode.Mn, r) {
		return "", true
	}
	lower := unicode.ToLower(r)
	if lower < 0x80 && unicode.IsLetter(lower) {
		// İ, whose lower case is the ASCII i, and the Kelvin sign, k.
		return string(lower), true
	}
	s, ok := spellings[lower]
	return s, ok
}

// spellings is every letter Spell knows, by its lower case.
var spellings = func() map[rune]string {
	m := map[rune]string{
		// Latin letters spelled with more than one.
		'æ': "ae", 'œ': "oe", 'ß': "ss", 'þ': "th", 'ĳ': "ij", 'ŋ': "ng",

		// Greek, ELOT 743 without its marks.
		'α': "a", 'β': "v", 'γ': "g", 'δ': "d", 'ε': "e", 'ζ': "z", 'η': "i",
		'θ': "th", 'ι': "i", 'κ': "k", 'λ': "l", 'μ': "m", 'ν': "n", 'ξ': "x",
		'ο': "o", 'π': "p", 'ρ': "r", 'σ': "s", 'ς': "s", 'τ': "t", 'υ': "y",
		'φ': "f", 'χ': "ch", 'ψ': "ps", 'ω': "o",
		'ά': "a", 'έ': "e", 'ή': "i", 'ί': "i", 'ϊ': "i", 'ΐ': "i", 'ό': "o",
		'ύ': "y", 'ϋ': "y", 'ΰ': "y", 'ώ': "o",

		// Cyrillic: Russian, Ukrainian, Belarusian, Serbian and Macedonian.
		// The hard and soft signs mark how the letter before them is said,
		// and are spelled as nothing: объявление is obiavlenie.
		'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e",
		'ж': "zh", 'з': "z", 'и': "i", 'й': "i", 'к': "k", 'л': "l", 'м': "m",
		'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
		'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch",
		'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "iu", 'я': "ia",
		'є': "ie", 'і': "i", 'ї': "i", 'ґ': "g", 'ў': "u",
		'ђ': "dj", 'ј': "j", 'љ': "lj", 'њ': "nj", 'ћ': "c", 'џ': "dz",
		'ѓ': "g", 'ќ': "k", 'ѕ': "dz",
	}
	// Latin letters that lose a mark: Latin-1 and Latin Extended-A, and the
	// comma-below letters of Romanian.
	for spelled, letters := range map[string]string{
		"a": "àáâãäåāăą", "c": "çćĉċč", "d": "ďđð", "e": "èéêëēĕėęě",
		"g": "ĝğġģ", "h": "ĥħ", "i": "ìíîïĩīĭįı", "j": "ĵ", "k": "ķĸ",
		"l": "ĺļľŀł", "n": "ñńņňŉ", "o": "òóôõöøōŏő", "r": "ŕŗř",
		"s": "śŝşšșſ", "t": "ţťŧț", "u": "ùúûüũūŭůűų", "w": "ŵ",
		"y": "ýÿŷ", "z": "źżž",
	} {
		for _, r := range letters {
			m[r] = spelled
		}
	}
	return m
}()
