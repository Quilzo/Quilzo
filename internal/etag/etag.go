// Package etag compares entity tags the way HTTP says to.
//
// # Why this is not a string comparison
//
// An If-None-Match header is a list, not a value. RFC 9110 §13.1.2 defines it
// as one or more entity tags separated by commas, or the single token `*`, and
// any of them matching is a match. A client that holds two representations of
// a URL — which is what a browser has the moment a response is served both
// compressed and not — sends both validators, and a server comparing the whole
// header against one tag finds they are not equal and sends the body again.
//
// That failure is invisible from the server's side. Nothing errors; the cache
// simply never hits, and the only symptom is bandwidth. This program had it in
// three places, each written as `if match == etag`, while a correct comparison
// already existed in internal/api. One copy, used everywhere, is the fix.
//
// Weak tags compare equal here. A weak validator is defined as sufficient for
// caching decisions and insufficient only for range requests and updates, and
// this program emits strong tags exclusively — so a `W/` prefix arriving means
// something in the path weakened it in transit, and refusing it would punish
// the client for a proxy's transformation.
package etag

import "strings"

// Matches reports whether an If-None-Match or If-Match header covers tag.
//
// Quoting is normalised on both sides, because a tag reaches this function
// from two directions: a header, where the quotes are the syntax, and a
// content hash the caller may not have quoted yet.
func Matches(header, tag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	// `*` means "any current representation", so it matches whatever this URL
	// has — including, for If-None-Match, the answer that it has one.
	if header == "*" {
		return true
	}
	tag = unquote(tag)
	if tag == "" {
		// No tag to match. Returning true here would answer 304 to a
		// conditional request for a resource with no validator at all.
		return false
	}
	for _, part := range strings.Split(header, ",") {
		if unquote(part) == tag {
			return true
		}
	}
	return false
}

// unquote reduces an entity tag to its opaque part.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "W/")
	return strings.Trim(s, `"`)
}
