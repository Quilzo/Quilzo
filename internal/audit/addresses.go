// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import "strings"

// WithoutCredentials is s with every address in it written without the
// credentials an address can carry: a user and password become "…@", a
// query "?…" and a fragment "#…". The scheme, the host and the path stay,
// so the record still says where.
//
// Done here, where every record is written, rather than by each writer. The
// guard on the names of details (ForbiddenKey) never looked at values, so an
// address went into the log as it was given: a staging site's password in
// `quilzo config set site.base_url`, the key in the address an agent's card
// was registered by, a ?token= in every error that quoted the address it
// could not reach. The auditor reads the log and should learn nothing they
// could post or sign in with, and every copy of it forwarded to a SIEM is as
// good as the log. A writer that remembers is one writer; the log is all of
// them, on every surface.
//
// A secret that is the path itself, as in a Slack, Teams or Discord
// incoming-webhook address, looks like any other path and is the writer's
// to leave out: internal/webhook's LogForm is how an endpoint is written.
//
// Exported for whatever compares a value with the record of it, as
// internal/engagement compares evidence with its entry: the value as the
// log wrote it is this.
func WithoutCredentials(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, "://")
		if i < 0 {
			break
		}
		start := i
		for start > 0 && schemeByte(rest[start-1]) {
			start--
		}
		end := i + len("://")
		for end < len(rest) && !endsAddress(rest[end]) {
			end++
		}
		b.WriteString(rest[:start])
		b.WriteString(addressWithoutCredentials(rest[start:end], i-start))
		rest = rest[end:]
	}
	b.WriteString(rest)
	return b.String()
}

// addressWithoutCredentials is one address, whose "://" is at sep.
func addressWithoutCredentials(a string, sep int) string {
	head, tail := a[:sep+len("://")], a[sep+len("://"):]
	host := tail
	if i := strings.IndexAny(tail, "/?#"); i >= 0 {
		host, tail = tail[:i], tail[i:]
	} else {
		tail = ""
	}
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = "…" + host[at:]
	}
	if i := strings.IndexAny(tail, "?#"); i >= 0 && i+1 < len(tail) {
		tail = tail[:i+1] + "…"
	}
	return head + host + tail
}

// schemeByte is a byte a URL scheme can be made of (RFC 3986, 3.1).
func schemeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '+' || c == '-' || c == '.'
}

// endsAddress is a byte no address written in a sentence goes on past:
// space and control characters, quotes and angle brackets.
func endsAddress(c byte) bool {
	return c <= ' ' || c == 0x7f || c == '"' || c == '\'' || c == '`' || c == '<' || c == '>'
}

// detailWithoutCredentials is d with WithoutCredentials applied to every
// value, leaving the caller's map alone.
func detailWithoutCredentials(d map[string]string) map[string]string {
	var out map[string]string
	for k, v := range d {
		clean := WithoutCredentials(v)
		if clean == v {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(d))
			for k2, v2 := range d {
				out[k2] = v2
			}
		}
		out[k] = clean
	}
	if out == nil {
		return d
	}
	return out
}
