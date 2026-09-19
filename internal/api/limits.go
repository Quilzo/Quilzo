// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package api

// The two limits an operator can set, which they could not.
//
// api.page.max and api.body.max_bytes were in the settings table with
// summaries, rationales and a Weaker rule that asks for a written reason
// before either is loosened — and nothing read them. The API used the
// compile-time constants below and always had.
//
// The body one was worse than dead. The table advertised a default of
// 1,048,576 bytes and the code enforced 2,097,152, so an operator reading the
// documentation believed in a limit half the size of the real one, and one who
// set it tighter got no change at all.
//
// So the constants stay as the defaults — a zero field means "whatever this
// build ships", which is what every test and every embedded use wants — and a
// host that has configuration overrides them.

// pageMax is the largest page size this server will answer.
func (s *Server) pageMax() int {
	if s.MaxPage > 0 {
		return s.MaxPage
	}
	return MaxPageSize
}

// bodyMax is the largest request body this server will read.
func (s *Server) bodyMax() int {
	if s.MaxBody > 0 {
		return s.MaxBody
	}
	return MaxBodyBytes
}
