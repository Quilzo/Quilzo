// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package api

import "testing"

// Zero means the compile-time default, which is what an embedded use and
// every test wants.
func TestUnsetLimitsFallBackToTheConstants(t *testing.T) {
	var s Server
	if got := s.pageMax(); got != MaxPageSize {
		t.Errorf("page max is %d, wanted %d", got, MaxPageSize)
	}
	if got := s.bodyMax(); got != MaxBodyBytes {
		t.Errorf("body max is %d, wanted %d", got, MaxBodyBytes)
	}
}

// And a configured value is used. api.page.max and api.body.max_bytes were in
// the settings table and nothing read them, so the API always used the
// constants — and the table advertised a body default of 1 MiB while the code
// enforced 2 MiB.
func TestConfiguredLimitsAreUsed(t *testing.T) {
	s := Server{MaxPage: 10, MaxBody: 1024}
	if got := s.pageMax(); got != 10 {
		t.Errorf("page max is %d", got)
	}
	if got := s.bodyMax(); got != 1024 {
		t.Errorf("body max is %d", got)
	}
}

// A limit above a request is not a refusal, and a limit below the default page
// size is an operator asking for small pages rather than a contradiction.
func TestPagingRespectsTheConfiguredMaximum(t *testing.T) {
	_, limit, err := parsePaging(map[string][]string{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if limit != 5 {
		t.Errorf("a default of %d against a maximum of 5", limit)
	}

	if _, _, err := parsePaging(map[string][]string{"limit": {"6"}}, 5); err == nil {
		t.Error("6 was accepted against a maximum of 5")
	}
	if _, _, err := parsePaging(map[string][]string{"limit": {"5"}}, 5); err != nil {
		t.Errorf("5 was refused against a maximum of 5: %v", err)
	}
	// And zero means the shipped constant, not "refuse everything".
	if _, limit, err := parsePaging(map[string][]string{"limit": {"50"}}, 0); err != nil {
		t.Errorf("50 refused with no configured maximum: %v", err)
	} else if limit != 50 {
		t.Errorf("limit came back as %d", limit)
	}
}
