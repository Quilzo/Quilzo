// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package posture

import (
	"testing"
	"time"
)

func TestTheAgentInterfaceChecks(t *testing.T) {
	base := func() State {
		return State{Now: time.Now(), Interface: InterfaceFacts{Checked: true, On: true, Hosts: []string{"claude.ai"}}}
	}
	if f := has(Scan(base(), nil), "mcp.any-app"); f != nil {
		t.Fatal("named hosts flagged")
	}
	s := base()
	s.Interface.Hosts = append(s.Interface.Hosts, "*")
	if f := has(Scan(s, nil), "mcp.any-app"); f == nil {
		t.Fatal("any host not flagged")
	}
	s.Interface.On = false
	if f := has(Scan(s, nil), "mcp.any-app"); f != nil {
		t.Fatal("flagged while the interface is off")
	}
	s = base()
	if f := has(Scan(s, nil), "mcp.admin-app"); f != nil {
		t.Fatal("no admin connection, yet flagged")
	}
	s.Interface.Admin = []string{"gr_1 (Assistant for dana)"}
	if f := has(Scan(s, nil), "mcp.admin-app"); f == nil || f.Resource != "mcp/gr_1 (Assistant for dana)" {
		t.Fatalf("admin connection not flagged: %+v", f)
	}
}
