// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package inbound

import (
	"fmt"
	"strings"
)

// What some Okta events mean for the rules here, as signals.
//
// Every Okta event goes to the event store and the detections. These few
// also say something a rule should be able to act on the moment it happens,
// under the same names shared signals use, so one rule covers a session
// ended in Okta whether Okta said so by event hook or by shared signal.
//
// The names are Okta's System Log event types. user.risk.change was renamed
// user.risk.detect in 2024.09; both are read.
var oktaSignals = map[string]struct{ typ, change string }{
	"user.session.clear":                                 {"session-revoked", ""},
	"user.session.universal_logout":                      {"session-revoked", ""},
	"user.authentication.universal_logout":               {"session-revoked", ""},
	"user.lifecycle.suspend":                             {"account-disabled", ""},
	"user.lifecycle.deactivate":                          {"account-disabled", ""},
	"user.lifecycle.unsuspend":                           {"account-enabled", ""},
	"user.lifecycle.reactivate":                          {"account-enabled", ""},
	"user.lifecycle.activate":                            {"account-enabled", ""},
	"user.lifecycle.delete.initiated":                    {"account-purged", ""},
	"user.account.report_suspicious_activity_by_enduser": {"reported", ""},
	"security.threat.detected":                           {"threat", ""},
	"user.risk.detect":                                   {"risk-level-change", ""},
	"user.risk.change":                                   {"risk-level-change", ""},
	"user.session.context.change":                        {"session-moved", ""},
	"user.account.reset_password":                        {"credential-change", "update"},
	"user.account.update_password":                       {"credential-change", "update"},
	"user.mfa.factor.reset_all":                          {"credential-change", "revoke"},
	"user.mfa.factor.deactivate":                         {"credential-change", "revoke"},
	"user.mfa.factor.activate":                           {"credential-change", "create"},
}

// OktaSignal is the signal an Okta event carries, if it carries one: its
// type, the person it is about (by the address Okta knows them by), and
// fields for the rules.
func OktaSignal(ev map[string]any) (typ, person string, fields map[string]string, ok bool) {
	et, _ := ev["eventType"].(string)
	m, found := oktaSignals[et]
	if !found {
		return "", "", nil, false
	}
	// A failed attempt to do one of these is not the thing done.
	if outcome, _ := ev["outcome"].(map[string]any); outcome != nil {
		if r, _ := outcome["result"].(string); r != "" && r != "SUCCESS" && r != "ALLOW" {
			return "", "", nil, false
		}
	}
	fields = map[string]string{"okta_event": et}
	if m.change != "" {
		fields["change_type"] = m.change
	}
	// Who it is about: the user it was done to, else the user who did it.
	person = userOf(ev["target"])
	if person == "" {
		if a, _ := ev["actor"].(map[string]any); a != nil && strings.EqualFold(fmt.Sprint(a["type"]), "User") {
			person, _ = a["alternateId"].(string)
		}
	}
	person = strings.ToLower(strings.TrimSpace(person))
	if person == "" || len(person) > 254 {
		return "", "", nil, false
	}
	if m.typ == "risk-level-change" {
		if lvl := riskLevel(ev); lvl != "" {
			fields["current_level"] = lvl
		}
	}
	if m.typ == "threat" {
		fields["current_level"] = "high"
	}
	return m.typ, person, fields, true
}

func userOf(target any) string {
	list, _ := target.([]any)
	for _, t := range list {
		m, _ := t.(map[string]any)
		if m == nil || !strings.EqualFold(fmt.Sprint(m["type"]), "User") {
			continue
		}
		if id, _ := m["alternateId"].(string); strings.Contains(id, "@") {
			return id
		}
	}
	return ""
}

// riskLevel finds the level an Okta risk event reports, wherever in the
// debug data Okta put it: the field names have moved between releases, the
// words have not.
func riskLevel(ev map[string]any) string {
	dc, _ := ev["debugContext"].(map[string]any)
	dd, _ := dc["debugData"].(map[string]any)
	best := ""
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	for k, v := range dd {
		lk := strings.ToLower(k)
		if !strings.Contains(lk, "risk") || strings.Contains(lk, "previous") {
			continue
		}
		s := strings.ToLower(fmt.Sprint(v))
		for _, w := range []string{"high", "medium", "low"} {
			if strings.Contains(s, w) && rank[w] > rank[best] {
				best = w
			}
		}
	}
	return best
}

// OktaSeverity weighs an Okta signal as shared signals are weighed.
func OktaSeverity(typ string, fields map[string]string) string {
	switch typ {
	case "threat", "reported":
		return "high"
	case "risk-level-change":
		switch fields["current_level"] {
		case "high":
			return "high"
		case "medium":
			return "medium"
		}
		return "low"
	case "session-revoked", "account-disabled", "account-purged", "credential-change", "session-moved":
		return "medium"
	}
	return "low"
}
