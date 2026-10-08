// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"fmt"
	"strings"
	"time"
)

// Sample is a made-up company's tools, for trying the workforce screens
// before connecting real ones: Northwind Labs, twenty-four people and their
// machines, as KnowBe4, Vanta, ManageEngine Endpoint Central and MDM Plus
// and Microsoft Entra would report them.
//
// It is written as the tools' own snapshots, marked as samples, and goes
// through exactly the join, the checks, the risk score and the compliance
// a real read does — so what it shows is what the program does, not a
// picture of it. Every screen that shows it says it is sample data.
//
// It is built to have something in every column: operating systems
// current, behind, ending and unsupported; tools that disagree; a leaver
// with a laptop; a rooted phone; people who clicked and one who typed a
// password in.
type SampleTool struct {
	Source string
	// Endpoints are the endpoint names and what each produces.
	Endpoints map[string]Kind
	Lines     []map[string]string
}

type samplePerson struct {
	first, last, dept, title string
	phish                    float64
	training                 string // KnowBe4 enrolment status
	policies                 string // Vanta task status
	gone                     bool
	clicked, entered, report bool
}

var samplePeople = []samplePerson{
	{"Ada", "Okafor", "Engineering", "Staff engineer", 4.2, "Passed", "complete", false, false, false, true},
	{"Bo", "Lindqvist", "Sales", "Account executive", 38.5, "Past Due", "overdue", false, true, true, false},
	{"Chen", "Wei", "Engineering", "Platform lead", 8.0, "Passed", "complete", false, false, false, true},
	{"Dana", "Reyes", "Finance", "Controller", 22.4, "Passed", "complete", false, true, false, false},
	{"Eli", "Haddad", "Support", "Support specialist", 31.0, "Not Started", "due_soon", false, true, false, false},
	{"Farah", "Nasser", "People", "People partner", 12.5, "Passed", "complete", false, false, false, true},
	{"Gus", "Moreau", "Sales", "Sales manager", 27.0, "In Progress", "overdue", false, true, false, false},
	{"Hana", "Sato", "Design", "Product designer", 6.0, "Passed", "complete", false, false, false, false},
	{"Ivo", "Petrov", "Engineering", "Engineer", 15.0, "Passed", "complete", true, false, false, false},
	{"Jade", "Mensah", "Finance", "Analyst", 41.0, "Past Due", "overdue", false, true, true, false},
	{"Kai", "Tanaka", "Engineering", "Engineer", 9.5, "Passed", "complete", false, false, false, true},
	{"Lena", "Fischer", "Support", "Support lead", 18.0, "Passed", "due_soon", false, false, false, false},
	{"Milo", "Rossi", "Sales", "Sales development", 35.0, "Not Started", "overdue", false, true, false, false},
	{"Nia", "Adeyemi", "Engineering", "Security engineer", 2.5, "Passed", "complete", false, false, false, true},
	{"Omar", "Farouk", "Design", "Designer", 11.0, "Passed", "complete", false, false, false, false},
	{"Pia", "Larsen", "People", "Recruiter", 24.0, "In Progress", "due_soon", false, true, false, false},
	{"Quinn", "Byrne", "Engineering", "Engineer", 7.0, "Passed", "complete", false, false, false, false},
	{"Rosa", "Silva", "Finance", "Payroll", 29.0, "Past Due", "overdue", false, false, false, false},
	{"Sam", "Kowalski", "Support", "Support specialist", 19.5, "Passed", "complete", true, false, false, false},
	{"Tara", "Singh", "Sales", "Account executive", 33.0, "Passed", "complete", false, true, false, false},
	{"Uma", "Kapoor", "Engineering", "Engineering manager", 5.0, "Passed", "complete", false, false, false, true},
	{"Vik", "Bose", "Design", "Design lead", 14.0, "Passed", "complete", false, false, false, false},
	{"Wren", "Doyle", "People", "Head of people", 10.0, "Passed", "complete", false, false, false, false},
	{"Xavi", "Ortega", "Sales", "VP sales", 26.5, "Passed", "due_soon", false, true, false, false},
}

type sampleMachine struct {
	owner      int // index into samplePeople, -1 for nobody
	name, os   string
	version    string
	serial     string
	tool       string // the tool that manages it
	quietDays  int
	encrypted  string
	lock       string
	av         string
	pwm        string
	patches    int
	prohibited int
	rooted     string
	passcode   string
	alsoVanta  string // a second tool's encryption reading, to disagree
	noMDM      bool   // known to Vanta only: unmanaged
}

var sampleMachines = []sampleMachine{
	{0, "ADA-MBP", "macOS", "26.7.1", "C02ZK1ADA", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{1, "BO-LAPTOP", "Windows 11 Pro", "10.0.22631.4317", "PF3BO0221", "endpointcentral", 1, "true", "true", "true", "false", 6, 1, "", "", "", false},
	{2, "CHEN-MBP", "macOS", "26.7.1", "C02ZK2CHN", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{3, "DANA-LAPTOP", "Windows 11 Enterprise", "10.0.22631.3880", "PF3DA0412", "endpointcentral", 2, "true", "true", "true", "true", 2, 0, "", "", "", false},
	{4, "ELI-LAPTOP", "Windows 10 Pro", "10.0.19045.4529", "PF3EL0118", "endpointcentral", 3, "false", "true", "true", "false", 14, 0, "", "", "", false},
	{5, "FARAH-MBA", "macOS", "15.6", "C02ZK5FRH", "endpointcentral", 1, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{6, "GUS-MBP", "macOS", "13.6.1", "C02ZK6GUS", "endpointcentral", 4, "true", "false", "true", "false", 9, 0, "", "", "", false},
	{7, "HANA-MBP", "macOS", "26.7.1", "C02ZK7HAN", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{8, "IVO-LAPTOP", "Windows 11 Pro", "10.0.26200.100", "PF3IV0907", "endpointcentral", 2, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{9, "JADE-LAPTOP", "Windows 11 Pro", "10.0.26100.2033", "PF3JA0303", "endpointcentral", 1, "true", "true", "false", "false", 4, 2, "", "", "", false},
	{10, "KAI-MBP", "macOS", "14.8.9", "C02ZKAKAI", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{11, "LENA-LAPTOP", "Windows 11 Pro", "10.0.26200.100", "PF3LE0505", "endpointcentral", 41, "true", "true", "true", "true", 3, 0, "", "", "", false},
	{12, "MILO-LAPTOP", "Windows 11 Pro", "10.0.26100.2033", "PF3MI0606", "endpointcentral", 1, "false", "false", "true", "false", 5, 0, "", "", "true", false},
	{13, "NIA-MBP", "macOS", "26.7.1", "C02ZKDNIA", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{14, "OMAR-MBA", "macOS", "15.6", "C02ZKEOMR", "endpointcentral", 2, "true", "true", "true", "false", 0, 0, "", "", "", false},
	{15, "PIA-LAPTOP", "Windows 11 Pro", "10.0.26200.100", "PF3PI0808", "endpointcentral", 1, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{16, "QUINN-MBP", "macOS", "26.7.1", "C02ZKGQUI", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{17, "ROSA-LAPTOP", "Windows 10 Pro", "10.0.19045.4529", "PF3RO1010", "endpointcentral", 6, "true", "true", "true", "false", 11, 0, "", "", "", false},
	{18, "SAM-LAPTOP", "Windows 11 Pro", "10.0.26100.2033", "PF3SA1111", "endpointcentral", 3, "true", "true", "true", "true", 2, 0, "", "", "", false},
	{20, "UMA-MBP", "macOS", "26.7.1", "C02ZKKUMA", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{21, "VIK-MBP", "macOS", "15.6", "C02ZKLVIK", "endpointcentral", 1, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{22, "WREN-MBA", "macOS", "26.7.1", "C02ZKMWRN", "endpointcentral", 0, "true", "true", "true", "true", 0, 0, "", "", "", false},
	{23, "XAVI-MBP", "macOS", "26.7.1", "C02ZKNXAV", "endpointcentral", 1, "true", "true", "true", "false", 0, 0, "", "", "", false},
	{-1, "MAC-SPARE", "macOS", "15.6", "C02ZKPSPR", "", 3, "false", "", "", "", 0, 0, "", "", "", true},
	// Phones, from MDM Plus.
	{0, "Ada's iPhone", "iOS", "26.7.1", "F2LADAIPH", "mdmplus", 0, "true", "", "", "", 0, 0, "false", "true", "", false},
	{1, "Bo's iPhone", "iOS", "17.5", "F2LBOIPHN", "mdmplus", 2, "true", "", "", "", 0, 0, "false", "true", "", false},
	{6, "Gus's Pixel", "Android", "16", "R5CGUSPXL", "mdmplus", 1, "true", "", "", "", 0, 0, "false", "true", "", false},
	{9, "Jade's Galaxy", "Android", "12", "R5CJADEGX", "mdmplus", 3, "true", "", "", "", 0, 0, "false", "false", "", false},
	{12, "Milo's Galaxy", "Android", "14", "R5CMILOGX", "mdmplus", 1, "true", "", "", "", 0, 0, "true", "true", "", false},
	{19, "Tara's iPhone", "iOS", "18.7.10", "F2LTARIPH", "mdmplus", 0, "true", "", "", "", 0, 0, "false", "true", "", false},
	{23, "Xavi's iPad", "iPadOS", "18.7.10", "F2LXAVIPD", "mdmplus", 5, "true", "", "", "", 0, 0, "false", "true", "", false},
}

func sampleEmail(p samplePerson) string {
	return strings.ToLower(p.first+"."+p.last) + "@northwind.example"
}

// Sample builds the tools' snapshots as of now.
func Sample(now time.Time) []SampleTool {
	stamp := func(daysAgo int) string {
		return now.Add(-time.Duration(daysAgo)*24*time.Hour - 3*time.Hour).Format(time.RFC3339)
	}
	entra := SampleTool{Source: "entra", Endpoints: map[string]Kind{"users": KindPerson}}
	kb4 := SampleTool{Source: "knowbe4", Endpoints: map[string]Kind{"users": KindPerson, "enrollments": KindTraining, "phishing": KindPhishing}}
	vanta := SampleTool{Source: "vanta", Endpoints: map[string]Kind{"people": KindPerson, "computers": KindDevice, "tests": KindControl}}
	ec := SampleTool{Source: "endpointcentral", Endpoints: map[string]Kind{"computers": KindDevice}}
	mdm := SampleTool{Source: "mdmplus", Endpoints: map[string]Kind{"devices": KindDevice}}

	for i, p := range samplePeople {
		email := sampleEmail(p)
		status := "active"
		if p.gone {
			status = "terminated"
		}
		// Ivo left, and Entra was never told: the account is still enabled.
		entraStatus := status
		if p.first == "Ivo" {
			entraStatus = "active"
		}
		entra.Lines = append(entra.Lines, map[string]string{"_endpoint": "users", "_produces": string(KindPerson),
			"id": fmt.Sprintf("e-%02d", i), "email": email, "name": p.first + " " + p.last,
			"title": p.title, "department": p.dept, "status": entraStatus})
		kb4.Lines = append(kb4.Lines, map[string]string{"_endpoint": "users", "_produces": string(KindPerson),
			"id": fmt.Sprintf("k-%02d", i), "email": email, "first_name": p.first, "last_name": p.last,
			"department": p.dept, "status": status, "phish_prone": fmt.Sprintf("%.1f", p.phish)})
		kb4.Lines = append(kb4.Lines, map[string]string{"_endpoint": "enrollments", "_produces": string(KindTraining),
			"id": fmt.Sprintf("t-%02d", i), "user": fmt.Sprintf("k-%02d", i), "email": email,
			"module": "2026 Security Awareness", "kind": "Training Module", "status": p.training})
		phish := map[string]string{"_endpoint": "phishing", "_produces": string(KindPhishing),
			"id": fmt.Sprintf("p-%02d", i), "parent": "campaign-sept", "user": fmt.Sprintf("k-%02d", i), "email": email,
			"delivered": stamp(20)}
		if p.clicked {
			phish["clicked"] = stamp(19)
		}
		if p.entered {
			phish["data_entered"] = stamp(19)
		}
		if p.report {
			phish["reported"] = stamp(20)
		}
		kb4.Lines = append(kb4.Lines, phish)
		vstatus := "active"
		if p.gone {
			vstatus = "former"
		}
		vanta.Lines = append(vanta.Lines, map[string]string{"_endpoint": "people", "_produces": string(KindPerson),
			"id": fmt.Sprintf("v-%02d", i), "email": email, "name": p.first + " " + p.last, "status": vstatus,
			"policies": p.policies, "training": map[bool]string{true: "complete", false: "overdue"}[p.training == "Passed"],
			"background_check": map[bool]string{true: "complete", false: "overdue"}[i%7 != 3]})
	}

	for i, m := range sampleMachines {
		owner := ""
		if m.owner >= 0 {
			owner = sampleEmail(samplePeople[m.owner])
		}
		line := map[string]string{"_produces": string(KindDevice), "id": fmt.Sprintf("m-%02d", i),
			"serial": m.serial, "name": m.name, "os": m.os, "os_version": m.version,
			"owner_email": owner, "seen": stamp(m.quietDays)}
		for k, v := range map[string]string{"encrypted": m.encrypted, "screenlock": m.lock, "antivirus": m.av,
			"password_manager": m.pwm, "rooted": m.rooted, "passcode_set": m.passcode} {
			if v != "" {
				line[k] = v
			}
		}
		if m.tool == "endpointcentral" {
			line["missing_patches"] = fmt.Sprint(m.patches)
			line["prohibited_software"] = fmt.Sprint(m.prohibited)
		}
		switch m.tool {
		case "endpointcentral":
			line["_endpoint"] = "computers"
			ec.Lines = append(ec.Lines, line)
		case "mdmplus":
			line["_endpoint"] = "devices"
			mdm.Lines = append(mdm.Lines, line)
		}
		// Vanta's agent is on every computer, and on one nobody manages.
		if strings.Contains(m.os, "mac") || strings.Contains(m.os, "Windows") {
			v := map[string]string{"_endpoint": "computers", "_produces": string(KindDevice),
				"id": fmt.Sprintf("vc-%02d", i), "serial": m.serial, "name": m.name, "os": m.os,
				"os_version": m.version, "owner_email": owner, "seen": stamp(m.quietDays),
				"encrypted": m.encrypted, "password_manager": m.pwm}
			if m.alsoVanta != "" {
				v["encrypted"] = "true" // Vanta's agent and the endpoint manager disagree
			}
			if m.noMDM || m.tool != "" {
				vanta.Lines = append(vanta.Lines, v)
			}
		}
	}
	for _, t := range []struct {
		name, cat, status string
		failing           int
	}{
		{"Security awareness training completed", "People", "fail", 7},
		{"Background checks completed", "People", "fail", 3},
		{"Security policies accepted", "Policies", "fail", 6},
		{"Computers have disk encryption", "Devices", "fail", 2},
		{"Computers have a password manager", "Devices", "fail", 8},
		{"MFA on the identity provider", "Identity", "pass", 0},
		{"Offboarded people lose access", "Identity", "fail", 1},
		{"Vulnerabilities fixed within SLA", "Engineering", "fail", 4},
		{"Access reviewed quarterly", "Identity", "pass", 0},
		{"Production database encrypted", "Infrastructure", "pass", 0},
	} {
		vanta.Lines = append(vanta.Lines, map[string]string{"_endpoint": "tests", "_produces": string(KindControl),
			"id": strings.ToLower(strings.ReplaceAll(t.name, " ", "-")), "name": t.name, "category": t.cat,
			"status": t.status, "failing_items": fmt.Sprint(t.failing)})
	}
	return []SampleTool{entra, kb4, vanta, ec, mdm}
}
