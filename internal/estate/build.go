// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/workforce"
)

// Individual is one person as every tool that knows them describes them.
type Individual struct {
	// Key is the lowest identifier among their records, so it does not
	// depend on which tool was read first.
	Key     string   `json:"key"`
	Records []Person `json:"records"`
	Emails  []string `json:"emails,omitempty"`
	// JoinedBy says how the records were put together: "confirmed" for a
	// link a person made, "email" for the one automatic rule.
	JoinedBy []string         `json:"joined_by,omitempty"`
	Devices  []*Machine       `json:"-"`
	Training []Training       `json:"training,omitempty"`
	Phishing []Phish          `json:"phishing,omitempty"`
	Sources  map[string]bool  `json:"sources"`
	Link     []workforce.Link `json:"-"`
}

// Name is the best label anybody has for them.
func (i *Individual) Name() string {
	for _, r := range i.Records {
		if strings.TrimSpace(r.Name) != "" {
			return r.Name
		}
	}
	if len(i.Emails) > 0 {
		return i.Emails[0]
	}
	return i.Key
}

// Current reads whether they are current across tools: current when every
// tool that says anything says so, gone when any says gone, and the tools
// that said each.
func (i *Individual) Current() (known, current bool, yes, no []string) {
	for _, r := range i.Records {
		if r.Active == nil {
			continue
		}
		if *r.Active {
			yes = append(yes, r.ID.Issuer)
		} else {
			no = append(no, r.ID.Issuer)
		}
	}
	sort.Strings(yes)
	sort.Strings(no)
	return len(yes)+len(no) > 0, len(no) == 0 && len(yes) > 0, yes, no
}

// Task is the status of a named compliance task in the tool that tracks it.
func (i *Individual) Task(name string) (status, source string) {
	for _, r := range i.Records {
		if s, ok := r.Tasks[name]; ok && s != "" {
			return s, r.ID.Issuer
		}
	}
	return "", ""
}

// Machine is one device as every tool that manages it describes it.
type Machine struct {
	// Key is the serial number when there is a usable one, and the
	// identifier of the only record otherwise.
	Key     string          `json:"key"`
	Serial  string          `json:"serial,omitempty"`
	Records []Device        `json:"records"`
	Class   Class           `json:"class,omitempty"`
	Owner   *Individual     `json:"-"`
	Sources map[string]bool `json:"sources"`
	// Owners are the owner addresses the tools gave, which may disagree.
	Owners    []string        `json:"owners,omitempty"`
	Software  []Software      `json:"software,omitempty"`
	Vulns     []Vulnerability `json:"vulnerabilities,omitempty"`
	Ambiguous bool            `json:"ambiguous,omitempty"`
}

// Name is the best label for it.
func (m *Machine) Name() string {
	for _, r := range m.Records {
		if strings.TrimSpace(r.Name) != "" {
			return r.Name
		}
	}
	return m.Key
}

// Seen is the most recent check-in any tool reports.
func (m *Machine) Seen() time.Time {
	var t time.Time
	for _, r := range m.Records {
		if r.Seen.After(t) {
			t = r.Seen
		}
	}
	return t
}

// Posture is what each tool says about one property, by tool.
func (m *Machine) Posture(get func(Device) *bool) map[string]bool {
	out := map[string]bool{}
	for _, r := range m.Records {
		if v := get(r); v != nil {
			out[r.ID.Issuer] = *v
		}
	}
	return out
}

// Estate is everything the tools said, joined.
type Estate struct {
	At          time.Time           `json:"at"`
	Sources     map[string]Snapshot `json:"sources"`
	People      []*Individual       `json:"people"`
	Machines    []*Machine          `json:"machines"`
	Controls    []Control           `json:"controls,omitempty"`
	Unplaced    Unplaced            `json:"unplaced"`
	Notes       []string            `json:"notes,omitempty"`
	byEmail     map[string]*Individual
	personOf    map[string]*Individual
	machineOf   map[string]*Machine
	testStarted map[string]time.Time
	// Tests names each phishing test, by tool and identifier.
	Tests map[string]string `json:"-"`
}

// Unplaced counts what could not be attached to anybody or anything, which
// is reported rather than dropped: training that belongs to no person is
// training nobody is being measured on.
type Unplaced struct {
	Training int `json:"training,omitempty"`
	Phishing int `json:"phishing,omitempty"`
	Software int `json:"software,omitempty"`
	Vulns    int `json:"vulnerabilities,omitempty"`
	Posture  int `json:"posture,omitempty"`
}

// Complete reports whether a tool was read, and read to the end, for a kind.
func (e *Estate) Complete(source string, k Kind) bool {
	s, ok := e.Sources[source]
	return ok && s.complete(k)
}

// With lists the tools that produced a kind completely.
func (e *Estate) With(k Kind) []string {
	var out []string
	for _, name := range sortedKeys(e.Sources) {
		if e.Sources[name].complete(k) {
			out = append(out, name)
		}
	}
	return out
}

// Build joins snapshots. Links are the person-to-person links people have
// confirmed; the exact-email rule is applied on top of them.
func Build(snaps []Snapshot, links []workforce.Link, now time.Time) *Estate {
	e := &Estate{At: now, Sources: map[string]Snapshot{},
		byEmail: map[string]*Individual{}, personOf: map[string]*Individual{},
		machineOf: map[string]*Machine{}, testStarted: map[string]time.Time{},
		Tests: map[string]string{}}
	var persons []Person
	var devices []Device
	var posture, training, phishing, software, vulns []Line
	for _, s := range snaps {
		e.Sources[s.Source] = s
		for _, l := range s.Lines {
			kind := Kind(l["_produces"])
			switch {
			case kind == KindPerson:
				if p, ok := personFrom(s.Source, l, now); ok {
					persons = append(persons, p)
				}
			case kind == KindDevice:
				if d, ok := deviceFrom(s.Source, l); ok {
					devices = append(devices, d)
				}
			case kind == KindControl && l["parent"] != "":
				posture = append(posture, l)
			case kind == KindControl || kind == KindPolicy:
				if c, ok := controlFrom(s.Source, kind, l); ok {
					e.Controls = append(e.Controls, c)
				}
			case kind == KindTraining:
				training = append(training, l)
			case kind == KindEvent:
				if t := when(l["started"]); !t.IsZero() && l["id"] != "" {
					e.testStarted[s.Source+":"+l["id"]] = t
				}
				if l["id"] != "" && l["name"] != "" {
					e.Tests[s.Source+":"+l["id"]] = l["name"]
				}
			case kind == KindPhishing:
				phishing = append(phishing, l)
			case kind == KindSoftware:
				software = append(software, l)
			case kind == KindVulnerability:
				vulns = append(vulns, l)
			}
		}
	}
	devices = mergePosture(devices, posture, &e.Unplaced)
	e.joinPeople(persons, links)
	e.joinMachines(devices)
	e.place(training, phishing, software, vulns)
	return e
}

func personFrom(source string, l Line, now time.Time) (Person, bool) {
	if l["id"] == "" {
		return Person{}, false
	}
	p := Person{
		ID:    telemetry.ID{Issuer: source, Value: l["id"]},
		Email: Email(l["email"]), EmployeeNumber: l["employee_number"],
		Title: l["title"], Department: l["department"], Office: l["office"],
		ManagerEmail: Email(l["manager_email"]),
		Ended:        when(l["ended"]),
		PhishProne:   number(l["phish_prone"]),
		RiskScore:    number(l["risk_score"]),
	}
	// A directory's sign-in name stands in for an address it does not have:
	// Entra's mail is empty for anybody without a mailbox.
	if p.Email == "" {
		p.Email = Email(l["upn"])
	}
	p.Name = l["name"]
	if p.Name == "" {
		p.Name = strings.TrimSpace(l["first_name"] + " " + l["last_name"])
	}
	if p.Department == "" {
		p.Department = l["division"]
	}
	for _, f := range []string{"employment", "status"} {
		if a := current(l[f]); a != nil {
			p.Active = a
			break
		}
	}
	// An archived date or an end date in the past is somebody gone, even
	// when the status field says otherwise — that disagreement inside one
	// tool is how a leaver stays active.
	if !when(l["archived"]).IsZero() ||
		(!p.Ended.IsZero() && p.Ended.Before(now)) {
		f := false
		p.Active = &f
	}
	for _, t := range []string{"training", "policies", "device_monitoring",
		"background_check"} {
		if s := task(l[t]); s != "" {
			if p.Tasks == nil {
				p.Tasks = map[string]string{}
			}
			p.Tasks[t] = s
		}
		if d := when(l[t+"_due"]); !d.IsZero() {
			if p.Due == nil {
				p.Due = map[string]time.Time{}
			}
			p.Due[t] = d
		}
	}
	return p, true
}

func deviceFrom(source string, l Line) (Device, bool) {
	if l["id"] == "" {
		return Device{}, false
	}
	d := Device{
		ID:     telemetry.ID{Issuer: source, Value: l["id"]},
		Serial: Serial(l["serial"]), Name: l["name"], OS: l["os"],
		OSVersion: l["os_version"], Platform: l["platform"],
		OwnerEmail: Email(l["owner_email"]),
		OwnerName:  l["owner_name"], User: l["user"], Seen: when(l["seen"]),
	}
	if r := truth(l["removed"]); r != nil && *r {
		d.Removed = true
	}
	d.Class = classify(l["os"] + " " + l["platform"])
	applyPosture(&d, l)
	return d, true
}

// applyPosture reads the posture fields a record carries onto a device.
func applyPosture(d *Device, l Line) {
	set := func(dst **bool, field string) {
		if v := truth(l[field]); v != nil {
			*dst = v
		}
	}
	set(&d.Encrypted, "encryption")
	set(&d.Encrypted, "encrypted")
	set(&d.ScreenLock, "screenlock")
	set(&d.Antivirus, "antivirus")
	set(&d.PasswordManager, "password_manager")
	set(&d.Rooted, "rooted")
	set(&d.Passcode, "passcode_set")
	if n := count(l["missing_patches"]); n != nil {
		d.MissingPatches = n
	}
	if n := count(l["prohibited_software"]); n != nil {
		d.Prohibited = n
	}
	if s := Serial(l["serial"]); s != "" && d.Serial == "" {
		d.Serial = s
	}
	if d.OSVersion == "" {
		d.OSVersion = l["os_version"]
	}
}

// mergePosture puts records read per device onto their device. A record
// about one drive (Endpoint Central reads encryption per drive) makes the
// device encrypted only if every fixed drive is.
func mergePosture(devices []Device, posture []Line, u *Unplaced) []Device {
	at := map[string]int{}
	for i, d := range devices {
		at[d.ID.String()] = i
	}
	drives := map[int][]bool{}
	for _, l := range posture {
		key := telemetry.ID{Issuer: l["_source"], Value: l["parent"]}.String()
		i, ok := at[key]
		if !ok {
			u.Posture++
			continue
		}
		if l["drive"] != "" {
			if strings.EqualFold(l["drive_type"], "removable") {
				continue
			}
			if v := truth(l["status"]); v != nil {
				drives[i] = append(drives[i], *v)
			}
			continue
		}
		applyPosture(&devices[i], l)
	}
	for i, states := range drives {
		all := true
		for _, s := range states {
			all = all && s
		}
		devices[i].Encrypted = &all
	}
	return devices
}

func controlFrom(source string, k Kind, l Line) (Control, bool) {
	if l["id"] == "" {
		return Control{}, false
	}
	c := Control{ID: telemetry.ID{Issuer: source, Value: l["id"]},
		Name: l["name"], Category: l["category"], Policy: k == KindPolicy}
	status := l["status"]
	if c.Policy && l["latest_version"] != "" {
		status = l["latest_version"]
	}
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "OK", "PASS", "APPROVED":
		t := true
		c.Passing = &t
	case "NEEDS_ATTENTION", "FAIL", "FAILED", "ERROR", "DRAFT",
		"NEEDS_APPROVAL":
		f := false
		c.Passing = &f
	}
	if d := truth(l["deactivated"]); d != nil && *d {
		// A deactivated test is not a passing one; it is not being run.
		c.Passing = nil
	}
	if n := count(l["failing_items"]); n != nil {
		c.Failing = *n
	}
	return c, true
}

// joinPeople groups person records: confirmed links first, then an exact
// email match where the address belongs to one record in each tool and is
// not a team's.
func (e *Estate) joinPeople(persons []Person, links []workforce.Link) {
	parent := map[string]string{}
	index := map[string]Person{}
	for _, p := range persons {
		k := p.ID.String()
		if _, dup := index[k]; dup {
			continue
		}
		index[k] = p
		parent[k] = k
	}
	var find func(string) string
	find = func(k string) string {
		for parent[k] != k {
			parent[k] = parent[parent[k]]
			k = parent[k]
		}
		return k
	}
	how := map[string][]string{}
	union := func(a, b, why string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if rb < ra {
			ra, rb = rb, ra
		}
		parent[rb] = ra
		how[ra] = append(how[ra], why)
		how[ra] = append(how[ra], how[rb]...)
	}
	for _, l := range links {
		a, b := l.A.String(), l.B.String()
		if _, ok := index[a]; !ok {
			continue
		}
		if _, ok := index[b]; !ok {
			continue
		}
		union(a, b, "confirmed")
	}

	byEmail := map[string][]Person{}
	for _, k := range sortedKeys(index) {
		p := index[k]
		if p.Email != "" {
			byEmail[p.Email] = append(byEmail[p.Email], p)
		}
	}
	for _, email := range sortedKeys(byEmail) {
		group := byEmail[email]
		if len(group) < 2 {
			continue
		}
		if Shared(email) {
			e.Notes = append(e.Notes, fmt.Sprintf(
				"%s is a team mailbox, so %d records using it were not "+
					"joined: joining them would make everybody who reads it "+
					"one person", email, len(group)))
			continue
		}
		per := map[string]int{}
		for _, p := range group {
			per[p.ID.Issuer]++
		}
		ambiguous := false
		for issuer, n := range per {
			if n > 1 {
				ambiguous = true
				e.Notes = append(e.Notes, fmt.Sprintf(
					"%s has %d records in %s with the same address, so none "+
						"of them was joined automatically; that duplicate is "+
						"%s's to resolve", issuer, n, issuer, issuer))
			}
		}
		if ambiguous {
			continue
		}
		for _, p := range group[1:] {
			union(group[0].ID.String(), p.ID.String(), "email")
		}
	}

	groups := map[string]*Individual{}
	for _, k := range sortedKeys(index) {
		root := find(k)
		ind, ok := groups[root]
		if !ok {
			ind = &Individual{Key: root, Sources: map[string]bool{}}
			groups[root] = ind
		}
		p := index[k]
		ind.Records = append(ind.Records, p)
		ind.Sources[p.ID.Issuer] = true
		if p.Email != "" && !contains(ind.Emails, p.Email) {
			ind.Emails = append(ind.Emails, p.Email)
		}
		e.personOf[k] = ind
	}
	for root, ind := range groups {
		ind.JoinedBy = dedupe(how[root])
		sort.Strings(ind.Emails)
		for _, em := range ind.Emails {
			e.byEmail[em] = ind
		}
		e.People = append(e.People, ind)
	}
	sort.Slice(e.People, func(i, j int) bool {
		return e.People[i].Key < e.People[j].Key
	})
}

// joinMachines groups device records by serial number, where the serial is
// usable and unique within each tool.
func (e *Estate) joinMachines(devices []Device) {
	perTool := map[string]map[string]int{}
	for _, d := range devices {
		if d.Serial == "" {
			continue
		}
		if perTool[d.ID.Issuer] == nil {
			perTool[d.ID.Issuer] = map[string]int{}
		}
		perTool[d.ID.Issuer][d.Serial]++
	}
	shared := map[string]bool{}
	for tool, serials := range perTool {
		for serial, n := range serials {
			if n > 1 {
				shared[serial] = true
				e.Notes = append(e.Notes, fmt.Sprintf(
					"serial %s is on %d devices in %s, so it identifies none "+
						"of them and they were not joined to anything",
					serial, n, tool))
			}
		}
	}
	sort.Strings(e.Notes)

	groups := map[string]*Machine{}
	var order []string
	for _, d := range devices {
		key := d.ID.String()
		if d.Serial != "" && !shared[d.Serial] {
			key = "serial:" + d.Serial
		}
		m, ok := groups[key]
		if !ok {
			m = &Machine{Key: key, Serial: d.Serial, Sources: map[string]bool{},
				Ambiguous: shared[d.Serial]}
			groups[key] = m
			order = append(order, key)
		}
		m.Records = append(m.Records, d)
		m.Sources[d.ID.Issuer] = true
		if m.Class == "" {
			m.Class = d.Class
		}
		if d.OwnerEmail != "" && !contains(m.Owners, d.OwnerEmail) {
			m.Owners = append(m.Owners, d.OwnerEmail)
		}
		e.machineOf[d.ID.String()] = m
	}
	sort.Strings(order)
	for _, key := range order {
		m := groups[key]
		sort.Strings(m.Owners)
		// An owner only when the tools agree on one and that address is a
		// person here. Two tools naming two people is a finding, not a
		// choice for this program to make.
		if len(m.Owners) == 1 {
			if ind, ok := e.byEmail[m.Owners[0]]; ok {
				m.Owner = ind
				ind.Devices = append(ind.Devices, m)
			}
		}
		e.Machines = append(e.Machines, m)
	}
}

// place attaches training, phishing results, software and vulnerabilities
// to the person or machine they are about.
func (e *Estate) place(training, phishing, software, vulns []Line) {
	who := func(source, user, email string) *Individual {
		if user != "" {
			if ind, ok := e.personOf[telemetry.ID{Issuer: source,
				Value: user}.String()]; ok {
				return ind
			}
		}
		return e.byEmail[Email(email)]
	}
	for _, l := range training {
		src := l["_source"]
		t := Training{ID: telemetry.ID{Issuer: src, Value: l["id"]},
			User:  telemetry.ID{Issuer: src, Value: l["user"]},
			Email: Email(l["email"]), Module: l["module"], Status: l["status"],
			Done: finished(l["status"]), Completed: when(l["completed"])}
		if strings.Contains(strings.ToLower(l["kind"]), "policy") {
			t.Policy = true
			t.Acknowledged = truth(l["policy_acknowledged"])
		}
		if ind := who(src, l["user"], l["email"]); ind != nil {
			ind.Training = append(ind.Training, t)
		} else {
			e.Unplaced.Training++
		}
	}
	for _, l := range phishing {
		src := l["_source"]
		p := Phish{ID: telemetry.ID{Issuer: src, Value: l["id"]},
			Test: l["parent"], TestName: e.Tests[src+":"+l["parent"]], User: telemetry.ID{Issuer: src, Value: l["user"]},
			Email: Email(l["email"]), Delivered: when(l["delivered"]),
			Clicked: when(l["clicked"]), DataEntered: when(l["data_entered"]),
			Reported: when(l["reported"])}
		for _, f := range []string{"replied", "attachment_opened",
			"macro_enabled", "qr_scanned"} {
			if t := when(l[f]); !t.IsZero() &&
				(p.Other.IsZero() || t.Before(p.Other)) {
				p.Other = t
			}
		}
		if ind := who(src, l["user"], l["email"]); ind != nil {
			ind.Phishing = append(ind.Phishing, p)
		} else {
			e.Unplaced.Phishing++
		}
	}
	machine := func(source, id string) *Machine {
		return e.machineOf[telemetry.ID{Issuer: source, Value: id}.String()]
	}
	for _, l := range software {
		m := machine(l["_source"], l["parent"])
		if m == nil || l["name"] == "" {
			e.Unplaced.Software++
			continue
		}
		s := Software{Device: telemetry.ID{Issuer: l["_source"],
			Value: l["parent"]}, Name: l["name"], Version: l["version"],
			Maker: l["maker"]}
		if p := truth(l["prohibited"]); p != nil && *p {
			s.Prohibited = true
		}
		m.Software = append(m.Software, s)
	}
	for _, l := range vulns {
		id := l["computer"]
		if id == "" {
			id = l["parent"]
		}
		m := machine(l["_source"], id)
		if m == nil {
			e.Unplaced.Vulns++
			continue
		}
		status := strings.ToLower(strings.TrimSpace(l["status"]))
		m.Vulns = append(m.Vulns, Vulnerability{
			Device: telemetry.ID{Issuer: l["_source"], Value: id},
			ID:     l["id"], Name: l["name"], Severity: l["severity"],
			Open: status == "" || status == "open" || status == "active"})
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
