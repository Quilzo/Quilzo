// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The shipped connectors, read against the sample responses their vendors
// publish. A path that does not match the documented shape comes back empty,
// and that is what these tests look for.

func entry(t *testing.T, name string) Entry {
	t.Helper()
	all, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := all[name]
	if !ok {
		t.Fatalf("no %s in the catalogue", name)
	}
	return e
}

func TestEveryShippedConnectorLoadsInEveryRegion(t *testing.T) {
	all, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"knowbe4", "vanta", "mdmplus",
		"endpointcentral"} {
		if _, ok := all[want]; !ok {
			t.Errorf("%s is missing from the catalogue", want)
		}
	}
	for name, e := range all {
		if _, ok := e.Regions[e.Default]; !ok {
			t.Errorf("%s: the default region %q is not one of its regions",
				name, e.Default)
		}
		for _, region := range e.RegionNames() {
			m, err := e.For(region)
			if err != nil {
				t.Errorf("%s/%s: %v", name, region, err)
				continue
			}
			if m.Auth.Kind.oauth() && m.Auth.Token.Host == "" {
				t.Errorf("%s/%s has no token host", name, region)
			}
			// Every credential the manifest names is explained to the
			// person who has to go and make it, and nothing else is.
			names := []string{m.Auth.Secret}
			if m.Auth.Token != nil {
				names = append(names, m.Auth.Token.Client)
				if m.Auth.Token.Refresh != "" {
					names = append(names, m.Auth.Token.Refresh)
				}
			}
			for _, n := range names {
				if strings.TrimSpace(e.Credentials[n]) == "" {
					t.Errorf("%s names the credential %s and does not say "+
						"what it is or where it is made", name, n)
				}
			}
			if len(e.Credentials) != len(names) {
				t.Errorf("%s explains %d credentials and uses %d", name,
					len(e.Credentials), len(names))
			}
		}
		if _, err := e.For("mars"); err == nil {
			t.Errorf("%s accepted a region it does not have", name)
		}
	}
}

// A region is chosen from the list; it is never a host somebody types.
func TestARegionCannotBeAHost(t *testing.T) {
	e := entry(t, "knowbe4")
	for _, r := range []string{"evil.example.com", "us.api.knowbe4.com",
		"../us"} {
		if _, err := e.For(r); err == nil {
			t.Errorf("%q was taken as a region", r)
		}
	}
	m, _ := e.For("eu")
	if m.Host != "eu.api.knowbe4.com" {
		t.Errorf("eu reads %s", m.Host)
	}
	// And choosing one does not change the catalogue for the next caller.
	us, _ := e.For("us")
	if us.Host != "us.api.knowbe4.com" {
		t.Errorf("after reading eu, us reads %s", us.Host)
	}
}

// The limits each vendor publishes, which a run must stay inside.
func TestTheShippedConnectorsKeepToTheVendorsLimits(t *testing.T) {
	kb := entry(t, "knowbe4").Manifest
	if kb.Rate.PerSecond > 4 || kb.Rate.PerMinute > 50 || kb.Rate.PerDay > 2000 {
		t.Errorf("KnowBe4 allows 4 a second, 50 a minute and 2,000 a day "+
			"(plus one per seat); this declares %+v", kb.Rate)
	}
	v := entry(t, "vanta").Manifest
	if v.Rate.PerMinute == 0 || v.Rate.PerMinute > 50 {
		t.Errorf("Vanta allows 50 a minute; this declares %+v", v.Rate)
	}
	ec := entry(t, "endpointcentral").Manifest
	if ec.Rate.PerMinute == 0 || ec.Rate.PerMinute >= 120 {
		t.Errorf("Endpoint Central locks a client out for five minutes past "+
			"120 a minute; this declares %+v", ec.Rate)
	}
	vulns, _ := ec.Endpoint("vulnerabilities")
	if vulns.Rate.PerMinute == 0 || vulns.Rate.PerMinute >= 30 {
		t.Errorf("the vulnerability report locks past 30 a minute; this "+
			"declares %+v", vulns.Rate)
	}
}

// fake answers every host of a manifest from a table of path to body.
func fake(t *testing.T, m Manifest, bodies map[string]string,
	seen *[]string) *hosts {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.Path+" "+
			r.Header.Get("Accept"))
		if r.URL.Path == "/oauth/token" || r.URL.Path == "/oauth/v2/token" {
			io.WriteString(w, `{"access_token":"1000.abcdef.123456","expires_in":3600}`)
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request for %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, body)
	}
	s := serve(t, handler)
	servers := map[string]*httptest.Server{m.Host: s}
	if m.Auth.Token != nil {
		servers[m.Auth.Token.Host] = s
	}
	return route(t, servers)
}

func readAll(t *testing.T, m Manifest, h Doer, s Secrets) map[string]Result {
	t.Helper()
	x, err := NewSession(m, h, s, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Result{}
	for _, r := range x.All(context.Background(), nil, nil) {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Endpoint, r.Err)
		}
		out[r.Endpoint] = r.Result
	}
	return out
}

func want(t *testing.T, rec map[string]string, fields map[string]string) {
	t.Helper()
	for k, v := range fields {
		if rec[k] != v {
			t.Errorf("%s is %q, want %q (record %v)", k, rec[k], v, rec)
		}
	}
}

func TestKnowBe4AgainstItsDocumentedResponses(t *testing.T) {
	m, err := entry(t, "knowbe4").For("eu")
	if err != nil {
		t.Fatal(err)
	}
	recent := time.Now().UTC().AddDate(0, 0, -20).Format(time.RFC3339)
	old := time.Now().UTC().AddDate(-2, 0, 0).Format(time.RFC3339)
	var seen []string
	h := fake(t, m, map[string]string{
		"/v1/users": `[{"id":667542,"employee_number":"19425","first_name":"William",
			"last_name":"Marcoux","job_title":"VP of Sales","email":"wmarcoux@kb4-demo.com",
			"phish_prone_percentage":14.235,"location":"Cairo, Egypt","division":"Sales",
			"manager_name":"Michael Scott","manager_email":"mscott@kb4-demo.com",
			"status":"active","current_risk_score":45.742,"joined_on":"2019-04-02T15:02:38.000Z",
			"last_sign_in":"2019-04-02T15:02:38.000Z","department":"Sales",
			"ip_location":"should never be read"}]`,
		"/v1/training/enrollments": `[{"enrollment_id":1425526,"content_type":"Uploaded Policy",
			"module_name":"Acceptable Use Policy","user":{"id":796742,
			"first_name":"Sarah","last_name":"Thomas","email":"s_thomas@kb4-demo.com"},
			"campaign_name":"New Employee Policies","enrollment_date":"2019-04-02T15:02:38.000Z",
			"start_date":"2019-04-02T15:02:38.000Z","completion_date":"2019-04-02T15:02:38.000Z",
			"status":"Passed","time_spent":2340,"policy_acknowledged":false}]`,
		"/v1/phishing/security_tests": `[
			{"pst_id":1,"campaign_id":242333,"name":"Corporate Test","status":"Closed",
			 "started_at":"` + recent + `","phish_prone_percentage":0.5,"clicked_count":1},
			{"pst_id":2,"name":"Old Test","started_at":"` + old + `"}]`,
		"/v1/phishing/security_tests/1/recipients": `[{"recipient_id":3077742,
			"pst_id":14240,"user":{"id":264215,"email":"psmith@kb4-demo.com"},
			"clicked_at":"2019-04-02T15:02:38.000Z","reported_at":null,
			"data_entered_at":"2019-04-02T15:02:38.000Z","ip":"XX.XX.XXX.XXX",
			"ip_location":"St.Petersburg, FL","browser":"Chrome","os":"MacOSX"}]`,
	}, &seen)
	got := readAll(t, m, h, MapFunc{"knowbe4-reporting-key": "kb4key"})

	want(t, got["users"].Records[0], map[string]string{
		"id": "667542", "email": "wmarcoux@kb4-demo.com",
		"employee_number": "19425", "phish_prone": "14.235",
		"risk_score": "45.742", "office": "Cairo, Egypt",
		"manager_email": "mscott@kb4-demo.com", "status": "active"})
	want(t, got["enrollments"].Records[0], map[string]string{
		"id": "1425526", "user": "796742", "email": "s_thomas@kb4-demo.com",
		"module": "Acceptable Use Policy", "status": "Passed",
		"policy_acknowledged": "false", "time_spent": "2340"})
	if len(got["phishing_results"].Records) != 1 {
		t.Fatalf("results: %v", got["phishing_results"].Records)
	}
	want(t, got["phishing_results"].Records[0], map[string]string{
		"parent": "1", "email": "psmith@kb4-demo.com",
		"clicked": "2019-04-02T15:02:38.000Z",
		"data_entered": "2019-04-02T15:02:38.000Z"})
	if _, ok := got["phishing_results"].Records[0]["reported"]; ok {
		t.Error("a null reported_at was mapped to something")
	}
	for _, rec := range append(got["users"].Records,
		got["phishing_results"].Records...) {
		for k, v := range rec {
			if strings.Contains(v, "St.Petersburg") || strings.Contains(v,
				"XX.XX") || strings.Contains(v, "should never") {
				t.Errorf("%s holds %q, which was never declared", k, v)
			}
		}
	}
	for _, s := range seen {
		if strings.Contains(s, "/security_tests/2/") {
			t.Error("a phishing test from two years ago was read, which " +
				"spends the day's budget on history")
		}
	}
}

func TestVantaAgainstItsDocumentedResponses(t *testing.T) {
	m, err := entry(t, "vanta").For("commercial")
	if err != nil {
		t.Fatal(err)
	}
	page := func(data string) string {
		return `{"results":{"data":[` + data + `],"pageInfo":{"hasNextPage":false,
			"hasPreviousPage":false,"startCursor":"YXJy","endCursor":"YXJy"}}}`
	}
	var seen []string
	h := fake(t, m, map[string]string{
		"/v1/people": page(`{"id":"p1","emailAddress":"jane@acme.com",
			"employment":{"status":"FORMER","startDate":"2022-01-10T00:00:00Z",
			"endDate":"2026-03-01T00:00:00Z","jobTitle":"Engineer"},
			"name":{"first":"Jane","last":"Doe","display":"Jane Doe"},
			"tasksSummary":{"status":"OVERDUE","dueDate":"2026-02-01T00:00:00Z",
			"details":{"completeTrainings":{"taskType":"COMPLETE_TRAININGS",
			"status":"OVERDUE","dueDate":"2026-02-01T00:00:00Z","completionDate":null},
			"acceptPolicies":{"status":"COMPLETE","completionDate":"2025-01-02T00:00:00Z"},
			"installDeviceMonitoring":{"status":"COMPLETE"},
			"completeBackgroundChecks":{"status":"NONE"}}}}`),
		"/v1/monitored-computers": page(`{"id":"5f2c939a52855e725c8d5823",
			"integrationId":"vantaAgent","serialNumber":"FVFGPGV2Q6L5",
			"udid":"280FF071-1D7A-5752-BD3A-1A68937CD187",
			"lastCheckDate":"2024-03-07T18:46:05.944Z","screenlock":{"outcome":"FAIL"},
			"diskEncryption":{"outcome":"PASS"},"passwordManager":{"outcome":"FAIL"},
			"antivirusInstallation":{"outcome":"FAIL"},
			"operatingSystem":{"type":"macOS","version":"13.2.1"},
			"owner":{"id":"65e1efde08e8478f143a8ff9","emailAddress":"example-person@email.com",
			"displayName":"Example Owner"}}`),
		"/v1/tests": page(`{"id":"aws-account-access-removed-on-termination",
			"name":"AWS accounts deprovisioned when personnel leave",
			"lastTestRunDate":"2024-06-18T20:17:38.463Z","category":"Account security",
			"status":"OK","deactivatedStatusInfo":{"isDeactivated":false},
			"remediationStatusInfo":{"status":"PASS","itemCount":0}}`),
		"/v1/policies": page(`{"id":"code-of-conduct-bsi","name":"Code of Conduct",
			"status":"OK","approvedAtDate":"2024-01-15T10:30:00.000Z",
			"latestVersion":{"status":"APPROVED"}}`),
	}, &seen)
	got := readAll(t, m, h, MapFunc{"vanta-client-id": "vci_x",
		"vanta-client-secret": "vcs_y"})

	want(t, got["people"].Records[0], map[string]string{
		"email": "jane@acme.com", "employment": "FORMER",
		"ended": "2026-03-01T00:00:00Z", "training": "OVERDUE",
		"policies": "COMPLETE", "device_monitoring": "COMPLETE",
		"name": "Jane Doe"})
	want(t, got["computers"].Records[0], map[string]string{
		"serial": "FVFGPGV2Q6L5", "screenlock": "FAIL", "encryption": "PASS",
		"antivirus": "FAIL", "owner_email": "example-person@email.com",
		"os_version": "13.2.1"})
	want(t, got["tests"].Records[0], map[string]string{
		"status": "OK", "remediation": "PASS", "failing_items": "0",
		"deactivated": "false"})
	want(t, got["policies"].Records[0], map[string]string{
		"name": "Code of Conduct", "latest_version": "APPROVED"})

	tokens := 0
	for _, s := range seen {
		if strings.HasPrefix(s, "POST /oauth/token") {
			tokens++
		}
	}
	if tokens != 1 {
		t.Errorf("%d tokens for one read of four endpoints", tokens)
	}
	if len(seen) != 5 {
		t.Errorf("%d requests: one token and one page each, since every page "+
			"said it was the last: %v", len(seen), seen)
	}
}

func TestMDMPlusAgainstItsDocumentedResponses(t *testing.T) {
	m, err := entry(t, "mdmplus").For("eu")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	h := fake(t, m, map[string]string{
		"/api/v1/mdm/devices": `{"devices":[{"device_id":9007199254741001,
			"os_version":"8.0.0","is_lost_mode_enabled":false,"owned_by":2,
			"is_removed":false,"product_name":"samsung","device_name":"admin_SM-G935F",
			"platform_type":"android","udid":"f8c4071d394ef48e",
			"serial_number":"2321bkbkqgidga1","model":"SM-G935F",
			"user":{"user_name":"admin","user_id":9007199254741000,
			"user_email":"admin@zylker.com"},"imei":357327071694307}],
			"paging":{"next":null}}`,
		"/api/v1/mdm/devices/9007199254741001": `{"serial_number":"2321bkbkqgidga1",
			"is_supervised":false,"managed_status":2,"registered_time":1540655566627,
			"apn_password":"never-read","security":{"passcode_complaint":false,
			"storage_encryption":false,"passcode_present":false,"device_rooted":true},
			"os":{"os_version":"8.0.0","serial_number":"2321bkbkqgidga1"}}`,
		"/api/v1/mdm/devices/9007199254741001/apps": `{"installed_apps":[
			{"app_version":"0.1.187945513","platform_type":"android",
			"identifier":"com.google.android.apps.googleassistant",
			"app_name":"Red Ball 4 (Ad Supported)","app_id":9007199254740996}]}`,
	}, &seen)
	got := readAll(t, m, h, MapFunc{"zoho-client-id": "1000.C",
		"zoho-client-secret": "s", "mdmplus-refresh-token": "1000.r"})

	want(t, got["devices"].Records[0], map[string]string{
		"id": "9007199254741001", "serial": "2321bkbkqgidga1",
		"owner_email": "admin@zylker.com", "imei": "357327071694307",
		"platform": "android"})
	want(t, got["device_security"].Records[0], map[string]string{
		"parent": "9007199254741001", "encrypted": "false",
		"passcode_set": "false", "rooted": "true", "supervised": "false"})
	want(t, got["apps"].Records[0], map[string]string{
		"parent":     "9007199254741001",
		"identifier": "com.google.android.apps.googleassistant"})
	for k, v := range got["device_security"].Records[0] {
		if v == "never-read" {
			t.Errorf("%s holds the APN password", k)
		}
	}
}

func TestEndpointCentralAgainstItsDocumentedResponses(t *testing.T) {
	m, err := entry(t, "endpointcentral").For("uk")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	h := fake(t, m, map[string]string{
		"/dcapi/inventory/viewData/scanComputers": `{"metadata":{"limit":25,"page":1},
			"totalRecords":"1","messageResponse":[{"resource_id":"301",
			"resource_name":"sample-computer","fqdn_name":"SAMPLE-COMPUTER.DOMAIN.COM",
			"servicetag":"SAMPLE01","os_name":"Windows 11 Professional Edition (x64)",
			"os_version":"10.0.26200","agent_last_contact_time":"1778756427000",
			"computer_live_status":"1","name":"SampleUser","ip_address":"10.0.0.1",
			"mac_address":"00:00:00:00:00:00"}],"totalPages":1,
			"Links":{"next":null,"prev":null},"status":"success"}`,
		"/dcapi/inventory/computers/301/diskEncryptionStatus": `{"diskEncryptionStatusDetails":[
			{"logicalDriveName":"/dev/sda1","encryptionStatus":"Encrypted",
			 "logicalDiskType":"Primary","encryptionMethod":"LUKS"},
			{"logicalDriveName":"/dev/sda2","encryptionStatus":"Not Encrypted",
			 "logicalDiskType":"Primary","encryptionMethod":"None"}]}`,
		"/dcapi/inventory/computers/301/assetSummary": `{"totalHardwaresCount":24,
			"totalSoftwaresCount":35,"missingPatchesCount":3,"commercialSoftwaresCount":0,
			"prohibitedSoftwaresCount":1}`,
		"/dcapi/inventory/computers/301/softwareInfo": `{"metadata":{"offset":1,"limit":500},
			"data":[{"invsw.software_name":"Sample Software","invsw.software_version":"13.2.5026.0",
			"invmanufacturer.manufacturer_name":"Sample Manufacturer",
			"invsw.is_usage_prohibited":0,"invswinstalled.installed_date":"1772700015000"}],
			"links":{"next":null,"prev":null},"status":"success"}`,
		"/dcapi/threats/systemreport/vulnerabilities": `{"metadata":{"pageLimit":100,
			"totalRecords":"1","totalPages":1,"links":{"next":null},"page":1},
			"message_response":{"systemreport":[{"resource_id":"304","vulnerabilities":[
			{"updatedtime":"1704365176820","severity":"Moderate","vulnerabilityid":"148376",
			 "vulnerabilityname":"Fixed in Apache Tomcat 8.5.75","vulnerability_status":"open"},
			{"updatedtime":"1704365176820","severity":"Important","vulnerabilityid":"154557",
			 "vulnerabilityname":"Fixed in Apache Tomcat 8.5.76","vulnerability_status":"open"}]}]},
			"status":"success"}`,
	}, &seen)
	got := readAll(t, m, h, MapFunc{"zoho-client-id": "1000.C",
		"zoho-client-secret": "s", "endpointcentral-refresh-token": "1000.r"})

	want(t, got["computers"].Records[0], map[string]string{
		"id": "301", "serial": "SAMPLE01", "user": "SampleUser",
		"seen": "1778756427000", "os_version": "10.0.26200"})
	for k, v := range got["computers"].Records[0] {
		if v == "10.0.0.1" || strings.Contains(v, "00:00:00") {
			t.Errorf("%s holds a network address, which was never declared", k)
		}
	}
	if n := len(got["encryption"].Records); n != 2 {
		t.Errorf("%d drives", n)
	}
	want(t, got["encryption"].Records[1], map[string]string{
		"parent": "301", "drive": "/dev/sda2", "status": "Not Encrypted"})
	want(t, got["posture"].Records[0], map[string]string{
		"parent": "301", "missing_patches": "3", "prohibited_software": "1"})
	want(t, got["software"].Records[0], map[string]string{
		"parent": "301", "name": "Sample Software", "version": "13.2.5026.0",
		"maker": "Sample Manufacturer", "prohibited": "0"})
	if n := len(got["vulnerabilities"].Records); n != 2 {
		t.Fatalf("%d vulnerabilities", n)
	}
	want(t, got["vulnerabilities"].Records[1], map[string]string{
		"computer": "304", "id": "154557", "severity": "Important",
		"status": "open"})

	for _, s := range seen {
		switch {
		case strings.Contains(s, "softwareInfo") &&
			!strings.HasSuffix(s, "application/softwareInfo.v1+json"):
			t.Errorf("%s: Endpoint Central answers this only when asked for "+
				"its own media type", s)
		case strings.Contains(s, "scanComputers") &&
			!strings.HasSuffix(s, "application/InventoryMobileAPI.v1+json"):
			t.Errorf("%s asked for the wrong media type", s)
		}
	}
}

// If the device list fails, the apps are reported as not read, never as a
// device estate with no apps on it.
func TestAChildOfAFailedParentIsNotReportedAsEmpty(t *testing.T) {
	m, _ := entry(t, "mdmplus").For("us")
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			io.WriteString(w, `{"access_token":"1000.abcdef.123456"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	h := route(t, map[string]*httptest.Server{m.Host: s,
		m.Auth.Token.Host: s})
	x, _ := NewSession(m, h, MapFunc{"zoho-client-id": "c",
		"zoho-client-secret": "s", "mdmplus-refresh-token": "r"}, noSleep)
	reads := x.All(context.Background(), []string{"apps"}, nil)
	var apps *Read
	for i := range reads {
		if reads[i].Endpoint == "apps" {
			apps = &reads[i]
		}
		if reads[i].Endpoint == "devices" && reads[i].Asked {
			t.Error("devices was read only for its records and is marked " +
				"as asked for")
		}
	}
	if apps == nil || apps.Err == nil ||
		!strings.Contains(apps.Err.Error(), "not read") {
		t.Errorf("apps after a failed device list: %+v", apps)
	}
}

func TestAChildOfATruncatedParentSaysSo(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/devices" {
			fmt.Fprint(w, `{"devices":[{"id":"1"},{"id":"2"}]}`)
			return
		}
		io.WriteString(w, `{"apps":[{"name":"x"}]}`)
	})
	m := mdmApps()
	m.Records = 1
	h := route(t, map[string]*httptest.Server{"mdm.example.com": s})
	x, _ := NewSession(m, h, MapFunc{"t": "k"}, noSleep)
	for _, r := range x.All(context.Background(), nil, nil) {
		if r.Endpoint == "apps" && r.Result.Complete() {
			t.Error("the apps of the first device read as the apps of the " +
				"estate")
		}
	}
}
