// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
)

// controlEvidence is evidence of one control on one occasion, recorded the
// way the assurance package records it.
func controlEvidence(control string, outcome assurance.Outcome) audit.Record {
	from := now.Add(-24 * time.Hour)
	return assurance.Evidence{
		Control: control, From: from, To: now, Outcome: outcome,
		What: "nightly backup restored to a scratch host", Source: "backup-job",
		Ref: "run-" + string(outcome), At: now, By: "dana", Kind: audit.KindHuman,
	}.Record()
}

// Evidence of a control streams to a SIEM as an OCSF Compliance Finding,
// class 2003, with the control's result in the compliance object, and not
// as API Activity.
//
// A control that failed is written to the audit log as a denial, so the log
// can be searched for the occasions something did not work. Filed as API
// Activity, that denial reached the SOC as an authorisation failure: a
// backup that did not restore looked like somebody refused a request, and
// it went to whoever triages access, not to whoever owns the control.
func TestControlEventIsComplianceFinding(t *testing.T) {
	events := log(t, nil,
		controlEvidence("backups", assurance.Operated),
		controlEvidence("backups", assurance.Failed),
		controlEvidence("backups", assurance.NotObserved),
	)
	res, err := Export(OCSF, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	recs := records(t, res.Body)
	if len(recs) != 3 {
		t.Fatalf("three events exported as %d records", len(recs))
	}
	want := []struct {
		action, status string
		statusID       float64
	}{
		{"control.operated", "Pass", 1},
		{"control.failed", "Fail", 3},
		// A check that could not tell: "did not yield a result due to
		// missing information", which is OCSF's Warning.
		{"control.not-observed", "Warning", 2},
	}
	for i, rec := range recs {
		w := want[i]
		if rec["activity_name"] != w.action {
			t.Fatalf("record %d is %v; want %s", i, rec["activity_name"], w.action)
		}
		if rec["class_uid"] != float64(classComplianceFinding) || rec["category_uid"] != float64(categoryFindings) {
			t.Errorf("%s is class %v in category %v; want Compliance Finding, 2003 in Findings, 2",
				w.action, rec["class_uid"], rec["category_uid"])
		}
		if rec["activity_id"] != float64(1) || rec["type_uid"] != float64(200301) {
			t.Errorf("%s is activity %v, type %v; want Create, 200301", w.action, rec["activity_id"], rec["type_uid"])
		}
		// A finding's status is its own lifecycle, and each record is a
		// new one; the result is the compliance object's.
		if rec["status_id"] != float64(1) || rec["status"] != "New" {
			t.Errorf("%s has finding status %v %v; want 1 New", w.action, rec["status_id"], rec["status"])
		}
		c, ok := rec["compliance"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no compliance object, which a Compliance Finding requires", w.action)
		}
		if c["control"] != "backups" || c["status_id"] != w.statusID || c["status"] != w.status {
			t.Errorf("%s says %v; want control backups, %v %s", w.action, c, w.statusID, w.status)
		}
		info, ok := rec["finding_info"].(map[string]any)
		if !ok || info["uid"] == nil || info["uid"] == "" || info["title"] == nil {
			t.Errorf("%s has no finding_info with a uid and a title, which a finding requires: %v", w.action, rec["finding_info"])
		}
		if _, ok := rec["api"]; ok {
			t.Errorf("%s still carries an API object, as though a request was made", w.action)
		}
		if rs, ok := rec["resources"].([]any); !ok || len(rs) != 1 || rs[0].(map[string]any)["type"] != "control" {
			t.Errorf("%s names its resource as %v", w.action, rec["resources"])
		}
		for _, required := range []string{"time", "severity_id", "metadata"} {
			if _, ok := rec[required]; !ok {
				t.Errorf("%s has no %s", w.action, required)
			}
		}
	}
	// The failure is raised above an informational record, as before.
	if recs[1]["severity_id"] != float64(3) || recs[0]["severity_id"] != float64(1) {
		t.Errorf("a failed control is severity %v and an operated one %v", recs[1]["severity_id"], recs[0]["severity_id"])
	}
	// And the chain still links: the next record's pointer back names the
	// class the record before it is filed under.
	att := recs[1]["attestation_list"].([]any)[0].(map[string]any)
	if prev := att["prev_event"].(map[string]any); prev["type_uid"] != float64(200301) {
		t.Errorf("the record after a Compliance Finding points back at type %v", prev["type_uid"])
	}
}

// A real denial is exported as it was: a refused request is API Activity,
// failed, at severity Medium, with the request it refused, and a refused
// sign-in is Authentication. Nothing but evidence of a control becomes a
// Compliance Finding.
func TestAuthDenialStillAPIActivity(t *testing.T) {
	events := log(t, nil,
		audit.Record{Action: "publish", Resource: "/legal", Outcome: audit.Denied,
			Principal: "kit", Kind: audit.KindHuman},
		audit.Record{Action: "signin.refused", Resource: "/admin", Outcome: audit.Denied,
			Principal: "kit", Kind: audit.KindHuman},
		audit.Record{Action: "token.issue", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true},
		controlEvidence("backups", assurance.Failed),
	)
	res, err := Export(OCSF, events, Options{}, now)
	if err != nil {
		t.Fatal(err)
	}
	recs := records(t, res.Body)
	publish, signin, token := recs[0], recs[1], recs[2]
	if publish["class_uid"] != float64(classAPIActivity) || publish["category_uid"] != float64(categoryApplication) ||
		publish["type_uid"] != float64(classAPIActivity*100+3) {
		t.Errorf("a refused publish is class %v, category %v, type %v; want API Activity",
			publish["class_uid"], publish["category_uid"], publish["type_uid"])
	}
	if publish["status_id"] != float64(2) || publish["status"] != "denied" || publish["severity_id"] != float64(3) {
		t.Errorf("a refused publish has status %v %v at severity %v; want 2 denied at 3",
			publish["status_id"], publish["status"], publish["severity_id"])
	}
	if api, ok := publish["api"].(map[string]any); !ok || api["operation"] != "publish" {
		t.Errorf("a refused publish lost the request it refused: %v", publish["api"])
	}
	if _, ok := publish["compliance"]; ok {
		t.Error("a refused publish carries a compliance object")
	}
	for _, rec := range []map[string]any{signin, token} {
		if rec["class_uid"] != float64(classAuthentication) || rec["category_uid"] != float64(categoryIAM) {
			t.Errorf("%v is class %v; want Authentication", rec["activity_name"], rec["class_uid"])
		}
	}
	if signin["status_id"] != float64(2) {
		t.Errorf("a refused sign-in has status %v", signin["status_id"])
	}
	if recs[3]["class_uid"] != float64(classComplianceFinding) {
		t.Errorf("control: the failed control beside them is class %v", recs[3]["class_uid"])
	}
}
