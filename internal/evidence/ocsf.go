// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/register"
)

// OCSF findings, as Prowler and the cloud providers' security hubs write
// them: OCSF 1.1 to 1.5, a JSON list of findings or one finding a line.
//
// A finding is a check run against a resource, and it becomes one fact:
// the check's result (pass, fail, manual) about the resource it was run
// against, read from Prowler's status_code or a Compliance Finding's own
// compliance status. The resource is an asset of the source, by its own
// identifier, an ARN or a resource ID.
//
// What a finding says about frameworks (Prowler's compliance table, a
// Compliance Finding's standards and requirements) is somebody else's
// mapping of their check to a clause. It is not the organisation's, so it
// is never written: each becomes a proposed Mapping, from the check as the
// tool's own requirement to the clause, waiting for a person to decide
// whether the check shows the clause is met.

func init() { readers[FormatOCSF] = readOCSF }

// The OCSF classes read as findings: Security Finding (2001, kept in 1.x
// for what still writes it), Compliance Finding (2003) and Detection
// Finding (2004).
var ocsfFindings = map[string]bool{"2001": true, "2003": true, "2004": true}

// mappingWhy is the rationale of every mapping a finding proposes. It is
// code's sentence and the same for all, so its digest is too.
const mappingWhy = "The tool that ran this check lists it against this clause in its own compliance table. " +
	"A person decides whether the check shows the clause is met."

func readOCSF(rd *reader) error {
	docs, err := jsonDocs(rd.in.Body)
	if err != nil {
		return err
	}
	skipped := 0
	for i, doc := range docs {
		place := "/" + strconv.Itoa(i)
		f := obj(doc)
		if f == nil {
			return fmt.Errorf("%w: %s is not an OCSF event", ErrUnreadable, place)
		}
		version := str(at(f, "metadata", "version"))
		if !ocsfVersion(version) {
			return fmt.Errorf("%w: %s is OCSF %q, and this reads OCSF 1.1 to 1.5", ErrUnreadable, place, label(version))
		}
		if !ocsfFindings[str(f["class_uid"])] {
			skipped++
			continue
		}
		if err := rd.ocsfFinding(f, place); err != nil {
			return err
		}
	}
	if skipped > 0 {
		rd.note("%d event(s) were not findings and were not read", skipped)
	}
	return nil
}

// ocsfVersion reports whether a schema version is one of 1.1 to 1.5.
func ocsfVersion(v string) bool {
	major, rest, ok := strings.Cut(v, ".")
	if !ok || major != "1" {
		return false
	}
	minor, _, _ := strings.Cut(rest, ".")
	n, err := strconv.Atoi(minor)
	return err == nil && n >= 1 && n <= 5
}

func (rd *reader) ocsfFinding(f map[string]any, place string) error {
	product := label(str(at(f, "metadata", "product", "name")))
	check := firstText(str(at(f, "metadata", "event_code")), str(at(f, "compliance", "control")),
		str(at(f, "finding_info", "title")))
	if check == "" {
		return fmt.Errorf("%w: the finding at %s names no check", ErrUnreadable, place)
	}
	status := ocsfStatus(f)
	about := []register.ID{}
	for j, r := range arr(f["resources"]) {
		res := obj(r)
		ref := firstText(str(res["uid"]), str(res["name"]))
		if ref == "" {
			continue
		}
		id, err := rd.asset("cloud-resource", ref, str(res["name"]), fmt.Sprintf("%s/resources/%d", place, j))
		if err != nil {
			return err
		}
		about = append(about, id)
	}
	if len(about) == 0 {
		account := str(at(f, "cloud", "account", "uid"))
		if account == "" {
			return fmt.Errorf("%w: the finding at %s is about no resource and no account", ErrUnreadable, place)
		}
		id, err := rd.asset("cloud-resource", account, "account "+account, place+"/cloud/account")
		if err != nil {
			return err
		}
		about = append(about, id)
	}
	fact := factName("check", check)
	for _, id := range about {
		if err := rd.observe(id, fact, register.TextValue(status), place+"/status_code", ""); err != nil {
			return err
		}
	}
	return rd.ocsfProposals(f, place, product, check)
}

// ocsfStatus is a finding's result, in lower case: Prowler's status_code,
// or a Compliance Finding's compliance status, or unknown.
func ocsfStatus(f map[string]any) string {
	if s := str(f["status_code"]); s != "" {
		return slug(s)
	}
	if s := str(at(f, "compliance", "status")); s != "" {
		return slug(s)
	}
	switch str(at(f, "compliance", "status_id")) {
	case "1":
		return "pass"
	case "2":
		return "warning"
	case "3":
		return "fail"
	}
	return "unknown"
}

// ocsfProposals proposes a mapping from the tool's check to each clause the
// finding lists it against.
func (rd *reader) ocsfProposals(f map[string]any, place, product, check string) error {
	type clause struct{ framework, ref string }
	var clauses []clause
	if table := obj(at(f, "unmapped", "compliance")); table != nil {
		for _, framework := range sortedKeys(table) {
			for _, ref := range arr(table[framework]) {
				clauses = append(clauses, clause{framework, str(ref)})
			}
		}
	}
	standards := arr(at(f, "compliance", "standards"))
	for _, r := range arr(at(f, "compliance", "requirements")) {
		req := str(r)
		if fw, ref, ok := strings.Cut(req, " "); ok {
			clauses = append(clauses, clause{fw, ref})
		} else if len(standards) == 1 {
			clauses = append(clauses, clause{str(standards[0]), req})
		} else {
			clauses = append(clauses, clause{"ocsf-requirements", req})
		}
	}
	if len(clauses) == 0 {
		return nil
	}
	tool := slug(firstText(product, "ocsf"))
	from := register.Requirement{Framework: tool, Ref: label(check),
		Title: label(firstText(str(at(f, "finding_info", "title")), check))}
	fromID, err := rd.propose(from, place, from.Title)
	if err != nil {
		return err
	}
	for _, c := range clauses {
		if strings.TrimSpace(c.ref) == "" {
			continue
		}
		to := register.Requirement{Framework: slug(c.framework), Ref: label(c.ref), Title: label(c.framework + " " + c.ref)}
		toID, err := rd.propose(to, place, to.Title)
		if err != nil {
			return err
		}
		if toID == fromID {
			continue
		}
		m := register.Mapping{From: fromID, To: toID, Relation: "intersects-with", Rationale: textDigest(mappingWhy)}
		if _, err := rd.propose(m, place, label(check+" to "+c.framework+" "+c.ref)); err != nil {
			return err
		}
	}
	return nil
}

// firstText is the first of its arguments that is not blank, trimmed.
func firstText(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// sortedKeys is an object's keys in order, so a file read twice is read
// the same way twice.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
