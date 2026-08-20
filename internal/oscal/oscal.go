// Package oscal renders a posture scan as machine-readable assessment evidence.
//
// # Why this exists, and why now
//
// FedRAMP 20x replaced point-in-time documents with continuous, machine-checked
// validation against a running system, and the Consolidated Rules for 2026
// (finalised 25 June 2026) set a deadline: new authorisation packages must
// include OSCAL outputs from 30 September 2026. The bar for automated evidence
// is at least 70%.
//
// That is a description of what `quilzo posture` already does. It reads this
// deployment rather than a questionnaire, every rule already names the NIST
// SP 800-53 controls it bears on, and the result is a structured finding with a
// severity and a resource. What was missing was the format an assessor's
// tooling can ingest.
//
// So this is a serialiser, not an architecture. The evidence was already being
// produced; it was being printed for a person.
//
// # What this is not
//
// It is not a certification, an authorisation, or a claim that a deployment
// passes anything. OSCAL assessment results are the output of an assessment —
// they say what was checked and what was found, and an empty findings list
// means the checks this program knows how to run did not fail, not that the
// system is compliant. That distinction is stated in the document itself,
// because a machine-readable artefact travels further than the conversation
// that produced it.
//
// # Shape
//
// OSCAL 1.2.3, JSON. The required fields are exactly:
//
//	assessment-results  uuid, metadata, import-ap, results
//	metadata            title, last-modified, version, oscal-version
//	result              uuid, title, description, start, reviewed-controls
//	observation         uuid, description, methods, collected
//	finding             uuid, title, description, target
//	finding-target      type, target-id, status{state}
//
// Read from the published schema rather than from an example, because an
// example shows one valid document and the schema shows which parts of it were
// load-bearing.
package oscal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/posture"
)

// Version is the OSCAL release this document conforms to.
const Version = "1.2.3"

// Results is the root object.
//
// Nested under a single key, because that is how the schema is written: the
// document's own required list is ["assessment-results"], and a flat object
// fails validation before anything inside it is read.
type Results struct {
	AssessmentResults Body `json:"assessment-results"`
}

// Body is the assessment-results object.
type Body struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	ImportAP ImportAP `json:"import-ap"`
	Results  []Result `json:"results"`
}

// Metadata is the block every OSCAL document carries.
type Metadata struct {
	Title        string  `json:"title"`
	LastModified string  `json:"last-modified"`
	Version      string  `json:"version"`
	OSCALVersion string  `json:"oscal-version"`
	Parties      []Party `json:"parties,omitempty"`
	Remarks      string  `json:"remarks,omitempty"`
}

// Party is who produced this.
type Party struct {
	UUID string `json:"uuid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// ImportAP points at the assessment plan this executes.
//
// Required by the schema and frequently a lie in the wild: a results document
// that imports a plan nobody wrote is a document claiming an assessment that
// was never designed. The href here names the tool's own rule set, which is
// honest — the plan is "run these 28 checks" and it is in the source.
type ImportAP struct {
	Href    string `json:"href"`
	Remarks string `json:"remarks,omitempty"`
}

// Result is one assessment run.
type Result struct {
	UUID             string           `json:"uuid"`
	Title            string           `json:"title"`
	Description      string           `json:"description"`
	Start            string           `json:"start"`
	End              string           `json:"end,omitempty"`
	ReviewedControls ReviewedControls `json:"reviewed-controls"`
	Observations     []Observation    `json:"observations,omitempty"`
	Findings         []Finding        `json:"findings,omitempty"`
}

// ReviewedControls says which controls were in scope.
//
// This is the field that makes the document useful to an assessor and the one
// most often overstated. It lists the controls the rules actually bear on —
// 35 of them — and not the whole baseline, because claiming to have reviewed
// a control nobody checked is the failure mode that makes automated evidence
// worthless.
type ReviewedControls struct {
	ControlSelections []ControlSelection `json:"control-selections"`
}

type ControlSelection struct {
	Description     string       `json:"description,omitempty"`
	IncludeControls []ControlRef `json:"include-controls,omitempty"`
}

type ControlRef struct {
	ControlID string `json:"control-id"`
}

// Observation is a thing that was looked at.
type Observation struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description"`
	Methods     []string `json:"methods"`
	Collected   string   `json:"collected"`
	Remarks     string   `json:"remarks,omitempty"`
}

// Finding is a control objective that was or was not satisfied.
type Finding struct {
	UUID        string        `json:"uuid"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Target      FindingTarget `json:"target"`
	Remarks     string        `json:"remarks,omitempty"`
}

// FindingTarget names what the finding is about.
type FindingTarget struct {
	// "objective-id" or "statement-id" — the only two the schema allows.
	Type     string `json:"type"`
	TargetID string `json:"target-id"`
	Status   Status `json:"status"`
}

// Status is satisfied or not-satisfied. There is no third value in OSCAL, and
// a scanner that wants to say "probably" has to pick one.
type Status struct {
	State   string `json:"state"`
	Remarks string `json:"remarks,omitempty"`
}

// Observation methods, from the schema's enum.
const (
	MethodExamine = "EXAMINE"
	MethodTest    = "TEST"
)

// Options are what the deployment knows and the scan does not.
type Options struct {
	// System is what is being assessed.
	System string
	// Organisation is who runs it.
	Organisation string
	// Version is the build that produced the evidence.
	Version string
	// RulesHref points at the rule set this executed.
	RulesHref string
}

// From renders a posture scan as OSCAL assessment results.
//
// Every finding the scan produced becomes both an observation — this was
// looked at, here is what was seen — and one finding per control the rule bears
// on. One rule touching three controls produces three findings, because an
// assessor reads by control and a single finding referencing three would be
// invisible under two of them.
func From(findings []posture.Finding, rules map[string]posture.Rule,
	at time.Time, o Options) (Results, error) {

	stamp := at.UTC().Format(time.RFC3339)

	docUUID, err := newUUID()
	if err != nil {
		return Results{}, err
	}
	resultUUID, err := newUUID()
	if err != nil {
		return Results{}, err
	}
	partyUUID, err := newUUID()
	if err != nil {
		return Results{}, err
	}

	system := nonEmpty(o.System, "a Quilzo deployment")
	body := Body{
		UUID: docUUID,
		Metadata: Metadata{
			Title:        "Automated security posture assessment of " + system,
			LastModified: stamp,
			Version:      nonEmpty(o.Version, "dev"),
			OSCALVersion: Version,
			Parties: []Party{{
				UUID: partyUUID, Type: "organization",
				Name: nonEmpty(o.Organisation, system),
			}},
			Remarks: "Produced by `quilzo posture`, which reads this " +
				"deployment rather than a questionnaire. These are assessment " +
				"results: they record what was checked and what was found. " +
				"An empty findings list means the checks this program knows " +
				"how to run did not fail — it is not a certification and not " +
				"a claim that the system is compliant.",
		},
		ImportAP: ImportAP{
			Href: nonEmpty(o.RulesHref,
				"https://github.com/Quilzo/Quilzo/blob/main/internal/posture/rules.go"),
			Remarks: "The assessment plan is the rule set in the source. " +
				"Named rather than pointed at a document nobody wrote, which " +
				"is what this field usually contains.",
		},
	}

	// Controls actually reviewed, from the rules that ran.
	seen := map[string]bool{}
	for _, r := range rules {
		for _, c := range r.Controls {
			seen[c] = true
		}
	}
	controls := make([]ControlRef, 0, len(seen))
	for c := range seen {
		controls = append(controls, ControlRef{ControlID: strings.ToLower(c)})
	}
	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ControlID < controls[j].ControlID
	})

	res := Result{
		UUID:  resultUUID,
		Title: "Posture scan",
		Description: fmt.Sprintf(
			"%d automated checks against the running deployment, mapped to "+
				"%d NIST SP 800-53 controls.", len(rules), len(controls)),
		Start: stamp,
		End:   stamp,
		ReviewedControls: ReviewedControls{
			ControlSelections: []ControlSelection{{
				Description: "Controls the automated checks bear on. Not the " +
					"whole baseline: claiming to have reviewed a control " +
					"nothing checked is what makes automated evidence " +
					"worthless.",
				IncludeControls: controls,
			}},
		},
	}

	// Deterministic order, so two runs over the same store produce documents
	// that diff cleanly. An assessor comparing this month against last month
	// should see what changed, not a reshuffle.
	sorted := append([]posture.Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Rule != sorted[j].Rule {
			return sorted[i].Rule < sorted[j].Rule
		}
		return sorted[i].Resource < sorted[j].Resource
	})

	for _, f := range sorted {
		obsUUID, uerr := newUUID()
		if uerr != nil {
			return Results{}, uerr
		}
		rule := rules[f.Rule]
		res.Observations = append(res.Observations, Observation{
			UUID:  obsUUID,
			Title: f.Title,
			Description: fmt.Sprintf("%s\n\n%s", f.Detail,
				nonEmpty(rule.Why, "")),
			// TEST, not EXAMINE: the check ran against the live deployment
			// rather than reading a document about it. That distinction is
			// what 20x is asking for, and overstating it in the other
			// direction would be claiming a document review as a test.
			Methods:   []string{MethodTest},
			Collected: stamp,
			Remarks:   "resource: " + nonEmpty(f.Resource, "the deployment"),
		})

		for _, control := range rule.Controls {
			fUUID, ferr := newUUID()
			if ferr != nil {
				return Results{}, ferr
			}
			res.Findings = append(res.Findings, Finding{
				UUID:        fUUID,
				Title:       f.Title,
				Description: f.Detail,
				Target: FindingTarget{
					Type:     "objective-id",
					TargetID: strings.ToLower(control),
					// OSCAL has two states and no third. A finding exists
					// because a check failed, so it is not-satisfied; a check
					// that passed produces no finding and therefore no claim.
					Status: Status{State: "not-satisfied", Remarks: string(f.Severity)},
				},
				Remarks: nonEmpty(rule.Why, ""),
			})
		}
	}

	body.Results = []Result{res}
	return Results{AssessmentResults: body}, nil
}

// newUUID makes a version-4 UUID.
//
// Written out rather than imported: OSCAL requires UUIDs everywhere and this
// project has no require block. Sixteen random bytes with the version and
// variant nibbles set, which is the whole of RFC 4122 section 4.4.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
