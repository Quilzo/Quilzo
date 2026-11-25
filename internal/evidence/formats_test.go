// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/register"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// factsOf is a batch's observations by their fact's name and the label of
// what they are about.
func factsOf(t testing.TB, b *Batch) map[string]register.Observation {
	t.Helper()
	labels := map[register.ID]string{}
	for _, rec := range b.Records {
		if a, ok := rec.(register.Asset); ok {
			id, _ := register.IDOf(a)
			labels[id] = a.Ref
		}
	}
	out := map[string]register.Observation{}
	for _, rec := range b.Records {
		if o, ok := rec.(register.Observation); ok {
			out[labels[o.About]+" "+o.Fact] = o
		}
	}
	return out
}

func value(o register.Observation) string { return o.Value.String() }

// Prowler's OCSF output from 1.1 to 1.3, and a security hub's Compliance
// Findings in 1.4 and 1.5 as JSON lines, all read to the same facts: each
// check's result about the resource it was run against. A version outside
// 1.1 to 1.5 is refused, not misread.
func TestOCSFVersionFixtures(t *testing.T) {
	for _, name := range []string{"prowler-1.1.0.json", "prowler-1.2.0.json", "prowler-1.3.0.json"} {
		b, err := Read(Input{Format: FormatOCSF, Body: fixture(t, "ocsf/"+name)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		f := factsOf(t, b)
		for k, want := range map[string]string{
			"arn:aws:iam::123456789012:root check.iam-root-mfa-enabled":                                       "pass",
			"arn:aws:s3:::evidence-bucket check.s3-bucket-public-access":                                      "fail",
			"arn:aws:cloudtrail:eu-west-2:123456789012:trail/org-trail check.cloudtrail-multi-region-enabled": "pass",
		} {
			if o, ok := f[k]; !ok || value(o) != want || o.Grade != register.GradeUploaded {
				t.Errorf("%s: %s reads %+v", name, k, o)
			}
		}
	}
	for _, name := range []string{"securityhub-1.4.0.jsonl", "securityhub-1.5.0.jsonl"} {
		b, err := Read(Input{Format: FormatOCSF, Body: fixture(t, "ocsf/"+name)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		f := factsOf(t, b)
		if o := f["arn:aws:s3:::evidence-bucket check.s3.1"]; value(o) != "fail" || o.Place != "/1/status_code" {
			t.Errorf("%s: S3.1 reads %+v", name, o)
		}
		if o := f["arn:aws:iam::123456789012:root check.iam.6"]; value(o) != "pass" {
			t.Errorf("%s: IAM.6 reads %+v", name, o)
		}
	}
	old := strings.Replace(string(fixture(t, "ocsf/prowler-1.1.0.json")), `"version": "1.1.0"`, `"version": "1.0.0-rc.3"`, 1)
	if _, err := Read(Input{Format: FormatOCSF, Body: []byte(old)}); err == nil || !strings.Contains(err.Error(), "1.1 to 1.5") {
		t.Errorf("OCSF 1.0 is read: %v", err)
	}
	future := strings.Replace(string(fixture(t, "ocsf/prowler-1.1.0.json")), `"version": "1.1.0"`, `"version": "1.6.0"`, 1)
	if _, err := Read(Input{Format: FormatOCSF, Body: []byte(future)}); err == nil {
		t.Error("OCSF 1.6 is read")
	}
}

// What Prowler's compliance table says (that its check covers a clause of
// CIS or ISO 27001) is a proposed mapping, never a mapping: it waits on the
// proposals ref for a person, and the register holds no Mapping and no
// Requirement after the import. A second import proposes nothing new.
func TestProwlerComplianceIsProposal(t *testing.T) {
	w := newWorld(t, false)
	res := w.ingest(t, person, Input{Format: FormatOCSF, Body: fixture(t, "ocsf/prowler-1.2.0.json")})
	if res.Proposed == nil || res.Proposed.Ref != register.ProposalsRef {
		t.Fatalf("the compliance table proposed nothing: %+v", res.Proposed)
	}
	counts, err := w.reg.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if counts[register.KindMapping] != 0 || counts[register.KindRequirement] != 0 {
		t.Fatalf("the import wrote %d mappings and %d requirements to the register", counts[register.KindMapping], counts[register.KindRequirement])
	}
	props, err := w.reg.Proposals()
	if err != nil {
		t.Fatal(err)
	}
	var mappings []string
	for _, p := range props {
		if p.Agent != Clerk {
			t.Errorf("a proposal is made by %q, not the evidence clerk", p.Agent)
		}
		if m, ok := p.Record.(register.Mapping); ok {
			to, _ := w.reg.Proposals()
			_ = to
			mappings = append(mappings, string(m.Relation))
		}
	}
	// iam_root_mfa_enabled maps to CIS 1.5 and ISO A.9.4, and the bucket's
	// check to CIS 2.1.4: three mappings, each only "intersects-with".
	if len(mappings) != 3 || slices.ContainsFunc(mappings, func(s string) bool { return s != "intersects-with" }) {
		t.Errorf("the proposed mappings are %v", mappings)
	}
	again := w.ingest(t, person, Input{Format: FormatOCSF, Body: fixture(t, "ocsf/prowler-1.2.0.json")})
	if again.Proposed != nil || again.Receipt.Commit != "" {
		t.Errorf("a second import wrote %q and proposed %+v", again.Receipt.Commit, again.Proposed)
	}
}

// A CycloneDX bill's software and every component in it, nested ones too,
// are assets by their package URLs, each with its version, its licence and
// what it is part of; the bill's VEX statements are facts about the
// components they name.
func TestCycloneDXComponents(t *testing.T) {
	b, err := Read(Input{Format: FormatCycloneDX, Body: fixture(t, "cyclonedx/bom-1.5.json")})
	if err != nil {
		t.Fatal(err)
	}
	f := factsOf(t, b)
	app := "pkg:github/example/payments-api@2.3.1"
	appID, _ := register.IDOf(register.Asset{Source: b.SourceID, Ref: app, Type: "application"})
	for k, want := range map[string]string{
		app + " sbom.components":                                     "4",
		"pkg:npm/lodash@4.17.21 component.version":                   "4.17.21",
		"pkg:npm/lodash@4.17.21 component.licence":                   "MIT",
		"pkg:npm/lodash@4.17.21 component.part-of":                   string(appID),
		"pkg:golang/golang.org/x/crypto@v0.31.0 component.licence":   "BSD-3-Clause",
		"pkg:golang/golang.org/x/sys@v0.28.0 component.version":      "v0.28.0",
		"distroless/static@nonroot component.version":                "nonroot",
		"pkg:npm/lodash@4.17.21 vuln.cve-2021-23337":                 "not_affected",
		"pkg:golang/golang.org/x/crypto@v0.31.0 vuln.cve-2024-45337": "resolved",
	} {
		if o, ok := f[k]; !ok || value(o) != want {
			t.Errorf("%s reads %q, not %q", k, value(o), want)
		}
	}
	if o := f["pkg:golang/golang.org/x/sys@v0.28.0 component.version"]; o.Place != "/components/1/components/0/version" {
		t.Errorf("the nested component is read at %q", o.Place)
	}
	if _, err := Read(Input{Format: FormatCycloneDX, Body: []byte(`{"bomFormat":"CycloneDX","specVersion":"2.0"}`)}); err == nil {
		t.Error("a CycloneDX version nobody has written is read")
	}
}

// An SPDX 2.3 document's packages are read as a CycloneDX bill's
// components are, with the described package as the software; SPDX 3 is
// refused, not misread.
func TestSPDXPackages(t *testing.T) {
	b, err := Read(Input{Format: FormatSPDX, Body: fixture(t, "spdx/sbom-2.3.json")})
	if err != nil {
		t.Fatal(err)
	}
	f := factsOf(t, b)
	for k, want := range map[string]string{
		"pkg:github/example/payments-api@2.3.1 sbom.components": "2",
		"pkg:npm/lodash@4.17.21 component.licence":              "MIT",
		"openssl@3.0.15 component.version":                      "3.0.15",
	} {
		if o, ok := f[k]; !ok || value(o) != want {
			t.Errorf("%s reads %q, not %q", k, value(o), want)
		}
	}
	if _, err := Read(Input{Format: FormatSPDX, Body: []byte(`{"@context":"https://spdx.org/rdf/3.0.0/spdx-context.jsonld","@graph":[]}`)}); err == nil {
		t.Error("an SPDX 3 document is read")
	}
}

// A SARIF log's results are counts about the repository scanned, across its
// runs: open findings, findings by rule, by severity and by kind, and what
// was suppressed in the source. A severity is the tool's security-severity
// where it gave one, and its level only where it did not, which is said.
func TestSARIFResults(t *testing.T) {
	b, err := Read(Input{Format: FormatSARIF, Body: fixture(t, "sarif/scan.sarif")})
	if err != nil {
		t.Fatal(err)
	}
	f := factsOf(t, b)
	repo := "https://github.com/example/payments-api"
	for k, want := range map[string]string{
		repo + " code.findings":                                   "3",
		repo + " code.findings.suppressed":                        "1",
		repo + " code.rule.go.lang.security.audit.dangerous-exec": "2",
		repo + " code.rule.go-sql-injection":                      "1",
		// The rule's 8.6 is high twice over; CodeQL's result gives no
		// severity and no level, so it is low, and the suppressed key is
		// not counted at all.
		repo + " code.findings.critical": "0",
		repo + " code.findings.high":     "2",
		repo + " code.findings.medium":   "0",
		repo + " code.findings.low":      "1",
		repo + " code.kind.weakness":     "3",
	} {
		if o, ok := f[k]; !ok || value(o) != want {
			t.Errorf("%s reads %q, not %q", k, value(o), want)
		}
	}
	if _, ok := f[repo+" code.kind.secret"]; ok {
		t.Errorf("a suppressed secret is counted as an open one")
	}
	for _, want := range []string{"primaryLocationLineHash", "security-severity"} {
		if !slices.ContainsFunc(b.Notes, func(n string) bool { return strings.Contains(n, want) }) {
			t.Errorf("no note says a result has no %s: %v", want, b.Notes)
		}
	}
}

// A CSAF advisory's and a CSAF VEX document's product statuses, and an
// OpenVEX document's statements, are facts about the products they name.
func TestCSAFAndVEXStatus(t *testing.T) {
	adv, err := Read(Input{Format: FormatCSAF, Body: fixture(t, "csaf/advisory.json")})
	if err != nil {
		t.Fatal(err)
	}
	f := factsOf(t, adv)
	for k, want := range map[string]string{
		"pkg:generic/example/gateway@4.1 vuln.cve-2026-1001": "affected",
		"Example Gateway 4.2 vuln.cve-2026-1001":             "fixed",
		"Example Gateway 4.2 vuln.exa-vuln-7":                "under_investigation",
	} {
		if o, ok := f[k]; !ok || value(o) != want {
			t.Errorf("advisory: %s reads %q, not %q", k, value(o), want)
		}
	}
	vex, err := Read(Input{Format: FormatCSAF, Body: fixture(t, "csaf/vex.json")})
	if err != nil {
		t.Fatal(err)
	}
	if o := factsOf(t, vex)["pkg:generic/example/gateway@4.1 vuln.cve-2026-1001"]; value(o) != "not_affected" {
		t.Errorf("CSAF VEX reads %+v", o)
	}
	open, err := Read(Input{Format: FormatOpenVEX, Body: fixture(t, "openvex/vex.json")})
	if err != nil {
		t.Fatal(err)
	}
	g := factsOf(t, open)
	if value(g["pkg:npm/lodash@4.17.21 vuln.cve-2021-23337"]) != "not_affected" ||
		value(g["pkg:golang/golang.org/x/crypto@v0.31.0 vuln.cve-2024-45337"]) != "fixed" {
		t.Errorf("OpenVEX reads %v", g)
	}
	if _, err := Read(Input{Format: FormatCSAF, Body: []byte(`{"document":{"csaf_version":"1.2"}}`)}); err == nil {
		t.Error("a CSAF version other than 2.0 is read")
	}
}

// osquery's result log, differential and snapshot alike, and a Fleet query
// report become facts about each host: a column each for a query that
// returned one row, and a count for one that returned several. A row the
// log says was removed is not read.
func TestOsqueryAndFleetResults(t *testing.T) {
	b, err := Read(Input{Format: FormatOsquery, Body: fixture(t, "osquery/results.log")})
	if err != nil {
		t.Fatal(err)
	}
	f := factsOf(t, b)
	for k, want := range map[string]string{
		"mac-01.example.internal osquery.pack-posture-disk-encryption.encrypted": "1",
		"mac-02.example.internal osquery.pack-posture-disk-encryption.encrypted": "0",
		"mac-01.example.internal osquery.pack-posture-firewall.global-state":     "1",
		"mac-01.example.internal osquery.pack-inventory-apps.rows":               "3",
	} {
		if o, ok := f[k]; !ok || value(o) != want {
			t.Errorf("%s reads %q, not %q", k, value(o), want)
		}
	}
	for k := range f {
		if strings.HasPrefix(k, "mac-03") {
			t.Errorf("a removed row was read: %s", k)
		}
	}
	fl, err := Read(Input{Format: FormatOsquery, Body: fixture(t, "osquery/fleet-report.json")})
	if err != nil {
		t.Fatal(err)
	}
	g := factsOf(t, fl)
	if value(g["mac-02.example.internal osquery.fleet-query-31.enabled"]) != "0" ||
		value(g["mac-01.example.internal osquery.fleet-query-31.version"]) != "14.6" {
		t.Errorf("the Fleet report reads %v", g)
	}
}

// signed is a DSSE envelope over an in-toto statement whose predicate is
// the CycloneDX fixture, signed by sign.
func signed(t testing.TB, sign func([]byte) []byte, keyid string) []byte {
	t.Helper()
	var bom any
	if err := json.Unmarshal(fixture(t, "cyclonedx/bom-1.5.json"), &bom); err != nil {
		t.Fatal(err)
	}
	st, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": "payments-api.tar.gz", "digest": map[string]any{"sha256": strings.Repeat("ab", 32)}}},
		"predicateType": "https://cyclonedx.org/bom", "predicate": bom})
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json",
		"payload":    base64.StdEncoding.EncodeToString(st),
		"signatures": []any{map[string]any{"keyid": keyid, "sig": base64.StdEncoding.EncodeToString(sign(pae("application/vnd.in-toto+json", st)))}}})
	return env
}

func pinned(t testing.TB, name string, pub any) register.PinnedKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	k, err := PinKey(name, "the build service", "", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), day0)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A DSSE envelope signed by a key a person pinned is read, Ed25519 or ECDSA,
// and everything in it is graded signed, the statement's subject and the
// bill of materials in its predicate alike; the seal's record names the key.
func TestDSSEPinnedVerifies(t *testing.T) {
	seed := sha256.Sum256([]byte("a fixed seed for a test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		pub  any
		sign func([]byte) []byte
	}{
		"ed25519": {priv.Public(), func(m []byte) []byte { return ed25519.Sign(priv, m) }},
		"ecdsa":   {&ec.PublicKey, func(m []byte) []byte { h := sha256.Sum256(m); s, _ := ecdsa.SignASN1(rand.Reader, ec, h[:]); return s }},
	} {
		w := newWorld(t, false)
		key := pinned(t, "build-"+name, tc.pub)
		if _, err := w.reg.Put(person, "a key, pinned", key); err != nil {
			t.Fatal(err)
		}
		in := Input{Format: FormatDSSE, Body: signed(t, tc.sign, "")}
		if err := w.g.Prepare(&in, ""); err != nil {
			t.Fatal(err)
		}
		res := w.ingest(t, person, in)
		if res.Batch.Grade != register.GradeSigned || res.Batch.Raw.Signer != key.Name {
			t.Fatalf("%s: graded %s, signed by %q", name, res.Batch.Grade, res.Batch.Raw.Signer)
		}
		f := factsOf(t, res.Batch)
		if o := f["payments-api.tar.gz attestation.cyclonedx.org-bom"]; value(o) != "true" || o.Grade != register.GradeSigned {
			t.Errorf("%s: the statement's subject reads %+v", name, o)
		}
		if o := f["pkg:npm/lodash@4.17.21 component.version"]; value(o) != "4.17.21" || o.Grade != register.GradeSigned ||
			!strings.HasPrefix(o.Place, "/payload/predicate/components/") {
			t.Errorf("%s: the signed bill's component reads %+v", name, o)
		}
		for _, o := range observations(t, w.reg) {
			if o.Grade != register.GradeSigned {
				t.Errorf("%s: %s is graded %s", name, o.Fact, o.Grade)
			}
		}
	}
}

// An envelope no pinned key verifies is refused, and nothing in it is read
// or written: with no key pinned, with another key pinned, with the
// signer's key brought inside the file, and with its payload changed after
// signing.
func TestDSSEUnpinnedRefused(t *testing.T) {
	seed := sha256.Sum256([]byte("a fixed seed for a test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	sign := func(m []byte) []byte { return ed25519.Sign(priv, m) }
	env := signed(t, sign, "")

	w := newWorld(t, false)
	if _, err := w.g.Ingest(person, "", Input{Format: FormatDSSE, Body: env}); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("with no key pinned: %v", err)
	}
	if _, err := w.reg.Put(person, "another key, pinned", pinned(t, "someone-else", other.Public())); err != nil {
		t.Fatal(err)
	}
	in := Input{Format: FormatDSSE, Body: env}
	if err := w.g.Prepare(&in, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := w.g.Ingest(person, "", in); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("with another key pinned: %v", err)
	}
	counts, _ := w.reg.Counts()
	if counts[register.KindObservation] != 0 || counts[register.KindRawFile] != 0 {
		t.Fatalf("an unverified envelope wrote %d observations", counts[register.KindObservation])
	}

	// The right key pinned, and the payload changed after it was signed.
	if _, err := w.reg.Put(person, "the build key, pinned", pinned(t, "build", priv.Public())); err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	json.Unmarshal(env, &e)
	payload, _ := base64.StdEncoding.DecodeString(e["payload"].(string))
	e["payload"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(payload), "4.17.21", "4.17.22", 1)))
	tampered, _ := json.Marshal(e)
	in = Input{Format: FormatDSSE, Body: tampered}
	w.g.Prepare(&in, "")
	if _, err := w.g.Ingest(person, "", in); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("a payload changed after signing: %v", err)
	}

	// A pinned key whose record was changed beside its fingerprint is no
	// key at all.
	k := pinned(t, "build", priv.Public())
	k.Public = base64.StdEncoding.EncodeToString(mustDER(t, other.Public()))
	if _, err := Read(Input{Format: FormatDSSE, Body: env, Keys: []register.PinnedKey{k}}); !errors.Is(err, ErrUnpinned) {
		t.Fatalf("a pinned key that does not match its fingerprint: %v", err)
	}
}

func mustDER(t testing.TB, pub any) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Whatever bytes arrive in whatever format, a reader answers or refuses: it
// does not panic.
func FuzzReaders(f *testing.F) {
	for _, name := range []string{"ocsf/prowler-1.1.0.json", "cyclonedx/bom-1.5.json", "spdx/sbom-2.3.json", "sarif/scan.sarif",
		"csaf/advisory.json", "openvex/vex.json", "osquery/results.log"} {
		f.Add(fixture(f, name))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, format := range []Format{FormatOCSF, FormatCycloneDX, FormatSPDX, FormatSARIF, FormatCSAF, FormatOpenVEX,
			FormatOsquery, FormatDSSE} {
			_, _ = Read(Input{Format: format, Body: b})
		}
	})
}
