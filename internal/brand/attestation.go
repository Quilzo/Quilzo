// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package brand

// The two words a security attestation page is held to.
//
// "Compliant" and "certified" are the claims a trust page is most often
// caught out on: a SOC 2 report is an auditor's opinion on controls over a
// period, not a certificate, and no report makes anybody compliant with
// anything in general. Said about something nobody attested, either word is
// a claim the organisation cannot stand behind, and the first person who
// asks for the report finds out.
//
// So they follow this package's rule, the claim and its substantiation:
// "compliant" is sayable where an attestation the organisation holds backs
// it, and "certified" only where a certificate does, from a certification
// body, still in force. The public attestation page (internal/attest) sets
// those fields on the entries that carry them, so the words are allowed in
// an attestation's own description and refused anywhere else: in a policy's
// title, in the organisation's name, in a report that is not a certificate.

// AttestationNeeds and CertificateNeeds are the fields that back the two
// words: an attestation held, and a certificate in force.
const (
	AttestationNeeds = "attestation"
	CertificateNeeds = "certificate"
)

// AttestationRules are the rules the public attestation page is checked
// against, compiled.
func AttestationRules() *Rules {
	r := &Rules{Terms: []Term{
		{Match: "compliant", Needs: AttestationNeeds,
			Why: "compliance is a claim only an attestation can back, and this is not " +
				"part of one: say what is held, the report or the certificate, and let it speak"},
		{Match: "certified", Needs: CertificateNeeds,
			Why: "certified is said only of a certificate a certification body issued and " +
				"that is still in force; an auditor's report is not a certificate"},
	}}
	if err := r.Compile(); err != nil {
		panic("brand: the attestation rules do not compile: " + err.Error())
	}
	return r
}
