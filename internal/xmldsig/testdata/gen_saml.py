# SPDX-FileCopyrightText: 2026 rsh1k
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

"""Writes testdata/saml: SAML responses shaped the way five identity
providers shape theirs, signed by the JDK's XML Signature implementation
(sign/Sign.java), plus the certificates that verify them.

The private keys are made in a temporary directory and deleted: only
certificates are kept, so nothing in the repository can sign. Regenerating
therefore changes every signature, which is fine; the tests read the
manifest rather than assuming one.

    python3 internal/xmldsig/testdata/gen_saml.py
"""

import json
import os
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "saml")
KEYS = os.path.join(HERE, "keys")
SIGN = os.path.join(HERE, "sign", "Sign.java")

REQ = "_4f2a9c1e7b3d5a6f8e0c2b4d6a8f0e1c"
T = "2026-10-03T12:00:00.123Z"
BEFORE = "2026-10-03T11:55:00.123Z"
AFTER = "2026-10-03T12:05:00.123Z"
AUTHN = "2026-10-03T11:59:58.000Z"
SESSION_END = "2026-10-03T20:00:00.000Z"

P = "urn:oasis:names:tc:SAML:2.0:protocol"
A = "urn:oasis:names:tc:SAML:2.0:assertion"
XS = "http://www.w3.org/2001/XMLSchema"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"


def sp(idp):
    return "https://quilzo.example/saml/" + idp, "https://quilzo.example/saml/" + idp + "/acs"


def okta(rid, aid):
    """saml2p/saml2, declarations on each element, xs:string values."""
    ent, acs = sp("okta")
    iss = "http://www.okta.com/exk8northwind"
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="{P}" Destination="{acs}" '
        f'ID="{rid}" InResponseTo="{REQ}" IssueInstant="{T}" Version="2.0" xmlns:xs="{XS}">'
        f'<saml2:Issuer xmlns:saml2="{A}" Format="{ENTITY}">{iss}</saml2:Issuer>'
        f'<saml2p:Status xmlns:saml2p="{P}"><saml2p:StatusCode Value="{SUCCESS}"/></saml2p:Status>'
        f'<saml2:Assertion xmlns:saml2="{A}" ID="{aid}" IssueInstant="{T}" Version="2.0" xmlns:xs="{XS}">'
        f'<saml2:Issuer Format="{ENTITY}">{iss}</saml2:Issuer>'
        f'<saml2:Subject><saml2:NameID Format="{EMAIL}">hana.sato@northwind.example</saml2:NameID>'
        f'<saml2:SubjectConfirmation Method="{BEARER}"><saml2:SubjectConfirmationData InResponseTo="{REQ}" '
        f'NotOnOrAfter="{AFTER}" Recipient="{acs}"/></saml2:SubjectConfirmation></saml2:Subject>'
        f'<saml2:Conditions NotBefore="{BEFORE}" NotOnOrAfter="{AFTER}"><saml2:AudienceRestriction>'
        f'<saml2:Audience>{ent}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>'
        f'<saml2:AuthnStatement AuthnInstant="{AUTHN}" SessionIndex="{aid}" SessionNotOnOrAfter="{SESSION_END}">'
        f'<saml2:AuthnContext><saml2:AuthnContextClassRef>'
        f'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        f'</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement>'
        f'<saml2:AttributeStatement>'
        f'<saml2:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">'
        f'<saml2:AttributeValue xmlns:xsi="{XSI}" xsi:type="xs:string">hana.sato@northwind.example'
        f'</saml2:AttributeValue></saml2:Attribute>'
        f'<saml2:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">'
        f'<saml2:AttributeValue xmlns:xsi="{XSI}" xsi:type="xs:string">Security &amp; Risk</saml2:AttributeValue>'
        f'<saml2:AttributeValue xmlns:xsi="{XSI}" xsi:type="xs:string">Everyone</saml2:AttributeValue>'
        f'</saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>'
    )


def entra(rid, aid):
    """Default namespace on Issuer and Assertion, as Entra ID and ADFS write."""
    ent, acs = sp("entra")
    iss = "https://sts.windows.net/9b1c0d2e-0000-4000-8000-000000000001/"
    return (
        f'<samlp:Response ID="{rid}" Version="2.0" IssueInstant="{T}" Destination="{acs}" '
        f'InResponseTo="{REQ}" xmlns:samlp="{P}"><Issuer xmlns="{A}">{iss}</Issuer>'
        f'<samlp:Status><samlp:StatusCode Value="{SUCCESS}"/></samlp:Status>'
        f'<Assertion ID="{aid}" IssueInstant="{T}" Version="2.0" xmlns="{A}"><Issuer>{iss}</Issuer>'
        f'<Subject><NameID Format="{EMAIL}">sam.rivera@northwind.example</NameID>'
        f'<SubjectConfirmation Method="{BEARER}"><SubjectConfirmationData InResponseTo="{REQ}" '
        f'NotOnOrAfter="{AFTER}" Recipient="{acs}"/></SubjectConfirmation></Subject>'
        f'<Conditions NotBefore="{BEFORE}" NotOnOrAfter="{AFTER}"><AudienceRestriction>'
        f'<Audience>{ent}</Audience></AudienceRestriction></Conditions>'
        f'<AttributeStatement>'
        f'<Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid">'
        f'<AttributeValue>9b1c0d2e-0000-4000-8000-000000000001</AttributeValue></Attribute>'
        f'<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">'
        f'<AttributeValue>sam.rivera@northwind.example</AttributeValue></Attribute>'
        f'<Attribute Name="http://schemas.microsoft.com/claims/authnmethodsreferences">'
        f'<AttributeValue>http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password</AttributeValue>'
        f'<AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</AttributeValue></Attribute>'
        f'</AttributeStatement>'
        f'<AuthnStatement AuthnInstant="{AUTHN}" SessionIndex="{aid}"><AuthnContext>'
        f'<AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>'
        f'</AuthnContext></AuthnStatement></Assertion></samlp:Response>'
    )


def keycloak(rid, aid):
    """samlp and saml declared once on the root, with indentation."""
    ent, acs = sp("keycloak")
    iss = "https://id.northwind.example/realms/staff"
    return (
        f'<samlp:Response xmlns:samlp="{P}" xmlns:saml="{A}" Destination="{acs}" ID="{rid}" '
        f'InResponseTo="{REQ}" IssueInstant="{T}" Version="2.0">\n'
        f'  <saml:Issuer>{iss}</saml:Issuer>\n'
        f'  <samlp:Status>\n    <samlp:StatusCode Value="{SUCCESS}"/>\n  </samlp:Status>\n'
        f'  <saml:Assertion ID="{aid}" IssueInstant="{T}" Version="2.0">\n'
        f'    <saml:Issuer>{iss}</saml:Issuer>\n'
        f'    <saml:Subject>\n'
        f'      <saml:NameID Format="{EMAIL}">dana.reyes@northwind.example</saml:NameID>\n'
        f'      <saml:SubjectConfirmation Method="{BEARER}">\n'
        f'        <saml:SubjectConfirmationData InResponseTo="{REQ}" NotOnOrAfter="{AFTER}" Recipient="{acs}"/>\n'
        f'      </saml:SubjectConfirmation>\n'
        f'    </saml:Subject>\n'
        f'    <saml:Conditions NotBefore="{BEFORE}" NotOnOrAfter="{AFTER}">\n'
        f'      <saml:AudienceRestriction>\n        <saml:Audience>{ent}</saml:Audience>\n'
        f'      </saml:AudienceRestriction>\n    </saml:Conditions>\n'
        f'    <saml:AuthnStatement AuthnInstant="{AUTHN}" SessionIndex="s1" SessionNotOnOrAfter="{SESSION_END}">\n'
        f'      <saml:AuthnContext>\n'
        f'        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>\n'
        f'      </saml:AuthnContext>\n    </saml:AuthnStatement>\n'
        f'    <saml:AttributeStatement>\n'
        f'      <saml:Attribute FriendlyName="Role" Name="Role" '
        f'NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">\n'
        f'        <saml:AttributeValue xmlns:xs="{XS}" xmlns:xsi="{XSI}" xsi:type="xs:string">analyst</saml:AttributeValue>\n'
        f'      </saml:Attribute>\n    </saml:AttributeStatement>\n'
        f'  </saml:Assertion>\n</samlp:Response>\n'
    )


def google(rid, aid):
    """saml2p/saml2 on the root; the NameID is the primary address."""
    ent, acs = sp("google")
    iss = "https://accounts.google.com/o/saml2?idpid=C01northwind"
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="no"?><saml2p:Response xmlns:saml2p="{P}" '
        f'Destination="{acs}" ID="{rid}" InResponseTo="{REQ}" IssueInstant="{T}" Version="2.0">'
        f'<saml2:Issuer xmlns:saml2="{A}">{iss}</saml2:Issuer>'
        f'<saml2p:Status><saml2p:StatusCode Value="{SUCCESS}"/></saml2p:Status>'
        f'<saml2:Assertion xmlns:saml2="{A}" ID="{aid}" IssueInstant="{T}" Version="2.0">'
        f'<saml2:Issuer>{iss}</saml2:Issuer><saml2:Subject>'
        f'<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">nia.adeyemi@northwind.example</saml2:NameID>'
        f'<saml2:SubjectConfirmation Method="{BEARER}"><saml2:SubjectConfirmationData InResponseTo="{REQ}" '
        f'NotOnOrAfter="{AFTER}" Recipient="{acs}"/></saml2:SubjectConfirmation></saml2:Subject>'
        f'<saml2:Conditions NotBefore="{BEFORE}" NotOnOrAfter="{AFTER}"><saml2:AudienceRestriction>'
        f'<saml2:Audience>{ent}</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions>'
        f'<saml2:AuthnStatement AuthnInstant="{AUTHN}" SessionIndex="_g1"><saml2:AuthnContext>'
        f'<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef>'
        f'</saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>'
    )


SHAPES = {"okta": okta, "entra": entra, "keycloak": keycloak, "google": google}

RSA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
RSA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
EC256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

# name, shape, key, signature algorithm, digest, what is signed, PrefixList
FIXTURES = [
    ("okta-both", "okta", "rsa", RSA256, SHA256, ["assertion", "response"], "xs"),
    ("okta-assertion", "okta", "rsa", RSA256, SHA256, ["assertion"], "xs"),
    ("entra-assertion", "entra", "rsa", RSA256, SHA256, ["assertion"], None),
    ("entra-response", "entra", "rsa", RSA256, SHA256, ["response"], None),
    ("keycloak-response", "keycloak", "rsa", RSA256, SHA256, ["response"], None),
    ("keycloak-both", "keycloak", "rsa", RSA256, SHA256, ["assertion", "response"], None),
    ("google-response", "google", "rsa", RSA256, SHA256, ["response"], None),
    ("okta-ecdsa", "okta", "ec", EC256, SHA256, ["assertion"], "xs"),
    ("entra-sha512", "entra", "rsa", RSA512, SHA512, ["assertion"], None),
    ("okta-weak", "okta", "rsa1024", RSA256, SHA256, ["assertion"], "xs"),
    ("okta-other-key", "okta", "rsa-other", RSA256, SHA256, ["assertion"], "xs"),
]


def run(*args):
    subprocess.run(args, check=True, capture_output=True)


def main():
    tmp = tempfile.mkdtemp()
    try:
        os.makedirs(OUT, exist_ok=True)
        os.makedirs(KEYS, exist_ok=True)
        for name, gen in [("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
                          ("rsa-other", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
                          ("rsa1024", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"]),
                          ("ec", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])]:
            pem = os.path.join(tmp, name + ".pem")
            run("openssl", "genpkey", *gen, "-out", pem)
            run("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", pem, "-outform", "DER",
                "-out", os.path.join(tmp, name + ".pk8"))
            run("openssl", "req", "-new", "-x509", "-key", pem, "-days", "3650",
                "-subj", "/CN=Test IdP " + name + " (not a real key)",
                "-out", os.path.join(KEYS, name + ".crt"))
        manifest = []
        for i, (name, shape, key, sig, dig, signed, prefixes) in enumerate(FIXTURES):
            rid, aid = f"_r{i:02d}c0ffee{name.replace('-', '')}", f"_a{i:02d}c0ffee{name.replace('-', '')}"
            src = os.path.join(tmp, name + ".xml")
            with open(src, "w") as f:
                f.write(SHAPES[shape](rid, aid))
            cur = src
            for which in signed:
                nxt = os.path.join(tmp, name + "." + which + ".xml")
                args = ["java", SIGN, cur, nxt, os.path.join(tmp, key + ".pk8"),
                        os.path.join(KEYS, key + ".crt"), sig, dig,
                        aid if which == "assertion" else rid]
                if prefixes:
                    args.append(prefixes)
                run(*args)
                cur = nxt
            shutil.copy(cur, os.path.join(OUT, name + ".xml"))
            manifest.append({"name": name, "idp": shape, "key": key, "signature": sig,
                             "digest": dig, "signed": signed, "response_id": rid,
                             "assertion_id": aid, "request_id": REQ, "now": T})
        with open(os.path.join(OUT, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=1)
            f.write("\n")
        print(len(manifest), "fixtures")
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    main()
