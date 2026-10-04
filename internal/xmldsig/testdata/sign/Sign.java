// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Signs one element of a SAML document with the JDK's own XML Signature
// implementation (javax.xml.crypto.dsig, the Apache Santuario lineage that
// Keycloak, Shibboleth and many identity providers sign with), so the
// fixtures in testdata/saml come from software that shares nothing with
// the Go verifier. Run by gen_saml.py; never by the tests.
//
//   java Sign.java IN OUT KEY.pk8 CERT.pem SIGALG DIGESTALG ID [PREFIXES]
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;

public class Sign {
    public static void main(String[] a) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document doc = dbf.newDocumentBuilder().parse(new File(a[0]));

        Element target = null;
        NodeList all = doc.getElementsByTagNameNS("*", "*");
        for (int i = 0; i < all.getLength(); i++) {
            Element e = (Element) all.item(i);
            if (e.hasAttribute("ID")) e.setIdAttribute("ID", true);
            if (a[6].equals(e.getAttribute("ID"))) target = e;
        }
        if (target == null) throw new IllegalArgumentException("no element with ID " + a[6]);

        // After the Issuer, where the SAML schema puts a signature.
        Node next = target.getFirstChild();
        for (Node n = target.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element && "Issuer".equals(n.getLocalName())) { next = n.getNextSibling(); break; }
        }

        KeyFactory kf = KeyFactory.getInstance(a[4].contains("ecdsa") ? "EC" : "RSA");
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of(a[2]))));
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new FileInputStream(a[3]));

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        TransformParameterSpec excl = a.length > 7
            ? new ExcC14NParameterSpec(Arrays.asList(a[7].split(" "))) : null;
        List<Transform> transforms = List.of(
            fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
            fac.newTransform(CanonicalizationMethod.EXCLUSIVE, excl));
        Reference ref = fac.newReference("#" + a[6], fac.newDigestMethod(a[5], null), transforms, null, null);
        SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
            fac.newSignatureMethod(a[4], null), List.of(ref));
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyInfo ki = kif.newKeyInfo(List.of(kif.newX509Data(List.of(cert))));

        DOMSignContext ctx = next == null ? new DOMSignContext(key, target) : new DOMSignContext(key, target, next);
        ctx.setDefaultNamespacePrefix("ds");
        fac.newXMLSignature(si, ki).sign(ctx);

        Transformer t = TransformerFactory.newInstance().newTransformer();
        t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        t.transform(new DOMSource(doc), new StreamResult(new File(a[1])));
    }
}
