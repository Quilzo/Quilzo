package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// The identity a C2PA manifest is signed with.
//
// # Why it is a certificate and not a bare key
//
// A manifest signed by a bare public key says only that whoever made it had a
// key. C2PA puts a certificate chain in the signature so a reader has
// something to check a name against, and the ecosystem's verifiers refuse a
// manifest without one.
//
// # What this certificate is worth, said plainly
//
// It is self-signed. It proves that every image from this site was signed by
// the same key, and that nobody has altered one since. It does not prove who
// runs the site to anybody who has not already been told. A deployment that
// wants a reader's C2PA tool to show a verified name needs a certificate from
// a CA in the C2PA trust list, and this file is where that certificate would
// go instead. The local default is the bootstrap, not the destination.
//
// Ed25519 because it is in the standard library, and because a manifest is
// signed once per file and read by everybody: a small signature is the right
// trade.

func provenanceKeyPath(root string) string {
	return filepath.Join(root, "provenance.key")
}

func provenanceCertPath(root string) string {
	return filepath.Join(root, "provenance.crt")
}

// provenanceSigner loads the signing identity, creating one on first use.
//
// Created rather than demanded, because an image served without a manifest is
// the failure this is meant to remove, and a site should not have to run a
// setup command to stop shipping unattributed pictures.
func provenanceSigner(root, siteName string, now time.Time) (
	[][]byte, ed25519.PrivateKey, error) {

	keyPEM, err := os.ReadFile(provenanceKeyPath(root))
	if os.IsNotExist(err) {
		return newProvenanceSigner(root, siteName, now)
	} else if err != nil {
		return nil, nil, err
	}
	certPEM, err := os.ReadFile(provenanceCertPath(root))
	if err != nil {
		return nil, nil, fmt.Errorf(
			"there is a provenance key at %s and no certificate at %s. A "+
				"manifest signed with a key whose certificate is missing "+
				"names no signer; delete the key to start over, or restore "+
				"the certificate",
			provenanceKeyPath(root), provenanceCertPath(root))
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("%s is not a PEM key", provenanceKeyPath(root))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read %s: %w",
			provenanceKeyPath(root), err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf(
			"%s is not an Ed25519 key, and that is the algorithm this signs "+
				"manifests with", provenanceKeyPath(root))
	}

	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("%s is not a PEM certificate",
			provenanceCertPath(root))
	}
	return [][]byte{cb.Bytes}, key, nil
}

func newProvenanceSigner(root, siteName string, now time.Time) (
	[][]byte, ed25519.PrivateKey, error) {

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate a provenance key: %w", err)
	}
	if siteName == "" {
		siteName = "this site"
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: siteName},
		// Ten years. A manifest outlives the certificate that signed it --
		// people keep images -- and an expiry short enough to be meaningful
		// would make every old picture look tampered with instead of old.
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			// The usage C2PA requires of a claim signer's certificate.
			x509.ExtKeyUsageEmailProtection,
		},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create a certificate: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	// 0600. Anyone who reads this can sign a manifest saying a picture came
	// from here.
	if err := os.WriteFile(provenanceKeyPath(root),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		0o600); err != nil {
		return nil, nil, fmt.Errorf("cannot write the provenance key: %w", err)
	}
	if err := os.WriteFile(provenanceCertPath(root),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		0o644); err != nil {
		return nil, nil, fmt.Errorf("cannot write the certificate: %w", err)
	}
	return [][]byte{der}, priv, nil
}
