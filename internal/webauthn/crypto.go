package webauthn

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
)

// elliptic256 is P-256, named so the algorithm check above reads as a
// statement about ES256 rather than about a curve constant.
func elliptic256() elliptic.Curve { return elliptic.P256() }

func rsaVerify(k *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig)
}
