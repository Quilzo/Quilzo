// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/dpop"
)

// A program's own key, for tokens bound to it (see internal/dpop). The key
// is made and kept on the program's machine; only its public half and its
// thumbprint ever reach the store.

type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// tokenKeygen is `quilzo token keygen FILE`: a P-256 key in FILE, readable
// by its owner only, and its public half in FILE.pub.
func tokenKeygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo token keygen FILE")
	}
	if _, err := os.Stat(args[0]); err == nil {
		return fmt.Errorf("%s exists; a key is not overwritten", args[0])
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	b64 := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	priv, err := json.Marshal(privateJWK{Kty: "EC", Crv: "P-256", X: b64(key.X), Y: b64(key.Y), D: b64(key.D)})
	if err != nil {
		return err
	}
	if err := atomicfile.Write(args[0], append(priv, '\n'), 0o600); err != nil {
		return err
	}
	pub, err := dpop.PublicJWK(&key.PublicKey)
	if err != nil {
		return err
	}
	if err := atomicfile.Write(args[0]+".pub", append(pub, '\n'), 0o644); err != nil {
		return err
	}
	thumb, err := dpop.Thumbprint(pub)
	if err != nil {
		return err
	}
	w.Human("wrote %s (the key, keep it with the program) and %s.pub (its public half)\n", args[0], args[0])
	w.Human("  thumbprint %s\n", thumb)
	w.Human("  %sbind a token to it: quilzo token issue NAME --principal WHO --key %s.pub%s\n", dim, args[0], reset)
	return nil
}

// readKey reads a key made by tokenKeygen.
func readKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k privateJWK
	if err := json.Unmarshal(raw, &k); err != nil || k.Kty != "EC" || k.Crv != "P-256" || k.D == "" {
		return nil, fmt.Errorf("%s is not a P-256 key made by quilzo token keygen", path)
	}
	num := func(s string) (*big.Int, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		return new(big.Int).SetBytes(b), err
	}
	x, err1 := num(k.X)
	y, err2 := num(k.Y)
	d, err3 := num(k.D)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	if !key.Curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("%s holds a point that is not on P-256", path)
	}
	return key, nil
}

// publicKeyThumbprint reads a public JWK file, or the public half of a key
// file, and returns its thumbprint.
func publicKeyThumbprint(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		return "", fmt.Errorf("%s is not a JWK: %w", path, err)
	}
	if _, private := members["d"]; private {
		return "", fmt.Errorf("%s is a private key; give its public half, %s.pub, so the key stays with the program", path, path)
	}
	return dpop.Thumbprint(raw)
}

// tokenProof is `quilzo token proof --key FILE --url URL [--method M]
// [--presenting T]`: one DPoP proof, for a script calling with curl.
func tokenProof(args []string) error {
	fs := flag.NewFlagSet("token proof", flag.ContinueOnError)
	keyFile := fs.String("key", "", "the key file from quilzo token keygen")
	url := fs.String("url", "", "the address the request goes to, such as https://admin.example/mcp")
	method := fs.String("method", "POST", "the request's method")
	token := fs.String("presenting", "", "the token the request presents; empty for an exchange")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *url == "" {
		return errors.New("usage: quilzo token proof --key FILE --url URL [--method POST] [--presenting TOKEN]")
	}
	key, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	proof, err := dpop.Prove(key, strings.ToUpper(*method), *url, strings.TrimSpace(*token), time.Now())
	if err != nil {
		return err
	}
	fmt.Println(proof)
	return nil
}
