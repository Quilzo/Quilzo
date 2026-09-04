package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/audit"
)

// The key that signs audit heads, and the file that publishes its public half.
//
// Separate from audit.key, which is a pseudonymisation secret and not a
// signing key: one turns a name into a stable token, the other says this site
// published this root. Sharing a key between the two would mean handing out
// the ability to forge heads to anybody who needs to re-identify a log entry.

func headKeyPath(root string) string {
	return filepath.Join(auditDir(root), "head.key")
}

// headKeysPath is the public half, meant to be copied anywhere.
//
// Published as its own file because a verifier outside this building needs it
// and must not need anything else: a head, this file, and the tool. Nothing in
// it is secret.
func headKeysPath(root string) string {
	return filepath.Join(auditDir(root), "head.pub.json")
}

// storedSeeds is what head.key holds: two 32-byte seeds, base64.
//
// Seeds rather than keys, because an ML-DSA private key is several kilobytes
// and its seed regenerates it exactly. Sixty-four bytes is small enough to
// write down, which is the difference between a key that gets backed up and
// one that does not.
type storedSeeds struct {
	Ed25519 string `json:"ed25519_seed"`
	MLDSA   string `json:"mldsa_seed"`
}

type publishedKeys struct {
	KeyID   string `json:"key_id"`
	Ed25519 string `json:"ed25519"`
	MLDSA   string `json:"mldsa"`
	Note    string `json:"note"`
}

// headSigner loads the signing keys, creating them on first use.
//
// Created rather than demanded: an unsigned head is the state this exists to
// end, and requiring a setup command first would mean the default stayed
// unsigned for everybody who did not read about it.
func headSigner(root string) (*audit.HeadSigner, error) {
	var seeds storedSeeds
	body, err := os.ReadFile(headKeyPath(root))
	switch {
	case os.IsNotExist(err):
		edSeed, mlSeed, gerr := audit.GenerateHeadSeeds()
		if gerr != nil {
			return nil, gerr
		}
		seeds = storedSeeds{
			Ed25519: base64.StdEncoding.EncodeToString(edSeed),
			MLDSA:   base64.StdEncoding.EncodeToString(mlSeed),
		}
		out, merr := json.MarshalIndent(seeds, "", "  ")
		if merr != nil {
			return nil, merr
		}
		if werr := os.MkdirAll(auditDir(root), 0o700); werr != nil {
			return nil, werr
		}
		// 0600. Anybody who reads this can sign a head saying the log is
		// something it is not, which is the one claim this whole mechanism
		// exists to make unforgeable.
		if werr := os.WriteFile(headKeyPath(root), append(out, '\n'), 0o600); werr != nil {
			return nil, fmt.Errorf("cannot write the head signing key: %w", werr)
		}
	case err != nil:
		return nil, err
	default:
		if uerr := json.Unmarshal(body, &seeds); uerr != nil {
			return nil, fmt.Errorf("%s is not readable: %w", headKeyPath(root), uerr)
		}
	}

	edSeed, err := base64.StdEncoding.DecodeString(seeds.Ed25519)
	if err != nil {
		return nil, fmt.Errorf("the Ed25519 seed is not base64: %w", err)
	}
	mlSeed, err := base64.StdEncoding.DecodeString(seeds.MLDSA)
	if err != nil {
		return nil, fmt.Errorf("the ML-DSA seed is not base64: %w", err)
	}
	s, err := audit.NewHeadSigner(edSeed, mlSeed)
	if err != nil {
		return nil, err
	}

	// The public half is rewritten whenever the key is loaded, so it cannot
	// drift from the key that is actually signing. A published key that names
	// a retired one is worse than none: it makes every genuine head look
	// forged.
	if err := writePublishedKeys(root, s); err != nil {
		return nil, err
	}
	return s, nil
}

func writePublishedKeys(root string, s *audit.HeadSigner) error {
	v := s.Verifier()
	ed, ml := v.PublicKeys()
	out, err := json.MarshalIndent(publishedKeys{
		KeyID:   v.KeyID(),
		Ed25519: base64.StdEncoding.EncodeToString(ed),
		MLDSA:   base64.StdEncoding.EncodeToString(ml),
		Note: "Public keys for this site's audit heads. Copy this anywhere; " +
			"nothing in it is secret. A head verifies only if both signatures " +
			"do — see quilzo auditlog verify-head.",
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(auditDir(root), 0o700); err != nil {
		return err
	}
	return os.WriteFile(headKeysPath(root), append(out, '\n'), 0o644)
}

// verifyHead checks a signed head from a file against published keys.
//
// A separate command because verification is what somebody outside does, and
// the thing they have is a file. It reads keys from --keys so that an auditor
// can check a head against the keys they were given rather than against
// whatever this machine currently holds — which would be checking a claim
// against itself.
func auditVerifyHead(root string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf(
			"usage: quilzo auditlog verify-head <head.json> [--keys head.pub.json]")
	}
	headPath := args[0]
	keysPath := headKeysPath(root)
	for i := 1; i < len(args)-1; i++ {
		if args[i] == "--keys" {
			keysPath = args[i+1]
		}
	}

	body, err := os.ReadFile(headPath)
	if err != nil {
		return err
	}
	var sh audit.SignedHead
	if err := json.Unmarshal(body, &sh); err != nil {
		return fmt.Errorf("%s is not a signed head: %w", headPath, err)
	}

	kb, err := os.ReadFile(keysPath)
	if err != nil {
		return fmt.Errorf("cannot read the public keys at %s: %w", keysPath, err)
	}
	var pub publishedKeys
	if err := json.Unmarshal(kb, &pub); err != nil {
		return fmt.Errorf("%s is not a published key file: %w", keysPath, err)
	}
	ed, err := base64.StdEncoding.DecodeString(pub.Ed25519)
	if err != nil {
		return fmt.Errorf("the published Ed25519 key is not base64: %w", err)
	}
	ml, err := base64.StdEncoding.DecodeString(pub.MLDSA)
	if err != nil {
		return fmt.Errorf("the published ML-DSA key is not base64: %w", err)
	}
	v, err := audit.NewHeadVerifier(ed, ml)
	if err != nil {
		return err
	}
	if err := v.Verify(sh); err != nil {
		return fmt.Errorf("this head does not verify: %w", err)
	}

	if w.JSON(map[string]any{
		"verified": true, "size": sh.Size, "root": sh.Root,
		"key_id": sh.KeyID, "algorithms": []string{"ed25519", "ml-dsa-65"},
	}) {
		return nil
	}
	w.Human("%sverified%s  %d entries, root %s\n", bold, reset, sh.Size, sh.Root)
	w.Human("  %ssigned by %s with Ed25519 and ML-DSA-65, and both check out%s\n",
		dim, sh.KeyID, reset)
	w.Human("\n  %sthis says the head came from that key. Whether it describes\n"+
		"  the log you hold is a separate question:%s\n", dim, reset)
	w.Human("    %squilzo auditlog consistency%s\n", dim, reset)
	return nil
}
