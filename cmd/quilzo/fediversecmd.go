package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/quilzo/quilzo/internal/activitypub"
	"github.com/quilzo/quilzo/internal/audit"
)

// cmdFediverse manages the identity this site federates under.
func cmdFediverse(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "init":
		return fediverseInit(root)
	case "status":
		return fediverseStatus(root)
	case "followers":
		return fediverseFollowers(root)
	default:
		return fmt.Errorf(
			"unknown fediverse command %q; try init, status or followers",
			args[0])
	}
}

// fediverseInit creates the signing key.
//
// # Why RSA and why 2048
//
// Ed25519 is the better algorithm and Mastodon has verified it only since 4.7.
// A key that half the network cannot check is a site half the network silently
// ignores, so this follows the installed base rather than the specification.
//
// 2048 rather than 4096: signatures are made on every delivery, and the larger
// key costs real time per follower for a margin nobody needs against an
// adversary who would be attacking the platform rather than a website's
// signing key.
//
// # It never overwrites
//
// Replacing the key strands every follower — remote servers cached the old
// public key and will refuse everything signed with the new one until they
// refetch, which some do lazily and some do not do at all. So an existing key
// is left alone and the command says so.
func fediverseInit(root string) error {
	path := fediverseKeyPath(root)
	if _, err := os.Stat(path); err == nil {
		return errBlocked{fmt.Errorf(
			"there is already a signing key at %s.\n"+
				"  Replacing it would strand every follower: remote servers "+
				"cached the old\n  public key and refuse anything signed with "+
				"a new one until they refetch,\n  which some do lazily and "+
				"some never do. Delete it deliberately if you\n  mean to start "+
				"over.", path)}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("cannot generate a signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	// 0600, because this is the credential that speaks for the site. Anybody
	// who reads it can publish as you to everybody following you.
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("cannot write the signing key: %w", err)
	}

	// Recorded, because this is the moment a site acquires an identity that
	// speaks for it to everybody who will ever follow it. A key appearing with
	// no entry saying who made it and when is the gap an audit log exists to
	// close.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "fediverse.key", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"algorithm": "RSA", "bits": "2048", "path": path,
		},
	})

	if w.JSON(map[string]any{"key": path, "bits": 2048}) {
		return nil
	}
	w.Human("%swrote a signing key%s to %s\n", green, reset, path)
	w.Human("  %sRSA 2048, which is what the installed fediverse verifies. "+
		"Mode 0600: anybody\n  who reads it can publish as this site to "+
		"everybody following it.%s\n", dim, reset)
	w.Human("\n  next: %squilzo config set fediverse.handle yourname%s\n",
		bold, reset)
	w.Human("  %sthen serve with --base-url, and the address is "+
		"@yourname@yourdomain%s\n", dim, reset)
	return nil
}

func fediverseStatus(root string) error {
	path := fediverseKeyPath(root)
	_, keyErr := os.Stat(path)
	cfg := mustConfig(root)
	handle := cfg.Raw("fediverse.handle")

	followers := activitypub.NewFollowers()
	_ = loadJSON(fediverseFollowersPath(root), followers)

	if w.JSON(map[string]any{
		"handle": handle, "key": keyErr == nil,
		"followers": followers.Len(),
	}) {
		return nil
	}

	switch {
	case handle == "" && keyErr != nil:
		w.Human("this site does not federate\n")
		w.Human("  %squilzo fediverse init, then config set "+
			"fediverse.handle NAME%s\n", dim, reset)
	case handle == "":
		w.Human("%sa signing key exists and no handle is set%s\n", yellow, reset)
		w.Human("  %squilzo config set fediverse.handle NAME%s\n", dim, reset)
	case keyErr != nil:
		w.Human("%sa handle is set and there is no signing key%s\n", red, reset)
		w.Human("  %sthe site will refuse to start: quilzo fediverse init%s\n",
			dim, reset)
	default:
		w.Human("%sfederating as %s@%s%s\n", bold, handle, "yourdomain", reset)
		w.Human("  %s%d follower(s)%s\n", dim, followers.Len(), reset)
	}
	return nil
}

func fediverseFollowers(root string) error {
	followers := activitypub.NewFollowers()
	if err := loadJSON(fediverseFollowersPath(root), followers); err != nil &&
		!os.IsNotExist(err) {
		return err
	}
	all := followers.All()
	if w.JSON(map[string]any{"followers": all, "total": len(all)}) {
		return nil
	}
	w.Human("%s%d follower(s)%s\n", bold, len(all), reset)
	for _, f := range all {
		w.Human("  %s\n", f.Actor)
	}
	if len(all) == 0 {
		w.Human("  %snobody yet. They arrive when somebody follows the "+
			"address.%s\n", dim, reset)
	}
	return nil
}
