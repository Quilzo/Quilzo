package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/audit"
	"github.com/lithoform/lithoform/internal/store"
	"github.com/lithoform/lithoform/internal/vault"
)

func keyringPath(root string) string { return filepath.Join(root, "keyring.json") }

// keySource says where the key encryption key comes from.
//
// Never from the code, and by default not from the data directory — a key
// stored beside the thing it protects protects nothing against somebody who
// takes the directory. The command form is the interesting one: it makes an
// HSM, a cloud KMS, a password manager or a hardware token work without this
// program knowing any of them exist.
const (
	keyEnv     = "SCRIVET_KEY"
	keyCmdEnv  = "SCRIVET_KEY_COMMAND"
	keyFileEnv = "SCRIVET_KEY_FILE"
)

// loadKeyring reads the keyring and supplies key material from outside.
//
// Returns nil with no error when encryption is not configured. That is the
// default and it has to stay silent, because a store that encrypted itself with
// a key generated on first run is a store whose contents are lost the first
// time somebody reimages a machine.
func loadKeyring(root string) (*vault.Keyring, error) {
	raw, err := os.ReadFile(keyringPath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kr := &vault.Keyring{}
	if err := json.Unmarshal(raw, kr); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", keyringPath(root), err)
	}

	material, err := keyMaterial()
	if err != nil {
		return nil, err
	}
	if len(material) == 0 {
		return nil, fmt.Errorf(
			"this store is encrypted but no key was supplied.\n"+
				"  Set one of:\n"+
				"    %s          the key itself, base64\n"+
				"    %s     a file holding it\n"+
				"    %s  a command that prints it — this is how a\n"+
				"                            KMS, an HSM or a password manager plugs in",
			keyEnv, keyFileEnv, keyCmdEnv)
	}

	// One supplied key, applied to whichever keyring entry it matches by id.
	// Multiple keys are supplied as id=base64 pairs, so a rotation in progress
	// can still read what the previous key wrapped.
	if err := applyMaterial(kr, material); err != nil {
		return nil, err
	}
	return kr, nil
}

func keyMaterial() (string, error) {
	if cmd := os.Getenv(keyCmdEnv); cmd != "" {
		// Run through the shell so an operator can write a real command with
		// arguments and a pipe. This is an operator-supplied command from the
		// environment of the process, not caller input — anybody who can set it
		// can already run anything as this user.
		out, err := exec.Command("/bin/sh", "-c", cmd).Output()
		if err != nil {
			return "", fmt.Errorf("%s failed: %w", keyCmdEnv, err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	if path := os.Getenv(keyFileEnv); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr,
				"%swarning: %s is mode %04o — the key is readable by other "+
					"local accounts%s\n",
				yellow, path, info.Mode().Perm(), reset)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(os.Getenv(keyEnv)), nil
}

// applyMaterial attaches key bytes to the keyring entries.
func applyMaterial(kr *vault.Keyring, material string) error {
	assign := func(id, encoded string) error {
		k, err := vault.DecodeKey(encoded)
		if err != nil {
			return fmt.Errorf("key %q: %w", id, err)
		}
		entry, ok := kr.Keys[id]
		if !ok {
			return fmt.Errorf("key %q was supplied but the keyring does not "+
				"list it; the ids have to match or an object cannot say which "+
				"key wrapped it", id)
		}
		entry.Key = k
		return nil
	}

	for _, part := range strings.Split(material, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// A bare key is tried first, and this ordering is the whole of the
		// fix for a bug that unit tests could not see: base64 ends in `=`
		// padding, so splitting on `=` to find an `id=key` pair chopped a
		// perfectly good key at its own padding and read the front half as an
		// id. Deciding by whether the part *is* a key removes the ambiguity
		// instead of trying to parse around it.
		if _, err := vault.DecodeKey(part); err == nil {
			// A bare key is only unambiguous when there is one entry. After a
			// rotation there are at least two, and assuming the bare key is the
			// active one silently attached the *old* key's material to the
			// *new* key's id — which then failed at the first read with a
			// message about a key that had in fact been supplied. Refusing is
			// the only honest answer: the operator has to say which.
			if len(kr.Keys) > 1 {
				return fmt.Errorf(
					"this keyring holds %d keys (%s), so a bare key is "+
						"ambiguous — it could belong to any of them, and "+
						"guessing wrong looks like a corrupt store rather than "+
						"a mistyped variable.\n  Name them: %s=k1=…,k2=…",
					len(kr.Keys), strings.Join(kr.IDs(), ", "), keyEnv)
			}
			if err := assign(kr.Active, part); err != nil {
				return err
			}
			continue
		}
		if id, encoded, ok := strings.Cut(part, "="); ok {
			if err := assign(strings.TrimSpace(id), encoded); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("%q is neither a key nor an id=key pair", part)
	}

	if entry, ok := kr.Keys[kr.Active]; !ok || len(entry.Key) == 0 {
		return fmt.Errorf("no material was supplied for the active key %q",
			kr.Active)
	}
	return nil
}

// openEncrypted is what every command uses instead of open().
func openEncrypted(root string) (*store.Store, error) {
	s, err := store.Open(root)
	if err != nil {
		return nil, err
	}
	kr, err := loadKeyring(root)
	if err != nil {
		return nil, err
	}
	if kr != nil {
		s = s.WithKeys(kr)
	}
	return s, nil
}

func cmdVault(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return vaultStatus(root)
	case "enable":
		return vaultEnable(root, args[1:])
	case "rotate":
		return vaultRotate(root, args[1:])
	default:
		return fmt.Errorf("unknown vault command %q; try status, enable or rotate",
			args[0])
	}
}

func vaultStatus(root string) error {
	raw, err := os.ReadFile(keyringPath(root))
	if os.IsNotExist(err) {
		if w.JSON(map[string]any{"encrypted": false}) {
			return nil
		}
		w.Human("objects are stored in the clear\n")
		w.Human("  %sscrivet vault enable — encrypt new objects at rest%s\n",
			dim, reset)
		w.Human("  %sthis protects against somebody obtaining the files: a lost\n"+
			"  laptop, a backup on an open bucket, a disposed disk. It cannot\n"+
			"  protect against somebody who can run this program, because the\n"+
			"  program has to read the content to render it.%s\n", dim, reset)
		return nil
	}
	if err != nil {
		return err
	}
	kr := &vault.Keyring{}
	if err := json.Unmarshal(raw, kr); err != nil {
		return err
	}

	loaded := "no"
	if live, err := loadKeyring(root); err == nil && live != nil {
		loaded = "yes"
	}
	if w.JSON(map[string]any{
		"encrypted": true, "active": kr.Active, "keys": kr.IDs(),
		"material_loaded": loaded == "yes",
	}) {
		return nil
	}

	w.Human("objects are encrypted at rest\n")
	w.Human("  active key   %s%s%s\n", bold, kr.Active, reset)
	for _, id := range kr.IDs() {
		state := "active"
		if kr.Keys[id].Retired {
			state = "retired — still needed to read what it wrapped"
		}
		w.Human("  %-12s %s%s%s\n", id, dim, state, reset)
	}
	w.Human("  key loaded   %s\n", loaded)
	if loaded == "no" {
		w.Human("  %sset %s, %s or %s%s\n", yellow, keyEnv, keyFileEnv, keyCmdEnv, reset)
	}
	return nil
}

func vaultEnable(root string, args []string) error {
	fs := flag.NewFlagSet("enable", flag.ContinueOnError)
	id := fs.String("id", "k1", "an id for the first key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(keyringPath(root)); err == nil {
		return fmt.Errorf("this store already has a keyring; use vault rotate")
	}

	kr, err := vault.NewKeyring(*id, time.Now())
	if err != nil {
		return err
	}
	secret := vault.EncodeKey(kr.Keys[*id].Key)

	// The keyring on disk holds ids and metadata, never material. Writing the
	// key beside the data it protects would defeat the entire exercise, so it
	// is printed once and the operator has to put it somewhere.
	if err := saveJSON(keyringPath(root), kr); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "vault.enable", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"kek_id": *id},
	})

	if w.JSON(map[string]any{"id": *id, "key": secret}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, secret, reset)
	w.Human("\n  %sthis is the only time it is shown. It is not stored here —\n"+
		"  a key kept beside the data it protects protects nothing against\n"+
		"  somebody who takes the directory.%s\n", yellow, reset)
	w.Human("\n  %ssupply it with one of:%s\n", dim, reset)
	w.Human("    export %s='%s'\n", keyEnv, "…")
	w.Human("    export %s=/run/secrets/scrivet.key\n", keyFileEnv)
	w.Human("    export %s='aws kms decrypt … --output text'\n", keyCmdEnv)
	w.Human("\n  %sobjects already written stay in the clear; only new ones are\n"+
		"  sealed. Nothing is rewritten, so enabling this cannot lose content.%s\n",
		dim, reset)
	return nil
}

func vaultRotate(root string, args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	id := fs.String("id", "", "an id for the new key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		*id = fmt.Sprintf("k%d", time.Now().Unix())
	}

	kr, err := loadKeyring(root)
	if err != nil {
		return err
	}
	if kr == nil {
		return fmt.Errorf("this store is not encrypted; use vault enable")
	}
	previous := kr.Active
	if err := kr.Add(*id, time.Now()); err != nil {
		return err
	}
	secret := vault.EncodeKey(kr.Keys[*id].Key)
	if err := saveJSON(keyringPath(root), kr); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "vault.rotate", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"kek_id": *id, "previous": previous},
	})

	w.Human("%s%s%s\n", bold, secret, reset)
	w.Human("\n  %snew objects are sealed with %s. %s is retained and still\n"+
		"  needed to read everything written before now — supply both:%s\n",
		yellow, *id, previous, reset)
	w.Human("    export %s='%s=…,%s=…'\n", keyEnv, previous, *id)
	w.Human("\n  %snothing was re-encrypted. Rotation rewraps data keys, which is\n"+
		"  why it is cheap enough to actually do.%s\n", dim, reset)
	return nil
}
