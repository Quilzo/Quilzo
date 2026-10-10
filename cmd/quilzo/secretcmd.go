// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/vault"
)

// Credentials an agent uses, kept sealed.
//
// An integration's credential came only from the environment of the process
// that used it. That was right for an API key a deployment sets once, and it
// left nothing for the case that matters next: an agent signing in to a web
// application, where Quilzo itself types the password into the page and the
// model never sees it. That needs the value held somewhere Quilzo can read
// and nobody who takes the files can: sealed under the store's keyring, as
// the connectors' credentials already are.
//
// Stricter than those in one way. A connector's credential is kept in plain
// text, readable only by this account, when the store has no keyring; an
// agent's is refused instead, because an agent's credentials are the ones a
// stolen backup would be read for.
//
// The value never comes from the command line, which is in the shell's
// history and in the process table: it is read from standard input, or from
// QUILZO_SECRET_VALUE, and never printed again. The environment still wins
// when QUILZO_SECRET_NAME is set, so a deployment that injects credentials
// at start keeps working, and keeps them out of the store entirely.

func agentSecretsPath(root string) string { return filepath.Join(root, "secrets.json") }

// agentSecrets is the file: each credential sealed, and who set it when.
type agentSecrets struct {
	Sealed map[string]json.RawMessage `json:"sealed,omitempty"`
	Set    map[string]secretKept      `json:"set,omitempty"`
}

type secretKept struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// reSecretName is a credential's name: what an integration or a manifest
// names, and what QUILZO_SECRET_ is followed by.
var reSecretName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// MaxSecretBytes bounds one credential. A private key in PEM is a few
// kilobytes; nothing an agent signs in with is larger.
const MaxSecretBytes = 16 << 10

func secretAAD(name string) []byte { return []byte("agent-secret/" + name) }

func loadAgentSecrets(root string) (agentSecrets, error) {
	var f agentSecrets
	b, err := os.ReadFile(agentSecretsPath(root))
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("%s is unreadable: %w", agentSecretsPath(root), err)
	}
	return f, nil
}

func saveAgentSecrets(root string, f agentSecrets) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(agentSecretsPath(root), append(b, '\n'), 0o600)
}

// sealedSecret reads one credential from the sealed store. Missing is
// reported as such, so the caller can say where it looked.
func sealedSecret(root, name string) (string, bool, error) {
	f, err := loadAgentSecrets(root)
	if err != nil {
		return "", false, err
	}
	raw, ok := f.Sealed[name]
	if !ok {
		return "", false, nil
	}
	kr, err := loadKeyring(root)
	if err != nil {
		return "", false, err
	}
	if kr == nil {
		return "", false, fmt.Errorf("%s holds sealed credentials and this store has no keyring", agentSecretsPath(root))
	}
	s, err := vault.Unmarshal(raw)
	if err != nil {
		return "", false, err
	}
	b, err := kr.Open(s, secretAAD(name))
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", name, err)
	}
	return string(b), true, nil
}

func cmdSecret(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, "")
	switch args[0] {
	case "set":
		if len(args) != 2 {
			return errors.New("usage: quilzo secret set NAME   (the value from standard input, or QUILZO_SECRET_VALUE)")
		}
		return secretSetCmd(root, args[1], caller)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: quilzo secret remove NAME")
		}
		return secretRemove(root, args[1], caller)
	case "list":
		return secretList(root)
	}
	return fmt.Errorf("unknown secret command %q; try set, list or remove", args[0])
}

func secretSetCmd(root, name string, caller *Caller) error {
	if !reSecretName.MatchString(name) {
		return fmt.Errorf("%q is not a credential's name: lower-case letters, digits, '.', '_' and '-', up to 64", name)
	}
	value, err := secretValue()
	if err != nil {
		return err
	}
	if err := setAgentSecret(root, name, value, caller.Name, time.Now()); err != nil {
		return err
	}
	record(root, caller.auditRecord("secret.set", "/", audit.Success, map[string]string{"name": name}))
	fmt.Printf("%s is kept, sealed. It is never shown again; set it again to change it.\n", name)
	if os.Getenv(secretEnvName(name)) != "" {
		fmt.Printf("  %s%s is set in this environment, and wins over the sealed one while it is%s\n",
			yellow, secretEnvName(name), reset)
	}
	return nil
}

// setAgentSecret seals and keeps one credential.
func setAgentSecret(root, name, value, by string, now time.Time) error {
	kr, err := loadKeyring(root)
	if err != nil {
		return err
	}
	if kr == nil {
		return errors.New("an agent's credentials are kept sealed, and this store has no keyring yet. " +
			"Run quilzo vault enable first; it prints the key once, and says where to keep it")
	}
	unlock, err := atomicfile.Lock(agentSecretsPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	f, err := loadAgentSecrets(root)
	if err != nil {
		return err
	}
	s, err := kr.Seal([]byte(value), secretAAD(name))
	if err != nil {
		return err
	}
	raw, err := vault.Marshal(s)
	if err != nil {
		return err
	}
	if f.Sealed == nil {
		f.Sealed, f.Set = map[string]json.RawMessage{}, map[string]secretKept{}
	}
	f.Sealed[name] = raw
	f.Set[name] = secretKept{By: by, At: now.UTC()}
	return saveAgentSecrets(root, f)
}

// secretValue reads the credential from QUILZO_SECRET_VALUE or standard
// input, never from an argument. A terminal is refused: what is typed there
// is shown on the screen, and this program reads no terminal without echo.
func secretValue() (string, error) {
	if v := os.Getenv("QUILZO_SECRET_VALUE"); v != "" {
		return checkSecretValue(v)
	}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return "", errors.New("give the value on standard input, from a file or a password manager " +
			"(quilzo secret set NAME < file), or in QUILZO_SECRET_VALUE. It is never taken from the " +
			"command line, which is in the shell's history, or typed where it is shown")
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, MaxSecretBytes+1))
	if err != nil {
		return "", err
	}
	return checkSecretValue(strings.TrimRight(string(b), "\r\n"))
}

func checkSecretValue(v string) (string, error) {
	switch {
	case v == "":
		return "", errors.New("the value is empty")
	case len(v) > MaxSecretBytes:
		return "", fmt.Errorf("a credential is at most %d bytes", MaxSecretBytes)
	}
	return v, nil
}

func secretRemove(root, name string, caller *Caller) error {
	unlock, err := atomicfile.Lock(agentSecretsPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	f, err := loadAgentSecrets(root)
	if err != nil {
		return err
	}
	if _, ok := f.Sealed[name]; !ok {
		return fmt.Errorf("no credential %q is kept", name)
	}
	delete(f.Sealed, name)
	delete(f.Set, name)
	if err := saveAgentSecrets(root, f); err != nil {
		return err
	}
	record(root, caller.auditRecord("secret.remove", "/", audit.Success, map[string]string{"name": name}))
	fmt.Printf("%s is gone.\n", name)
	return nil
}

func secretList(root string) error {
	f, err := loadAgentSecrets(root)
	if err != nil {
		return err
	}
	if len(f.Sealed) == 0 {
		fmt.Printf("  %sno credentials are kept; quilzo secret set NAME < file keeps one%s\n", dim, reset)
		return nil
	}
	names := make([]string, 0, len(f.Sealed))
	for n := range f.Sealed {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := f.Set[n]
		fmt.Printf("%s%s%s  sealed, set by %s on %s\n", bold, n, reset, onOneLine(s.By), s.At.Format("2 Jan 2006"))
		if os.Getenv(secretEnvName(n)) != "" {
			fmt.Printf("  %s%s in this environment wins over it%s\n", yellow, secretEnvName(n), reset)
		}
	}
	return nil
}
