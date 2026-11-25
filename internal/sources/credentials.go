// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/store"
)

// A source's credentials, kept in the vault and nowhere else.
//
// The credential is the part of a connector worth stealing: the 2025
// breaches through a chat widget's integration were its tokens, not its
// code. So it is kept sealed under the store's keyring, each one bound to
// its source and its name, beside the store and never in it, and a store
// with no keyring keeps none: a credential in the clear on a disk is the
// copy a stolen backup is read for. The register's Source names the recipe,
// and the recipe's manifest names each credential; neither ever holds one.
// A run reads them here by those names and from nowhere else: not a flag,
// not a setting, not the environment.
//
//	sources/credentials/SOURCE/NAME   one credential, sealed

// Vault is the credentials of a store's sources.
type Vault struct {
	Store *store.Store
}

// ErrNoKeyring is a credential kept on a store that cannot seal it.
var ErrNoKeyring = errors.New("a source's credentials are kept sealed in the vault, and this store has no keyring yet. " +
	"Run quilzo vault enable first; it prints the key once, and says where to keep it")

// MaxCredential bounds one credential: a private key in PEM, or a service
// account's key file, is a few kilobytes.
const MaxCredential = 16 << 10

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (v *Vault) dir(source string) string {
	return filepath.Join(v.Store.Root(), "sources", "credentials", source)
}

func credentialAAD(source, name string) []byte {
	return []byte("quilzo source credential " + source + " " + name)
}

func checkNames(source, name string) error {
	if !reName.MatchString(source) || !reName.MatchString(name) {
		return fmt.Errorf("%q of %q is not a credential's name: lower-case letters, digits, '.', '_' and '-'",
			name, source)
	}
	return nil
}

// Set keeps one credential of a source, sealed.
func (v *Vault) Set(source, name, value string) error {
	if err := checkNames(source, name); err != nil {
		return err
	}
	if !v.Store.Encrypted() {
		return ErrNoKeyring
	}
	value = strings.TrimRight(value, "\r\n")
	switch {
	case strings.TrimSpace(value) == "":
		return errors.New("the credential is empty")
	case len(value) > MaxCredential:
		return fmt.Errorf("a credential is at most %d bytes", MaxCredential)
	}
	body, err := v.Store.Seal([]byte(value), credentialAAD(source, name))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(v.dir(source), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(v.dir(source), name), body, 0o600)
}

// Get is one credential of a source, unsealed.
func (v *Vault) Get(source, name string) (string, error) {
	if err := checkNames(source, name); err != nil {
		return "", err
	}
	body, err := os.ReadFile(filepath.Join(v.dir(source), name))
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("the vault keeps no credential %s for the source %s: quilzo source credential %s %s, "+
			"from standard input", name, source, source, name)
	}
	if err != nil {
		return "", err
	}
	if !v.Store.Encrypted() {
		return "", ErrNoKeyring
	}
	b, err := v.Store.Unseal(body, credentialAAD(source, name))
	if err != nil {
		return "", fmt.Errorf("the credential %s of %s does not open: %w", name, source, err)
	}
	return string(b), nil
}

// Names are the credentials kept for a source, by name; never their values.
func (v *Vault) Names(source string) []string {
	entries, err := os.ReadDir(v.dir(source))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && reName.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Remove forgets one credential of a source.
func (v *Vault) Remove(source, name string) error {
	if err := checkNames(source, name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(v.dir(source), name))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the vault keeps no credential %s for the source %s", name, source)
	}
	return err
}

// secrets is what a run of a source may ask the vault for: the names its
// manifest declares, and only those.
type secrets struct {
	v      *Vault
	source string
	names  map[string]bool
}

func (v *Vault) secretsFor(source string, m connector.Manifest) secrets {
	names := map[string]bool{}
	for _, n := range Credentials(m) {
		names[n] = true
	}
	return secrets{v: v, source: source, names: names}
}

// Secret implements connector.Secrets.
func (s secrets) Secret(name string) (string, error) {
	if !s.names[name] {
		return "", fmt.Errorf("the recipe does not name a credential %q", name)
	}
	return s.v.Get(s.source, name)
}
