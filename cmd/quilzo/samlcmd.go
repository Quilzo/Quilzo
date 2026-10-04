// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/saml"
)

// SAML identity providers, one file each under saml/. See internal/saml for
// what is checked and why; this is how an operator sets one up.

func samlDir(root string) string { return filepath.Join(root, "saml") }

func samlFile(root, name string) string { return filepath.Join(samlDir(root), name+".json") }

// loadSAML reads every configured provider, refusing a file whose name and
// contents disagree.
func loadSAML(root string) ([]saml.Config, error) {
	entries, err := os.ReadDir(samlDir(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []saml.Config
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var c saml.Config
		if err := loadJSON(filepath.Join(samlDir(root), e.Name()), &c); err != nil {
			return nil, err
		}
		if c.Name+".json" != e.Name() {
			return nil, fmt.Errorf("saml/%s names itself %q", e.Name(), c.Name)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func saveSAML(root string, c saml.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(samlDir(root), 0o700); err != nil {
		return err
	}
	return saveJSON(samlFile(root, c.Name), c)
}

func removeSAML(root, name string) error {
	if _, err := os.Stat(samlFile(root, name)); err != nil {
		return fmt.Errorf("there is no identity provider called %q", name)
	}
	return os.Remove(samlFile(root, name))
}

// samlFetch reads metadata from an address under the sso purpose.
func samlFetch(addr string) ([]byte, error) {
	if _, err := fetch.ValidateURL(addr); err != nil {
		return nil, err
	}
	c := fetch.New()
	c.Purpose = "sso"
	c.UserAgent = "quilzo/1 (+saml metadata)"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := c.Get(ctx, addr)
	if err != nil {
		return nil, err
	}
	if res.Status != 200 || res.Truncated {
		return nil, fmt.Errorf("%s answered %d", addr, res.Status)
	}
	return res.Body, nil
}

func samlUsage() error {
	return fmt.Errorf("usage: quilzo saml list | show NAME | metadata NAME | presets | " +
		"add NAME --metadata FILE|URL --url https://YOUR-ADMIN [--preset okta] " +
		"[--domain d] [--require-mfa] [--required] [--fingerprint SHA256] | remove NAME")
}

func cmdSAML(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, "")
	switch args[0] {
	case "list":
		all, err := loadSAML(root)
		if err != nil {
			return err
		}
		if w.JSON(all) {
			return nil
		}
		if len(all) == 0 {
			w.Human("no SAML identity provider is set up\n  %squilzo saml add NAME --metadata FILE --url https://YOUR-ADMIN%s\n", dim, reset)
			return nil
		}
		for _, c := range all {
			w.Human("%s%s%s  %s  %s\n", bold, c.Name, reset, c.Label, c.EntityID)
		}
		return nil
	case "presets":
		keys := make([]string, 0, len(saml.Presets))
		for k := range saml.Presets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := saml.Presets[k]
			w.Human("%-10s %s: %s\n", k, p.Label, p.Where)
		}
		return nil
	case "show", "metadata":
		if len(args) < 2 {
			return samlUsage()
		}
		c, err := findSAML(root, args[1])
		if err != nil {
			return err
		}
		if args[0] == "metadata" {
			_, err := os.Stdout.Write(saml.ServiceMetadata(c.ServiceEntityID(), c.ACS(), time.Now().AddDate(1, 0, 0)))
			return err
		}
		return samlShow(c)
	case "add":
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("setting up single sign-on decides who can become an administrator, "+
				"so it is for an administrator of the whole site: %w", err)
		}
		c, err := samlAdd(root, args[1:])
		if err != nil {
			return err
		}
		return recordE(root, caller.auditRecord("saml.add", "/", audit.Success, map[string]string{
			"provider": c.Name, "entity": c.EntityID, "certs": fmt.Sprint(len(c.Certs)),
			"domains": strings.Join(c.Domains, ","), "required": fmt.Sprint(c.Required),
			"mfa": fmt.Sprint(c.RequireMFA)}))
	case "remove":
		if len(args) < 2 {
			return samlUsage()
		}
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("removing single sign-on is for an administrator of the whole site: %w", err)
		}
		if err := removeSAML(root, args[1]); err != nil {
			return err
		}
		w.Human("removed %s; nobody can sign in through it\n", args[1])
		return recordE(root, caller.auditRecord("saml.remove", "/", audit.Success,
			map[string]string{"provider": args[1]}))
	}
	return samlUsage()
}

func findSAML(root, name string) (*saml.Config, error) {
	all, err := loadSAML(root)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("there is no identity provider called %q", name)
}

func samlShow(c *saml.Config) error {
	if w.JSON(c) {
		return nil
	}
	w.Human("%s%s%s %s\n", bold, c.Name, reset, c.Label)
	w.Human("  its entity ID    %s\n  signs in at      %s\n", c.EntityID, c.SSOURL)
	w.Human("\n  give the identity provider:\n")
	w.Human("    entity ID      %s\n    ACS URL        %s\n    metadata       %s\n", c.ServiceEntityID(), c.ACS(), c.MetadataURL())
	certs, err := c.Certificates()
	if err != nil {
		return err
	}
	w.Human("\n  trusted certificates:\n")
	for _, cert := range certs {
		w.Human("    %s  %s, expires %s\n", saml.Fingerprint(cert), cert.Subject.CommonName,
			cert.NotAfter.UTC().Format("2 Jan 2006"))
	}
	if len(c.Domains) > 0 {
		w.Human("\n  domains %s%s\n", strings.Join(c.Domains, ", "), map[bool]string{true: " (required)"}[c.Required])
	}
	if c.RequireMFA {
		w.Human("  a second factor is required\n")
	}
	return nil
}

func samlAdd(root string, args []string) (*saml.Config, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return nil, samlUsage()
	}
	name := args[0]
	fs := flag.NewFlagSet("saml add", flag.ContinueOnError)
	meta := fs.String("metadata", "", "the provider's metadata: a file, or an https address")
	adminURL := fs.String("url", "", "this admin's address as the provider reaches it")
	preset := fs.String("preset", "", "okta, entra, google, jumpcloud, onelogin, pingone, adfs or keycloak")
	label := fs.String("label", "", "the name on the sign-in button")
	domains := fs.String("domain", "", "the organisation's domain(s), comma-separated")
	principal := fs.String("principal", "", `"nameid" (the default) or "attribute:NAME"`)
	required := fs.Bool("required", false, "people in the domains must sign in this way")
	breakGlass := fs.String("break-glass", "", "people who may still use a token or passkey, comma-separated")
	mfa := fs.Bool("require-mfa", false, "refuse a sign-in the provider does not say used a second factor")
	fingerprint := fs.String("fingerprint", "", "the SHA-256 fingerprint you checked at the provider")
	replace := fs.Bool("replace", false, "replace a provider with this name")
	if err := fs.Parse(args[1:]); err != nil {
		return nil, err
	}
	if *meta == "" || *adminURL == "" {
		return nil, samlUsage()
	}
	var raw []byte
	var err error
	if strings.HasPrefix(*meta, "https://") || strings.HasPrefix(*meta, "http://") {
		raw, err = samlFetch(*meta)
	} else if *meta == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	} else {
		raw, err = os.ReadFile(*meta)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the metadata: %w", err)
	}
	m, err := saml.ParseMetadata(raw)
	if err != nil {
		return nil, err
	}
	c := saml.Config{Name: name, URL: strings.TrimRight(*adminURL, "/"), EntityID: m.EntityID,
		SSOURL: m.SSOURL, Principal: *principal, Required: *required, RequireMFA: *mfa, Preset: *preset}
	if p, ok := saml.Presets[*preset]; ok {
		c.Label, c.MFAContexts, c.MFAAttribute, c.MFAValues, c.NameIDFormat =
			p.Label, p.MFAContexts, p.MFAAttribute, p.MFAValues, p.NameIDFormat
	} else if *preset != "" {
		return nil, fmt.Errorf("%q is not a preset; quilzo saml presets lists them", *preset)
	}
	if *label != "" {
		c.Label = *label
	}
	for _, d := range strings.Split(*domains, ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			c.Domains = append(c.Domains, d)
		}
	}
	for _, b := range strings.Split(*breakGlass, ",") {
		if b = strings.ToLower(strings.TrimSpace(b)); b != "" {
			c.BreakGlass = append(c.BreakGlass, b)
		}
	}
	var fps []string
	match := false
	want := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(*fingerprint)), ":", "")
	for _, cert := range m.Certs {
		fp := saml.Fingerprint(cert)
		fps = append(fps, fp)
		match = match || (want != "" && strings.ReplaceAll(fp, ":", "") == want)
		c.Certs = append(c.Certs, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !match {
		// The decision a person makes: nothing is saved until they have
		// compared the key with what the provider's own console shows.
		w.Human("%s%s%s says it is %s and signs people in at %s.\n", bold, name, reset, m.EntityID, m.SSOURL)
		w.Human("Whoever holds this key can sign anybody in as anybody. Compare it with the\n" +
			"fingerprint your identity provider's admin console shows:\n\n")
		for _, fp := range fps {
			w.Human("  %s\n", fp)
		}
		w.Human("\nthen run the same command again with --fingerprint and that value.\n")
		return nil, errors.New("not saved: the certificate has not been confirmed")
	}
	if existing, _ := findSAML(root, name); existing != nil && !*replace {
		return nil, fmt.Errorf("%s is already set up; add --replace to change it", name)
	}
	if m.WantsSignedRequests {
		w.Human("%snote: the metadata asks for signed requests; Quilzo sends unsigned ones, so turn "+
			"that requirement off for this application at the provider%s\n", dim, reset)
	}
	c.Added, c.AddedBy = time.Now().Unix(), resolveCaller(root, "").Name
	if err := saveSAML(root, c); err != nil {
		return nil, err
	}
	w.Human("set up %s%s%s. Give the identity provider:\n", bold, name, reset)
	w.Human("  entity ID   %s\n  ACS URL     %s\n  metadata    %s\n", c.ServiceEntityID(), c.ACS(), c.MetadataURL())
	return &c, nil
}
