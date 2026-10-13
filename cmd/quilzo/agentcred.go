// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agentcred"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// Agent credentials (internal/agentcred): what another vendor's agent
// presents at /mcp/browser/NAME in place of a person's token. Issued by an
// administrator for an agent declared here with a sponsor, bound to the
// agent's own key, kept in a register so each can be withdrawn, and
// accepted only with a proof made by that key for that request.

// credKeyPath is the issuer's signing seed; credKeysPath its public half,
// as a JSON Web Key Set anybody may have.
func credKeyPath(root string) string  { return filepath.Join(agentsDir(root), "credential.key") }
func credKeysPath(root string) string { return filepath.Join(agentsDir(root), "credential.jwks.json") }
func credRegPath(root string) string  { return filepath.Join(agentsDir(root), "credentials.json") }

// issuedCred is one credential in the register.
type issuedCred struct {
	ID      string    `json:"id"`
	Agent   string    `json:"agent"`
	Sponsor string    `json:"sponsor"`
	Grant   string    `json:"grant"`
	Act     bool      `json:"act,omitempty"`
	Holder  string    `json:"holder"`
	Issued  time.Time `json:"issued"`
	Until   time.Time `json:"until"`
	By      string    `json:"by"`
	Revoked time.Time `json:"revoked,omitzero"`
}

// credIssuer loads the issuer key, creating it and publishing its public
// half on first use.
func credIssuer(root string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(credKeyPath(root))
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(agentsDir(root), 0o700); err != nil {
			return nil, err
		}
		// 0600: whoever reads this can issue credentials in this store's name.
		if err := atomicfile.Write(credKeyPath(root), []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
			return nil, err
		}
		key := ed25519.NewKeyFromSeed(seed)
		jwks, err := agentcred.JWKS(key.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
		return key, atomicfile.Write(credKeysPath(root), jwks, 0o644)
	}
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not an Ed25519 seed", credKeyPath(root))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// credPublicKeys are the keys credentials are checked against.
func credPublicKeys(root string) (map[string]ed25519.PublicKey, error) {
	key, err := credIssuer(root)
	if err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	return map[string]ed25519.PublicKey{agentcred.KeyID(pub): pub}, nil
}

func loadCredRegister(root string) ([]issuedCred, error) {
	var reg []issuedCred
	b, err := readBounded(credRegPath(root), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return reg, json.Unmarshal(b, &reg)
}

func changeCredRegister(root string, change func([]issuedCred) ([]issuedCred, error)) error {
	unlock, err := atomicfile.Lock(credRegPath(root) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	reg, err := loadCredRegister(root)
	if err != nil {
		return err
	}
	if reg, err = change(reg); err != nil {
		return err
	}
	b, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(credRegPath(root), b, 0o600)
}

// issuerName is what a credential names its issuer: the admin's address
// when one is set, or a URN naming the key.
func issuerName(root string, key ed25519.PrivateKey) string {
	if c, err := loadConfig(root); err == nil && c.Raw("admin.base_url") != "" {
		return strings.TrimSuffix(c.Raw("admin.base_url"), "/")
	}
	return "urn:quilzo:issuer:" + agentcred.KeyID(key.Public().(ed25519.PublicKey))
}

// agentCredentialCmd is `quilzo agent credential issue|list|revoke|verify|keys`.
func agentCredentialCmd(root string, args []string) error {
	usage := errors.New(`usage: quilzo agent credential issue NAME --grant browser:G [--act] (--holder did:key:… | --generate FILE) [--for 24h]
       quilzo agent credential list [NAME] | revoke ID | verify FILE | keys`)
	if len(args) == 0 {
		return usage
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "keys":
		if _, err := credIssuer(root); err != nil {
			return err
		}
		b, err := os.ReadFile(credKeysPath(root))
		if err != nil {
			return err
		}
		fmt.Print(string(b))
		return nil
	case "list":
		reg, err := loadCredRegister(root)
		if err != nil {
			return err
		}
		if w.JSON(map[string]any{"credentials": reg}) {
			return nil
		}
		now := time.Now()
		for _, c := range reg {
			if len(args) > 1 && c.Agent != args[1] {
				continue
			}
			state := "valid until " + c.Until.Format("2 Jan 2006 15:04")
			switch {
			case !c.Revoked.IsZero():
				state = "withdrawn " + c.Revoked.Format("2 Jan 2006")
			case !now.Before(c.Until):
				state = "expired"
			}
			act := "read"
			if c.Act {
				act = "act"
			}
			fmt.Printf("  %s  %-14s %-20s %-5s %s\n", c.ID, c.Agent, c.Grant, act, state)
		}
		return nil
	case "revoke":
		if len(args) != 2 {
			return usage
		}
		if err := revokeCredential(root, caller, args[1]); err != nil {
			return err
		}
		fmt.Printf("  %s%s is withdrawn; it is refused from its next request%s\n", green, args[1], reset)
		return nil
	case "verify":
		if len(args) != 2 {
			return usage
		}
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		keys, err := credPublicKeys(root)
		if err != nil {
			return err
		}
		c, err := checkCredential(root, strings.TrimSpace(string(b)), keys, time.Now().UTC())
		if err != nil {
			return err
		}
		fmt.Printf("  %svalid%s: %s for %s, answered for by %s, %s, until %s\n", green, reset,
			c.Grant, c.Agent, c.Sponsor, map[bool]string{true: "may act", false: "reads only"}[c.Act],
			c.ValidUntil.Format("2 Jan 2006 15:04 UTC"))
		return nil
	case "issue":
		tok, err := issueCredential(root, caller, args[1:])
		if err != nil {
			return err
		}
		fmt.Println(tok)
		return nil
	}
	return usage
}

// revokeCredential withdraws a credential in force.
func revokeCredential(root string, caller *Caller, id string) error {
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	found := false
	if err := changeCredRegister(root, func(reg []issuedCred) ([]issuedCred, error) {
		for i := range reg {
			if reg[i].ID == id && reg[i].Revoked.IsZero() {
				reg[i].Revoked, found = time.Now().UTC(), true
			}
		}
		return reg, nil
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no credential %s is in force", id)
	}
	record(root, caller.auditRecord("agent.credential.revoke", "/", audit.Success, map[string]string{"credential": id}))
	return nil
}

func issueCredential(root string, caller *Caller, args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("quilzo agent credential issue NAME --grant browser:G [--act] (--holder did:key:… | --generate FILE) [--for 24h]")
	}
	name := args[0]
	fs := flag.NewFlagSet("agent credential issue", flag.ContinueOnError)
	grant := fs.String("grant", "", "the one grant it may use, as browser:NAME")
	act := fs.Bool("act", false, "it may act on pages, not only read them")
	holderDID := fs.String("holder", "", "the agent's own public key, as a did:key")
	generate := fs.String("generate", "", "make the agent's key here instead, written to this file")
	lifetime := fs.Duration("for", 24*time.Hour, "how long it is valid, up to 720h")
	if err := fs.Parse(args[1:]); err != nil {
		return "", err
	}
	if caller.Kind == audit.KindAI {
		return "", errors.New("a credential is issued by a person: a model that could issue one could give itself a way in")
	}
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return "", fmt.Errorf("issuing a credential is an administrator's: %w", err)
	}
	set, err := loadAgents(root)
	if err != nil {
		return "", err
	}
	if _, ok := set.Agents[name]; !ok {
		return "", fmt.Errorf("no agent called %s is declared; declare it, and name who answers for it, first", name)
	}
	id := set.identityOf(name)
	now := time.Now().UTC()
	switch {
	case id == nil || id.Sponsor == "":
		return "", fmt.Errorf("nobody answers for %s yet (quilzo agent sponsor %s PERSON)", name, name)
	case !hasStanding(root, id.Sponsor):
		return "", fmt.Errorf("%s's sponsor, %s, can no longer act here", name, id.Sponsor)
	case !id.Expires.IsZero() && !now.Before(id.Expires):
		return "", fmt.Errorf("%s has not been renewed; it does not run, and it gets no credential", name)
	}
	g, ok := strings.CutPrefix(*grant, "browser:")
	if !ok {
		return "", errors.New("a credential carries one grant, as --grant browser:NAME")
	}
	if _, _, offered := browserGrantOffered(root, g); !offered {
		return "", fmt.Errorf("no browser grant called %s is offered here", g)
	}
	until := now.Add(*lifetime)
	if !id.Expires.IsZero() && id.Expires.Before(until) {
		until = id.Expires
	}
	var holder ed25519.PublicKey
	switch {
	case *holderDID != "" && *generate == "":
		if holder, err = agentcred.PublicFromDIDKey(*holderDID); err != nil {
			return "", err
		}
	case *generate != "" && *holderDID == "":
		pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return "", gerr
		}
		holder = pub
		if err := atomicfile.Write(*generate, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
			return "", err
		}
	default:
		return "", errors.New("name the agent's own key with --holder did:key:…, or make one with --generate FILE")
	}
	key, err := credIssuer(root)
	if err != nil {
		return "", err
	}
	tok, err := agentcred.Issue(key, issuerName(root, key), agentcred.Credential{Agent: name, Sponsor: id.Sponsor,
		Grant: *grant, Act: *act, Holder: holder, ValidUntil: until}, now)
	if err != nil {
		return "", err
	}
	keys, _ := credPublicKeys(root)
	c, err := agentcred.Verify(tok, keys, now)
	if err != nil {
		return "", err
	}
	if err := changeCredRegister(root, func(reg []issuedCred) ([]issuedCred, error) {
		return append(reg, issuedCred{ID: c.ID, Agent: name, Sponsor: id.Sponsor, Grant: *grant, Act: *act,
			Holder: agentcred.DIDKey(holder), Issued: now, Until: c.ValidUntil, By: caller.Name}), nil
	}); err != nil {
		return "", err
	}
	record(root, caller.auditRecord("agent.credential.issue", "/", audit.Success, map[string]string{
		"agent": name, "credential": c.ID, "grant": *grant, "act": fmt.Sprint(*act),
		"until": c.ValidUntil.Format(time.RFC3339)}))
	return tok, nil
}

// checkCredential verifies a credential and that it is still in force:
// issued here and not withdrawn, for an agent still declared, with a
// sponsor who can still act here, for a grant still offered.
func checkCredential(root, tok string, keys map[string]ed25519.PublicKey, now time.Time) (agentcred.Credential, error) {
	c, err := agentcred.Verify(tok, keys, now)
	if err != nil {
		return c, err
	}
	reg, err := loadCredRegister(root)
	if err != nil {
		return c, err
	}
	var entry *issuedCred
	for i := range reg {
		if reg[i].ID == c.ID {
			entry = &reg[i]
		}
	}
	switch {
	case entry == nil:
		return c, errors.New("this store has no record of issuing it")
	case !entry.Revoked.IsZero():
		return c, errors.New("it was withdrawn")
	case entry.Holder != agentcred.DIDKey(c.Holder) || entry.Grant != c.Grant || entry.Agent != c.Agent:
		return c, errors.New("it does not match what was issued")
	}
	set, err := loadAgents(root)
	if err != nil {
		return c, err
	}
	if _, ok := set.Agents[c.Agent]; !ok {
		return c, fmt.Errorf("%s is no longer declared", c.Agent)
	}
	if id := set.identityOf(c.Agent); id == nil || id.Sponsor != c.Sponsor || !hasStanding(root, c.Sponsor) {
		return c, fmt.Errorf("%s's sponsor is no longer %s, or can no longer act here", c.Agent, c.Sponsor)
	}
	g, _ := strings.CutPrefix(c.Grant, "browser:")
	if _, _, ok := browserGrantOffered(root, g); !ok {
		return c, fmt.Errorf("the grant %s is no longer offered", g)
	}
	return c, nil
}

// credReplays are the proofs already accepted by this process.
var credReplays = &agentcred.Replays{}

// credentialCaller turns a presented credential and its proof into the
// caller a browser grant is answered for: the agent, acting within its
// sponsor's authority on the one grant it carries.
func credentialCaller(root string, r *http.Request, tok, url, grant string) (auth.Token, error) {
	keys, err := credPublicKeys(root)
	if err != nil {
		return auth.Token{}, err
	}
	now := time.Now().UTC()
	c, err := checkCredential(root, tok, keys, now)
	if err != nil {
		return auth.Token{}, fmt.Errorf("the agent credential is refused: %w", err)
	}
	if c.Grant != "browser:"+grant {
		return auth.Token{}, fmt.Errorf("the agent credential is for %s, not browser:%s", c.Grant, grant)
	}
	if err := agentcred.CheckProof(c, r.Header.Get("Agent-Proof"), r.Method, url, now, credReplays); err != nil {
		return auth.Token{}, fmt.Errorf("the agent credential is refused: %w", err)
	}
	role := auth.RoleReader
	if c.Act {
		role = auth.RoleAuthor
	}
	return auth.Token{ID: c.ID, Name: "credential " + c.ID, Principal: c.Sponsor, Role: role,
		Resource: "/mcp/browser/" + grant, Client: "agent:" + c.Agent, Grant: c.ID,
		CreatedAt: c.ValidFrom.Unix(), ExpiresAt: c.ValidUntil.Unix()}, nil
}
