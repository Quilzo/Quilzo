// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/marking"
	"github.com/quilzo/quilzo/internal/outpost"
	"github.com/quilzo/quilzo/internal/public"
)

// The public instance (internal/outpost), from both sides: on its own host,
// `quilzo init --profile public` makes it and `quilzo serve --profile public`
// serves it; on the internal instance, `quilzo public` says where it is and
// sends it what was published, one way, signed.

// publicDir is a public instance's directory under its root.
func publicDir(root string) string { return filepath.Join(root, "public") }

// isPublicInstance reports whether root is a public instance's.
func isPublicInstance(root string) bool { return outpost.IsInstance(publicDir(root)) }

// errPublicInstance is what the admin, the site and init say on a public
// instance's root: it has no admin, and nothing here may give it one.
func errPublicInstance(root, what string) error {
	return errBlocked{fmt.Errorf("%s is a public instance, which %s: it serves what the internal instance "+
		"sends it, with quilzo serve --profile public, and holds no admin, no register and no secret", root, what)}
}

// initPublicInstance makes a public instance at root, pinned to the
// internal instance's published head keys.
func initPublicInstance(root, pin string) error {
	if isStore(root) && !isPublicInstance(root) {
		if found := publicSecrets(root); len(found) > 0 || hasRefs(root) {
			return errBlocked{fmt.Errorf("%s holds a store already. A public instance is made in a directory of "+
				"its own, on a host of its own, so a bug in what it serves reaches nothing but what was published", root)}
		}
	}
	body, err := os.ReadFile(pin)
	if err != nil {
		return fmt.Errorf("cannot read the key to pin: %w", err)
	}
	// An empty store, so the commands that look for one find it; nothing is
	// ever written to it.
	if _, err := makeStore(root); err != nil {
		return err
	}
	if err := outpost.Init(publicDir(root), body, time.Now()); err != nil {
		return err
	}
	in, err := outpost.Open(publicDir(root))
	if err != nil {
		return err
	}
	w.Human("a public instance, pinned to key %s\n", in.KeyID())
	w.Human("  %sit takes transfers signed by that key and nothing else, and holds no admin, no register and no secret%s\n", dim, reset)
	w.Human("  %sserve it on its own host:%s quilzo --root %s serve --profile public --addr 0.0.0.0:8090\n", dim, reset, root)
	w.Human("  %sand on the internal instance:%s quilzo public target https://THIS-HOST\n", dim, reset)
	return nil
}

// hasRefs reports whether a store holds any ref: content, a register, a
// draft. A public instance holds none.
func hasRefs(root string) bool {
	found := false
	_ = filepath.Walk(filepath.Join(root, "refs"), func(path string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			found = true
		}
		return nil
	})
	return found
}

// publicSecrets is every file a root holds outside the public instance's
// own directory, which a public instance must not hold: its configuration
// is the pinned key and its content what it was sent, both under public/,
// so anything else is a store's, and may be a secret.
//
// Every file and not a list of secrets: a list named the tokens, the vault
// and the signing key, and let a root holding the second-factor secrets,
// the provenance key or the pseudonymisation key start as a public
// instance, and would have let next year's secret do the same. The named
// ones are said first, by name, since they are what a person needs to see.
func publicSecrets(root string) []string {
	var found []string
	said := map[string]bool{}
	for _, p := range []string{tokensPath(root), passkeysPath(root), keyringPath(root), agentSecretsPath(root),
		headKeyPath(root), connectionsPath(root), scimTokenPath(root), oidcPath(root), policyPath(root)} {
		if fileExists(p) {
			found, said[filepath.Clean(p)] = append(found, filepath.Base(p)), true
		}
	}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || said[filepath.Clean(path)] {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		if rel = filepath.ToSlash(rel); !strings.HasPrefix(rel, "public/") {
			found = append(found, rel)
		}
		return nil
	})
	if len(found) > 12 {
		found = append(found[:12], fmt.Sprintf("and %d more", len(found)-12))
	}
	return found
}

// publicHandler is the public instance at root as `serve --profile public`
// serves it, offline and refusing to start on a root that holds anything
// secret.
func publicHandler(root string) (http.Handler, *outpost.Instance, error) {
	if found := publicSecrets(root); len(found) > 0 {
		return nil, nil, errBlocked{fmt.Errorf("a public instance holds no secret, and %s holds %s. Remove them, "+
			"or serve this store as the internal instance it is", root, strings.Join(found, ", "))}
	}
	if hasRefs(root) {
		return nil, nil, errBlocked{fmt.Errorf("a public instance holds no register and no site, and %s holds refs", root)}
	}
	// Offline: the public instance opens no connection off its host, so a
	// bug in a handler cannot reach the internal instance or anything else.
	if err := egress.SetMode(egress.Offline); err != nil {
		return nil, nil, err
	}
	in, err := outpost.Open(publicDir(root))
	if err != nil {
		return nil, nil, err
	}
	return in.Handler(), in, nil
}

// servesPublic reports whether `serve` was asked for the public profile.
func servesPublic(args []string) bool {
	for i, a := range args {
		switch strings.TrimLeft(a, "-") {
		case "profile=public":
			return true
		case "profile":
			if i+1 < len(args) && args[i+1] == "public" {
				return true
			}
		}
	}
	return false
}

// servePublic is `quilzo serve --profile public`.
func servePublic(root string, args []string) error {
	fs := flag.NewFlagSet("serve --profile public", flag.ContinueOnError)
	fs.String("profile", "public", "public: serve this public instance")
	addr := fs.String("addr", "127.0.0.1:8090", "listen address")
	intake := fs.Bool("intake", true, "take transfers posted to "+outpost.IntakePath+"; off takes them only from quilzo public import")
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}
	h, in, err := publicHandler(root)
	if err != nil {
		return err
	}
	in.Intake = *intake
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10}
	fmt.Printf("public instance on http://%s, pinned to key %s\n", *addr, in.KeyID())
	fmt.Printf("  %sit serves the attestation page, the head feed and security.txt, and holds no admin, "+
		"no register and no secret; it opens no connection off this host%s\n", dim, reset)
	if st := in.Status(); st.Problem != "" {
		fmt.Fprintf(os.Stderr, "  %s%s%s\n", noteYellow, st.Problem, noteReset)
	} else if st.Served == nil {
		fmt.Printf("  %snothing has been sent to it yet%s\n", dim, reset)
	}
	return srv.ListenAndServe()
}

// publicBindWarning is what the internal instance says when it listens on
// an address the internet can reach: every interface, or a public address.
// Empty on loopback and on a private network.
func publicBindWarning(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if host == "localhost" {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	const where = "The internal instance belongs on an internal network, and the public faces on a " +
		"public instance of their own (quilzo init --profile public)"
	switch {
	case ip.IsUnspecified():
		return "the admin listens on every interface, which is a public address on any host that has one. " + where
	case ip.IsLoopback(), ip.IsPrivate(), ip.IsLinkLocalUnicast(), sharedAddressSpace.Contains(ip):
		return ""
	}
	return "the admin listens on " + host + ", a public address. " + where
}

// sharedAddressSpace is RFC 6598's 100.64.0.0/10, which a carrier's network
// or an overlay network such as a mesh VPN numbers its hosts from and the
// internet does not route. An admin reached that way is on a network of its
// own, and calling its address public would be untrue.
var sharedAddressSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// -- the internal instance's side --------------------------------------------

func publicTargetPath(root string) string { return filepath.Join(root, "public-target.json") }
func publicHeadsPath(root string) string  { return filepath.Join(root, "public-heads.json") }
func publicSentPath(root string) string   { return filepath.Join(root, "public-sent.json") }

// publishedAttestationsPath is the file last published, kept so a fresh
// head can be sent with it without a second approval of what was approved.
func publishedAttestationsPath(root string) string {
	return filepath.Join(root, "attestations.published.json")
}

// publicTarget is where transfers go: the public instance's address, or a
// directory a transfer is written to for carrying.
type publicTarget struct {
	To string `json:"to"`
}

func loadTarget(root string) (string, error) {
	var t publicTarget
	if err := loadJSON(publicTargetPath(root), &t); err != nil {
		return "", err
	}
	return t.To, nil
}

// checkTarget refuses a target that is neither an http(s) address nor an
// absolute directory.
func checkTarget(to string) error {
	if u, err := url.Parse(to); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errMisused{errors.New("the public instance's address carries no credentials, query or fragment")}
		}
		return nil
	}
	if filepath.IsAbs(to) {
		return nil
	}
	return errMisused{fmt.Errorf("%q is neither an https address nor an absolute directory", to)}
}

// publicSent is the last transfer sent.
type publicSent struct {
	Digest     string    `json:"digest"`
	At         time.Time `json:"at"`
	To         string    `json:"to"`
	ApprovedBy string    `json:"approved_by"`
	Alone      bool      `json:"alone,omitempty"`
	Request    string    `json:"request,omitempty"`
	Head       int       `json:"head_size"`
	Created    string    `json:"created"`
}

// publication is one send: who approved it and why.
type publication struct {
	approvers []string
	alone     bool
	request   string
	reason    string
	by        *Caller
}

// publishProjection builds the projection from the attestations file at
// path, signs it as a transfer and sends it to the target: the one way
// anything reaches the public instance.
func publishProjection(root, path string, p publication) (publicSent, error) {
	to, err := loadTarget(root)
	if err != nil {
		return publicSent{}, err
	}
	if to == "" {
		return publicSent{}, errBlocked{errors.New("there is nowhere to send it: quilzo public target " +
			"https://PUBLIC-HOST says where the public instance is, or a directory to carry it from")}
	}
	now := time.Now()
	body, err := os.ReadFile(path)
	if err != nil {
		return publicSent{}, err
	}
	file, err := parseAttestations(body, now)
	if err != nil {
		return publicSent{}, err
	}
	signer, err := headSigner(root)
	if err != nil {
		return publicSent{}, err
	}
	feed, head, err := nextHeadFeed(root, signer, now)
	if err != nil {
		return publicSent{}, err
	}
	stage, err := os.MkdirTemp(root, "public-out-")
	if err != nil {
		return publicSent{}, err
	}
	defer os.RemoveAll(stage)
	enc, err := file.Encode()
	if err != nil {
		return publicSent{}, err
	}
	files := map[string][]byte{outpost.AttestationsFile: enc, outpost.FeedFile: feed}
	if cfg, err := loadConfig(root); err == nil {
		if c, err := securityContactFrom(cfg); err != nil {
			return publicSent{}, err
		} else if c != nil {
			base := ""
			if u, err := url.Parse(to); err == nil && u.Host != "" {
				base = u.Scheme + "://" + u.Host
			}
			files[outpost.SecurityTxtFile] = []byte(public.SecurityText(c, base))
		}
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(stage, name), b, 0o600); err != nil {
			return publicSent{}, err
		}
	}
	banner, err := deploymentBanner(root)
	if err != nil {
		return publicSent{}, err
	}
	t, err := marking.RecordTransfer(stage, marking.Transfer{Banner: banner,
		Approved: strings.Join(p.approvers, ", "), Carried: "quilzo public send", Reason: p.reason,
		From: "internal", To: "public"}, now)
	if err != nil {
		return publicSent{}, err
	}
	if err := marking.SignTransfer(stage, signer); err != nil {
		return publicSent{}, err
	}
	if err := deliver(stage, to, now); err != nil {
		return publicSent{}, err
	}
	sent := publicSent{Digest: file.Digest(), At: now.UTC(), To: to, ApprovedBy: strings.Join(p.approvers, ", "),
		Alone: p.alone, Request: p.request, Head: head.Size, Created: t.Created}
	// Each person under an identity key of their own, so the log
	// pseudonymises them one by one as it does everybody it names.
	detail := map[string]string{"digest": sent.Digest, "to": to, "proposed_by": p.approvers[0],
		"reason": p.reason, "head_size": fmt.Sprint(head.Size), "head_root": head.Root, "transfer": t.Created}
	if len(p.approvers) > 1 {
		detail["approved_by"] = p.approvers[1]
	}
	if p.alone {
		detail["alone"] = "true"
	}
	if p.request != "" {
		detail["request"] = p.request
	}
	if err := recordE(root, p.by.auditRecord("public.published", "/security/public", audit.Success, detail)); err != nil {
		return publicSent{}, err
	}
	if err := atomicfile.Write(publishedAttestationsPath(root), enc, 0o600); err != nil {
		return publicSent{}, err
	}
	if err := saveJSON(publicSentPath(root), sent); err != nil {
		return publicSent{}, err
	}
	return sent, nil
}

// sentHeads is the heads sent so far, which is the feed.
type sentHeads struct {
	Heads []audit.SignedHead `json:"heads"`
}

// nextHeadFeed signs the log's head now, adds it to the heads already sent
// and returns the feed to send.
func nextHeadFeed(root string, signer headSigning, now time.Time) ([]byte, audit.SignedHead, error) {
	events, err := auditEntries(root)
	if err != nil {
		return nil, audit.SignedHead{}, err
	}
	head, err := audit.TreeHead(events, now)
	if err != nil {
		return nil, audit.SignedHead{}, err
	}
	signed, err := signer.Sign(head)
	if err != nil {
		return nil, audit.SignedHead{}, err
	}
	var hf sentHeads
	if err := loadJSON(publicHeadsPath(root), &hf); err != nil {
		return nil, audit.SignedHead{}, err
	}
	hf.Heads = append(hf.Heads, signed)
	if n := len(hf.Heads); n > outpost.MaxHeads {
		hf.Heads = hf.Heads[n-outpost.MaxHeads:]
	}
	if err := saveJSON(publicHeadsPath(root), hf); err != nil {
		return nil, audit.SignedHead{}, err
	}
	body, err := json.MarshalIndent(outpost.HeadFeed{Format: 1, KeyID: signer.Verifier().KeyID(), Heads: hf.Heads}, "", "  ")
	if err != nil {
		return nil, audit.SignedHead{}, err
	}
	return append(body, '\n'), signed, nil
}

// deliver sends a signed transfer: posted to the public instance's intake,
// or written to a directory for carrying. Outbound only: the answer to a
// post is read for whether it was taken, and nothing in it is kept.
func deliver(stage, to string, now time.Time) error {
	if strings.HasPrefix(to, "http://") || strings.HasPrefix(to, "https://") {
		body, err := outpost.Pack(stage)
		if err != nil {
			return err
		}
		resp, err := egress.Client("public-transfer", 60*time.Second).Post(strings.TrimSuffix(to, "/")+outpost.IntakePath,
			"application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("the public instance could not be reached: %w", err)
		}
		defer resp.Body.Close()
		said, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode != http.StatusOK {
			var e struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(said, &e)
			if e.Error == "" {
				e.Error = strings.TrimSpace(string(said))
			}
			return fmt.Errorf("the public instance refused the transfer (%s): %s", resp.Status, e.Error)
		}
		return nil
	}
	dir := filepath.Join(to, now.UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(stage, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// cmdPublic is `quilzo public key | target [URL|DIR] | send | status |
// import DIR`.
func cmdPublic(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return publicStatus(root)
	case "import":
		return publicImport(root, args[1:])
	}
	if isPublicInstance(root) {
		return errPublicInstance(root, "is sent transfers and sends none")
	}
	switch args[0] {
	case "key":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
		return publicKey(root)
	case "target":
		return publicTargetCmd(root, args[1:])
	case "send":
		return publicSend(root, args[1:])
	}
	return errMisused{fmt.Errorf("unknown public command %q; try status, key, target, send or import", args[0])}
}

func publicKey(root string) error {
	signer, err := headSigner(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]string{"key_id": signer.Verifier().KeyID(), "file": headKeysPath(root)}) {
		return nil
	}
	w.Human("%skey %s%s\n", bold, signer.Verifier().KeyID(), reset)
	w.Human("  the public half is %s: copy it to the public host, and pin it there with\n", headKeysPath(root))
	w.Human("    quilzo --root DIR init --profile public --pin head.pub.json\n")
	return nil
}

func publicTargetCmd(root string, args []string) error {
	if len(args) == 0 {
		to, err := loadTarget(root)
		if err != nil {
			return err
		}
		if w.JSON(map[string]string{"to": to}) {
			return nil
		}
		if to == "" {
			w.Human("nowhere yet: quilzo public target https://PUBLIC-HOST, or an absolute directory to carry transfers from\n")
			return nil
		}
		w.Human("%s\n", to)
		return nil
	}
	if len(args) != 1 {
		return errMisused{errors.New("usage: quilzo public target [https://PUBLIC-HOST | /DIRECTORY]")}
	}
	c := resolveCaller(root, "")
	if err := setTarget(root, c, args[0]); err != nil {
		return err
	}
	// Under --json, where transfers go now, as the line with no address
	// answers it: setting one confirmed only in prose, so a script got an
	// empty stdout and exit 0, as from a line that had set nothing.
	to, err := loadTarget(root)
	if err != nil {
		return err
	}
	w.JSON(map[string]string{"to": to})
	return nil
}

// setTarget says where transfers go, as c, an administrator, recorded.
func setTarget(root string, c *Caller, to string) error {
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return err
	}
	to = strings.TrimSpace(to)
	if err := checkTarget(to); err != nil {
		return err
	}
	if err := recordE(root, c.auditRecord("public.target", "/security/public", audit.Success,
		map[string]string{"to": to})); err != nil {
		return err
	}
	if err := saveJSON(publicTargetPath(root), publicTarget{To: to}); err != nil {
		return err
	}
	w.Human("transfers go to %s\n", to)
	return nil
}

// publicSend sends again what was last published, with a fresh head of the
// record: what it carries was approved by two people when it was published,
// and the head is the log's own, signed.
func publicSend(root string, args []string) error {
	fs := flag.NewFlagSet("public send", flag.ContinueOnError)
	reason := fs.String("reason", "a fresh head of the record", "why, for the record")
	if err := parseFlags(fs, args, nil, 0); err != nil {
		return err
	}
	c := resolveCaller(root, "")
	sent, err := resendPublished(root, c, *reason)
	if err != nil {
		return err
	}
	if w.JSON(sent) {
		return nil
	}
	w.Human("%ssent%s to %s, with the head of %d entries\n", bold, reset, sent.To, sent.Head)
	return nil
}

func resendPublished(root string, c *Caller, reason string) (publicSent, error) {
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return publicSent{}, err
	}
	if !fileExists(publishedAttestationsPath(root)) {
		return publicSent{}, errNotFound{errors.New("nothing has been published to the public instance yet: " +
			"quilzo attest publish --reason WHY proposes the first publication")}
	}
	var last publicSent
	if err := loadJSON(publicSentPath(root), &last); err != nil {
		return publicSent{}, err
	}
	approvers := []string{last.ApprovedBy + " (sent again by " + c.Name + ")"}
	return publishProjection(root, publishedAttestationsPath(root), publication{approvers: approvers,
		alone: last.Alone, request: last.Request, reason: reason, by: c})
}

// publicImport is `quilzo public import DIR`, on the public host: a
// transfer carried to it rather than posted.
func publicImport(root string, args []string) error {
	if len(args) != 1 {
		return errMisused{errors.New("usage: quilzo public import DIR")}
	}
	if !isPublicInstance(root) {
		return errBlocked{fmt.Errorf("%s is not a public instance; a transfer is imported on the public host", root)}
	}
	in, err := outpost.Open(publicDir(root))
	if err != nil {
		return err
	}
	rc, err := in.Import(args[0], time.Now())
	if err != nil {
		var no outpost.Refused
		if errors.As(err, &no) {
			return errBlocked{err}
		}
		return err
	}
	if w.JSON(rc) {
		return nil
	}
	w.Human("%staken%s: made %s, approved by %s; served from the next request\n", bold, reset, rc.Created, rc.Approved)
	return nil
}

func publicStatus(root string) error {
	if isPublicInstance(root) {
		in, err := outpost.Open(publicDir(root))
		if err != nil {
			return err
		}
		st := in.Status()
		if w.JSON(st) {
			return nil
		}
		w.Human("%sa public instance%s, pinned to key %s\n", bold, reset, st.KeyID)
		switch {
		case st.Problem != "":
			w.Human("  %s%s%s\n", yellow, st.Problem, reset)
		case st.Served == nil:
			w.Human("  nothing has been sent to it yet\n")
		default:
			w.Human("  serving what was made %s, approved by %s\n", st.Served.Created, st.Served.Approved)
		}
		return nil
	}
	if err := authorise(root, resolveCaller(root, ""), auth.ActView, "/"); err != nil {
		return err
	}
	v, err := viewPublic(root)
	if err != nil {
		return err
	}
	if w.JSON(v) {
		return nil
	}
	w.Human("%sthe public instance%s: %s\n", bold, reset, orDash(v.Target))
	if v.Sent != nil {
		w.Human("  last sent %s, approved by %s, with the head of %d entries\n",
			v.Sent.At.Format("2 January 2006 15:04 MST"), v.Sent.ApprovedBy, v.Sent.Head)
	} else {
		w.Human("  nothing sent yet\n")
	}
	if v.Waiting != "" {
		w.Human("  %sa publication waits for a second administrator: request %s%s\n", yellow, v.Waiting, reset)
	}
	return nil
}

// publicInstanceHooks is the Public instance screen's wiring: the same
// view, draft, target and publication as the command line.
func publicInstanceHooks(root string, signedIn func(admin.Actor) *Caller) *admin.PublicInstance {
	return &admin.PublicInstance{
		View: func() (admin.PublicView, error) {
			v, err := viewPublic(root)
			if err != nil {
				return admin.PublicView{}, err
			}
			out := admin.PublicView{Target: v.Target, KeyID: v.KeyID, Draft: v.Draft, Digest: v.Digest,
				Problem: v.Problem, Waiting: v.Waiting}
			if body, err := os.ReadFile(attestationsPath(root)); err == nil {
				out.DraftText = string(body)
			}
			if s := v.Sent; s != nil {
				out.Sent = &admin.PublicSent{Digest: s.Digest, To: s.To, ApprovedBy: s.ApprovedBy, At: s.At,
					Alone: s.Alone, Head: s.Head}
			}
			return out, nil
		},
		SetTarget: func(to string, by admin.Actor) error { return setTarget(root, signedIn(by), to) },
		SetDraft: func(body []byte, by admin.Actor) error {
			_, err := setDraft(root, signedIn(by), body, "admin")
			return err
		},
		Propose: func(reason string, by admin.Actor) (bool, error) {
			return proposePublication(root, signedIn(by), reason)
		},
		Resend: func(reason string, by admin.Actor) error {
			if reason == "" {
				reason = "a fresh head of the record"
			}
			_, err := resendPublished(root, signedIn(by), reason)
			return err
		},
		Keys: func() ([]byte, error) {
			if _, err := headSigner(root); err != nil {
				return nil, err
			}
			return os.ReadFile(headKeysPath(root))
		},
	}
}
