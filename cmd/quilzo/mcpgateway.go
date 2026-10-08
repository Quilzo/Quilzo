// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/automate"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/mcpclient"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/shield"
)

// The governed MCP gateway: Quilzo in front of the company's MCP servers.
//
// Other vendors' agents (Claude, ChatGPT, Copilot, an agent somebody wrote)
// reach a company's MCP servers through Quilzo rather than directly, at
// /mcp/gateway/NAME on the admin, with the same tokens and app connections
// as Quilzo's own interface. What they are offered is what a person agreed
// to and pinned: the integration's Uses, each tool's definition as it was
// on the day it was approved, unchanged since. Every call is then checked
// here before it is forwarded: the role the integration is offered to, the
// person's access to it, the shield, a daily count per caller, and for the
// tools a person approves call by call, that person's decision. The
// server's credential is Quilzo's, injected by the client; the caller never
// holds it. Every call is one record in the signed log, naming the app, the
// person it acted for, the tool and a digest of the arguments, never the
// arguments themselves.

func gatewayDir(root string) string { return filepath.Join(root, "gateway") }

// heldCall is a call waiting for, or decided by, a person.
type heldCall struct {
	ID          string    `json:"id"`
	Integration string    `json:"integration"`
	Tool        string    `json:"tool"`
	Principal   string    `json:"principal"`
	Client      string    `json:"client,omitempty"`
	Digest      string    `json:"digest"`
	Args        string    `json:"args"`
	Asked       time.Time `json:"asked"`
	Decided     time.Time `json:"decided,omitzero"`
	By          string    `json:"by,omitempty"`
	Approved    bool      `json:"approved,omitempty"`
	Used        bool      `json:"used,omitempty"`
}

// gatewayState is the held calls and each day's counts.
type gatewayState struct {
	Held []heldCall                `json:"held"`
	Days map[string]map[string]int `json:"days"`
}

// How long things last: a call waits a day for a decision, and an approval
// lets exactly that call through once, within the hour.
const (
	heldWaits    = 24 * time.Hour
	approvalLast = time.Hour
	maxHeld      = 500
)

var gatewayMu sync.Mutex

func gatewayStatePath(root string) string { return filepath.Join(gatewayDir(root), "state.json") }

func loadGatewayState(root string) (*gatewayState, error) {
	st := &gatewayState{Days: map[string]map[string]int{}}
	b, err := os.ReadFile(gatewayStatePath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("the gateway's state cannot be read: %w", err)
	}
	if st.Days == nil {
		st.Days = map[string]map[string]int{}
	}
	return st, nil
}

// saveGatewayState keeps two days of counts and the held calls still
// worth showing.
func saveGatewayState(root string, st *gatewayState, now time.Time) error {
	today, yesterday := now.UTC().Format("2006-01-02"), now.UTC().Add(-24*time.Hour).Format("2006-01-02")
	for d := range st.Days {
		if d != today && d != yesterday {
			delete(st.Days, d)
		}
	}
	kept := st.Held[:0]
	for _, h := range st.Held {
		if now.Sub(h.Asked) < 7*24*time.Hour {
			kept = append(kept, h)
		}
	}
	if len(kept) > maxHeld {
		kept = kept[len(kept)-maxHeld:]
	}
	st.Held = kept
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(gatewayDir(root), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(gatewayStatePath(root), b, 0o600)
}

// gatewayOffered is the integration offered through the gateway under a
// name, when it is: declared, enabled, an MCP server, and offered.
func gatewayOffered(root, name string) (agent.Integration, bool) {
	set, err := loadIntegrations(root)
	if err != nil {
		return agent.Integration{}, false
	}
	for _, in := range set.Declared {
		if in.Name == name {
			return in, in.Enabled && in.Kind == agent.IntegrationMCP && in.Gateway != nil
		}
	}
	return agent.Integration{}, false
}

// gatewayClient is the client the gateway forwards through; a test hands
// in its own.
var gatewayClient = func(root string) *mcpclient.Client { return newMCPClient(root) }

// gatewayServer is what one caller is offered of one integration.
func gatewayServer(r *http.Request, root, name string, tok auth.Token) (*mcp.Server, error) {
	in, ok := gatewayOffered(root, name)
	if !ok {
		return nil, fmt.Errorf("%s is not offered through the gateway", name)
	}
	mc := gatewayClient(root)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	defs, err := mc.Definitions(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("%s could not be asked what it offers: %w", name, err)
	}
	var tools []mcp.Tool
	for _, t := range offeredTools(defs) {
		var schema map[string]any
		_ = json.Unmarshal(t.InputSchema, &schema)
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		tools = append(tools, mcp.Tool{Name: t.Name, Description: plaintext.Clean(t.Description), InputSchema: schema,
			Annotations: map[string]any{"readOnlyHint": !in.Writes, "openWorldHint": true}})
	}
	caller := remoteCaller(tok)
	srv := mcp.NewServer("quilzo-gateway-"+name, version)
	srv.Direct = &mcp.Direct{
		Instructions: "The tools of " + name + " (" + in.Purpose + "), through Quilzo: each call is checked " +
			"and recorded, and some wait for a person to approve them.",
		Tools: tools,
		Call: func(tool string, args map[string]any) (string, error) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()
			return gatewayCall(ctx, root, in, mc, tool, args, caller, tok, time.Now())
		},
	}
	return srv, nil
}

// offeredTools are the tools a person agreed to and pinned, and which are
// still what was pinned.
func offeredTools(defs []mcpclient.Tool) []mcpclient.Tool {
	var out []mcpclient.Tool
	for _, t := range defs {
		if t.Allowed && t.Matches() {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// gatewayCall checks one call and forwards it, and records it whatever
// happens.
func gatewayCall(ctx context.Context, root string, in agent.Integration, mc *mcpclient.Client, tool string,
	args map[string]any, caller *Caller, tok auth.Token, now time.Time) (out string, err error) {

	g := *in.Gateway
	digest := argsDigest(in.Name, tool, args)
	held := ""
	defer func() {
		d := map[string]string{"integration": in.Name, "tool": tool, "on_behalf_of": tok.Principal, "args_digest": digest}
		if tok.Grant != "" {
			d["grant"] = tok.Grant
		}
		if held != "" {
			d["held"] = held
		}
		outcome := audit.Success
		if err != nil {
			outcome, d["error"] = audit.Denied, clip(err.Error(), 300)
			var ref *mcp.Refusal
			var se *mcp.ScopeError
			if !errors.As(err, &ref) && !errors.As(err, &se) {
				outcome = audit.Failure
			}
		}
		who, kind := tok.Principal, audit.KindHuman
		if tok.Client != "" {
			who, kind = "app:"+tok.Client, audit.KindAI
		}
		record(root, audit.Record{Action: "mcp.gateway", Resource: "/integrations/" + in.Name, Outcome: outcome,
			Principal: who, Kind: kind, Model: tok.Client, Verified: true, Detail: d})
	}()
	refuse := func(why string) (string, error) { return "", &mcp.Refusal{Reason: why} }

	if err := remoteRefusal(root, caller, auth.Role(g.Role)); err != nil {
		return "", err
	}
	if p, off := shield.Find(root, shield.Feature, "mcp", now); off && p.Level == shield.Off {
		return refuse("the machine interface is turned off until about " + p.Until.UTC().Format("15:04 UTC") + ": " + p.Reason)
	}
	action, err := actionForRole(g.Role)
	if err != nil {
		return "", err
	}
	if err := authorise(root, caller, action, "/integrations/"+in.Name); err != nil {
		return refuse(err.Error())
	}
	who := gatewayCallerKey(tok)
	gatewayMu.Lock()
	st, err := loadGatewayState(root)
	if err != nil {
		gatewayMu.Unlock()
		return "", err
	}
	day := now.UTC().Format("2006-01-02")
	if st.Days[day] == nil {
		st.Days[day] = map[string]int{}
	}
	key := who + "|" + in.Name
	if st.Days[day][key] >= g.DailyLimit() {
		gatewayMu.Unlock()
		return refuse(fmt.Sprintf("this caller has made %d calls to %s today, which is as many as a caller may", st.Days[day][key], in.Name))
	}
	if g.Asks(tool) {
		id, ok, why := decideHeld(st, in.Name, tool, digest, tok, args, now)
		held = id
		if !ok {
			err := saveGatewayState(root, st, now)
			gatewayMu.Unlock()
			if err != nil {
				return "", err
			}
			if why == heldNew {
				tellHeld(root, in.Name, tool, id, tok)
				return refuse("a person approves each call of " + tool + " on " + in.Name + ". This one is held as " + id +
					": call again with the same arguments once they have decided")
			}
			return refuse(why)
		}
	}
	st.Days[day][key]++
	err = saveGatewayState(root, st, now)
	gatewayMu.Unlock()
	if err != nil {
		return "", err
	}
	return mc.Call(ctx, in, tool, args)
}

const heldNew = "new"

// decideHeld finds what a person decided about exactly this call, or
// holds it: ok says it may go ahead, and why says why not.
func decideHeld(st *gatewayState, integration, tool, digest string, tok auth.Token, args map[string]any, now time.Time) (string, bool, string) {
	// Only the newest decision about exactly this call counts: one used,
	// lapsed or long declined is asked again.
newest:
	for i := len(st.Held) - 1; i >= 0; i-- {
		h := &st.Held[i]
		if h.Integration != integration || h.Tool != tool || h.Digest != digest || h.Principal != tok.Principal || h.Client != tok.Client {
			continue
		}
		switch {
		case h.Decided.IsZero() && now.Sub(h.Asked) < heldWaits:
			return h.ID, false, "still waiting for a person to decide about " + h.ID
		case !h.Decided.IsZero() && !h.Approved && now.Sub(h.Decided) < heldWaits:
			return h.ID, false, h.ID + " was declined by " + h.By
		case h.Approved && !h.Used && now.Sub(h.Decided) < approvalLast:
			h.Used = true
			return h.ID, true, ""
		}
		break newest
	}
	b, _ := json.Marshal(args)
	id := "gq_" + randomHex(6)
	st.Held = append(st.Held, heldCall{ID: id, Integration: integration, Tool: tool, Principal: tok.Principal,
		Client: tok.Client, Digest: digest, Args: clip(string(b), 4000), Asked: now.UTC()})
	return id, false, heldNew
}

// tellHeld tells the security contact a call is waiting for them.
func tellHeld(root, integration, tool, id string, tok auth.Token) {
	notify := automationActions(root)["notify"]
	if notify.Run == nil {
		return
	}
	by := tok.Principal
	if tok.Client != "" {
		by = tok.Client + " for " + tok.Principal
	}
	ev := automate.Event{Kind: "signal", Subject: "gateway:" + integration, At: time.Now(),
		Summary: fmt.Sprintf("%s asks to call %s on %s, which a person approves call by call (%s). "+
			"Decide on Integrations, or with quilzo integrations approve %s.", by, tool, integration, id, id),
		Fields: map[string]string{"signal": "gateway-held"}}
	_, _ = notify.Run(ev, map[string]string{"to": "security"})
}

// gatewayDecide approves or declines a held call. Somebody other than the
// person it acts for decides, and an administrator.
func gatewayDecide(root, id string, approve bool, by *Caller, now time.Time) error {
	if err := authorise(root, by, auth.ActGrant, "/"); err != nil {
		return fmt.Errorf("deciding what other systems' agents may do is an administrator's: %w", err)
	}
	gatewayMu.Lock()
	defer gatewayMu.Unlock()
	st, err := loadGatewayState(root)
	if err != nil {
		return err
	}
	for i := range st.Held {
		h := &st.Held[i]
		if h.ID != id {
			continue
		}
		switch {
		case !h.Decided.IsZero():
			return fmt.Errorf("%s was already decided by %s", id, h.By)
		case now.Sub(h.Asked) >= heldWaits:
			return fmt.Errorf("%s waited more than a day and has lapsed; the caller asks again", id)
		case h.Principal == by.Name:
			return errors.New("a call made for you is decided by somebody else")
		}
		h.Decided, h.By, h.Approved = now.UTC(), by.Name, approve
		if err := saveGatewayState(root, st, now); err != nil {
			return err
		}
		return recordE(root, by.auditRecord("mcp.gateway.decided", "/integrations/"+h.Integration, audit.Success,
			map[string]string{"held": id, "tool": h.Tool, "approved": strconv.FormatBool(approve), "on_behalf_of": h.Principal}))
	}
	return fmt.Errorf("no held call is %q", id)
}

// heldCalls are the calls waiting for a person, oldest first.
func heldCalls(root string, now time.Time) ([]heldCall, error) {
	st, err := loadGatewayState(root)
	if err != nil {
		return nil, err
	}
	var out []heldCall
	for _, h := range st.Held {
		if h.Decided.IsZero() && now.Sub(h.Asked) < heldWaits {
			out = append(out, h)
		}
	}
	return out, nil
}

// gatewayCallerKey is who a call is counted against: the app and the
// person it acts for, or the person.
func gatewayCallerKey(tok auth.Token) string {
	if tok.Client != "" {
		return tok.Client + "|" + tok.Principal
	}
	return tok.Principal
}

// argsDigest is a digest of a call: which tool, and its arguments in a
// canonical form. The log keeps this, never the arguments.
func argsDigest(integration, tool string, args map[string]any) string {
	b, _ := json.Marshal(args) // map keys are sorted
	sum := sha256.Sum256(append([]byte(integration+"\x00"+tool+"\x00"), b...))
	return hex.EncodeToString(sum[:])[:32]
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
