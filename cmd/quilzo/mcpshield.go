// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/shield"
)

// What Quilzo is doing to protect itself, for an agent: read-only. Lifting,
// blocking and changing a playbook are a person's. A security team's queue
// — findings, cases, vulnerabilities, the estate — is Vaigil's, and its
// agents reach it through Vaigil's own interface.

func registerShieldOps(srv *mcp.Server, root string, caller *Caller) {
	srv.Register(mcp.Operation{
		Name: "shield_status", NeedsRole: "admin",
		Summary: "what Quilzo is doing to protect itself: protections in " +
			"force, the playbooks and how often each has been right",
		Detail: "Each protection in force (what it blocks or turns down, " +
			"where, until when, and which playbook stage or person set it), " +
			"whether every playbook is held to watching, each playbook's " +
			"mode and trigger, its verdicts and precision, and how many " +
			"changes wait for a second administrator. Sources appear only " +
			"as audit-log handles; where decoys were planted is not " +
			"returned. Read-only: lifting, blocking, holding and changing a " +
			"playbook are a person's, on the Shield screen or the command " +
			"line.",
		Keywords: []string{"shield", "block", "protection", "lockdown", "freeze",
			"playbook", "self-protection", "attack"},
	}, func(map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActView, auth.AreaSecurity); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		st, err := shield.Load(root)
		if err != nil {
			return nil, err
		}
		bk, err := shield.LoadBook(root)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		type prot struct {
			ID    string `json:"id"`
			What  string `json:"what"`
			Kind  string `json:"kind"`
			Until string `json:"until"`
			By    string `json:"by"`
			Stage int    `json:"stage,omitempty"`
		}
		type book struct {
			Name      string `json:"name"`
			Title     string `json:"title"`
			Mode      string `json:"mode"`
			Signal    string `json:"signal"`
			Per       string `json:"per"`
			Count     int    `json:"count"`
			Within    string `json:"within"`
			Precision string `json:"precision"`
		}
		var active []prot
		for _, p := range st.Active(now) {
			active = append(active, prot{ID: p.ID, What: shield.Describe(p), Kind: p.Kind,
				Until: p.Until.UTC().Format(time.RFC3339), By: p.By, Stage: p.Stage})
		}
		recs := map[string]shield.Record{}
		for _, r := range shield.Records(st) {
			recs[r.Playbook] = r
		}
		var pbs []book
		for _, pb := range bk.InForce() {
			pbs = append(pbs, book{Name: pb.Name, Title: pb.Title, Mode: pb.Mode, Signal: pb.On.Signal,
				Per: pb.On.Per, Count: pb.On.Count, Within: time.Duration(pb.On.Within).String(),
				Precision: precisionWords(recs[pb.Name])})
		}
		return map[string]any{"active": active, "held": st.Watching != nil, "playbooks": pbs,
			"waiting_for_a_second_administrator": len(bk.Pending), "decoys_planted": len(st.Decoys)}, nil
	})
}
