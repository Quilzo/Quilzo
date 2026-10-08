// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Quilzo watching itself.
//
// Every security-relevant thing this program does is already in its audit
// log: failed sign-ins past the threshold, tokens issued, access granted,
// settings weakened, the log itself moved, an extension refused. Until now
// that log answered questions somebody thought to ask. It now goes into the
// event store under its own source, so the detection rules — the same
// engine, the same queue, the same incidents as every other platform's
// logs — read it continuously, and a rule pack ships for it (quilzo.*).
//
// This is the application-layer intrusion detection OWASP's AppSensor
// describes: detection points inside the application, where the context
// is, rather than a network sensor guessing from outside.
//
// What is copied is what the audit log holds and nothing more: the action,
// its outcome and resource, the kind of actor, and the few details a rule
// needs. The principal is the pseudonym the log already stores.

// SelfSource is the source Quilzo's own audit records are stored under.
const SelfSource = "quilzo/audit"

// selfDetail are the audit details a rule about Quilzo may read. Others are
// left out: they are either free text somebody typed, or not needed.
var selfDetail = []string{"role", "surface", "failures", "setting", "to",
	"autonomy", "agent", "reason", "conversation"}

type selfCursor struct {
	Seq int64 `json:"seq"`
}

func selfCursorPath(root string) string {
	return filepath.Join(root, "detect", "self.json")
}

// storeSelfEvents copies the audit records written since the last call into
// the event store, and returns them for the rules to read at once. Records
// of what a model did are left to storeAgentEvents, which stores them under their own
// source with the agent as the actor.
func storeSelfEvents(root string, sp *spool.Spool, now time.Time) ([]telemetry.Event, error) {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	var cur selfCursor
	if b, rerr := os.ReadFile(selfCursorPath(root)); rerr == nil {
		if jerr := json.Unmarshal(b, &cur); jerr != nil {
			return nil, fmt.Errorf("self.json: %w", jerr)
		}
	}
	var stored []telemetry.Event
	last := cur.Seq
	for _, e := range events {
		if e.Seq <= cur.Seq {
			continue
		}
		last = e.Seq
		if e.Kind == audit.KindAI {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, e.At)
		if perr != nil {
			at = now
		}
		disposition := telemetry.DispositionAllowed
		switch e.Outcome {
		case audit.Denied:
			disposition = telemetry.DispositionBlocked
		case audit.Failure:
			disposition = telemetry.DispositionFailed
		}
		raw := map[string]string{"action": e.Action, "outcome": string(e.Outcome),
			"resource": e.Resource, "kind": string(e.Kind)}
		for _, k := range selfDetail {
			if v, ok := e.Detail[k]; ok {
				raw[k] = v
			}
		}
		if _, ok := e.Detail["accepted_risk"]; ok {
			// Whether a risk was accepted, not the reason somebody typed.
			raw["accepted_risk"] = "yes"
		}
		ev := telemetry.Event{Time: at, Received: now,
			Class: telemetry.ClassAPIActivity, Disposition: disposition,
			Source: SelfSource, Message: e.Action,
			Actor: telemetry.ID{Issuer: "quilzo", Value: e.Principal},
			Raw:   raw}
		if _, aerr := sp.Append(ev); aerr != nil {
			return stored, aerr
		}
		stored = append(stored, ev)
	}
	if last == cur.Seq {
		return stored, nil
	}
	b, _ := json.Marshal(selfCursor{Seq: last})
	if err := os.MkdirAll(filepath.Dir(selfCursorPath(root)), 0o700); err != nil {
		return stored, err
	}
	return stored, atomicfile.Write(selfCursorPath(root), b, 0o600)
}
