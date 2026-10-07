// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// What agents remember between runs. See internal/memory.

func memoryStore(root string) *memory.Store {
	return &memory.Store{Dir: filepath.Join(root, "memory")}
}

// runMemory is a run's memory: about the person who started it, kept for
// as long as the agent declares.
func runMemory(root string, m agent.Manifest, caller *Caller, runID string) agentexec.Memory {
	store := memoryStore(root)
	who := caller.Name
	return agentexec.Memory{About: who,
		Remember: func(kind, text string, held bool, sources, tier string) (memory.Entry, error) {
			about := who
			if kind == memory.Procedural {
				about = ""
			}
			e, err := store.Remember(memory.Entry{Agent: m.Name, About: about, Kind: kind, Text: text,
				Run: runID, By: who, Held: held, Sources: sources, Tier: tier}, time.Duration(m.Memory.Retain), time.Now())
			if err == nil {
				record(root, actorRecord(caller, "memory.remembered", audit.Success, m, programOrModel(m),
					map[string]string{"agent": m.Name, "run": runID, "memory": e.ID, "kind": kind,
						"held": strconv.FormatBool(e.Held), "tier": e.Tier}))
			}
			return e, err
		},
		Recall: func(query string, kinds map[string]bool) ([]memory.Entry, error) {
			return store.Recall(m.Name, who, query, kinds, agentexec.MaxRecalled, time.Now())
		}}
}

// programOrModel names what decided, for a memory record: the run's own
// record says which; here it is enough that an agent wrote it.
func programOrModel(m agent.Manifest) programModel {
	if m.Program != nil {
		return programModel{name: filepath.Base(m.Program.Command[0])}
	}
	return programModel{name: "a model"}
}

// cmdMemory is `quilzo memory list|confirm|delete|edit|forget|receipt`.
func cmdMemory(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, flagToken)
	admin := authorise(root, caller, auth.ActGrant, "/") == nil
	store := memoryStore(root)
	// Whose memory a caller may see and change: their own, or anybody's
	// for an administrator.
	mayTouch := func(e memory.Entry) error {
		if admin || (e.About != "" && e.About == caller.Name && caller.Verified) {
			return nil
		}
		return errors.New("that memory is not about you; an administrator can change it")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("memory list", flag.ContinueOnError)
		agentName := fs.String("agent", "", "one agent's")
		about := fs.String("about", "", "about one person (yourself, unless you administer)")
		held := fs.Bool("held", false, "only what waits for a person to confirm it")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if !admin {
			if *about != "" && *about != caller.Name {
				return errors.New("you see what agents remember about you; an administrator sees anybody's")
			}
			*about = caller.Name
		}
		list, err := store.List(memory.Filter{Agent: *agentName, About: *about, Held: *held})
		if err != nil {
			return err
		}
		if !admin {
			// Procedural memory is about nobody and listed for administrators.
			kept := list[:0]
			for _, e := range list {
				if e.About == caller.Name {
					kept = append(kept, e)
				}
			}
			list = kept
		}
		if w.JSON(list) {
			return nil
		}
		if len(list) == 0 {
			w.Human("nothing is remembered%s\n", map[bool]string{true: "", false: " about you"}[admin])
			return nil
		}
		for _, e := range list {
			state := ""
			if e.Held {
				state = yellow + " held" + reset
			}
			about := e.About
			if about == "" {
				about = "everybody (procedure)"
			}
			tier := ""
			if words := memory.TierWords[e.Tier]; words != "" {
				tier = ", " + words
			}
			w.Human("%s%s%s%s  %s, %s, about %s%s, until %s\n    %s\n", bold, e.ID, reset, state, e.Agent, e.Kind, about,
				tier, e.Expires.Format("2 Jan 2006"), clip(e.Text, 300))
			if e.Held && e.Sources != "" {
				w.Human("    %slearnt after reading: %s%s\n", dim, clip(e.Sources, 200), reset)
			}
		}
		return nil
	case "confirm", "delete":
		if len(args) != 2 {
			return fmt.Errorf("quilzo memory %s ID", args[0])
		}
		e, err := store.Get(args[1])
		if err != nil {
			return err
		}
		if err := mayTouch(e); err != nil {
			return err
		}
		if args[0] == "confirm" {
			set, _ := loadAgents(root)
			retain := time.Duration(0)
			if set != nil {
				retain = time.Duration(set.Agents[e.Agent].Memory.Retain)
			}
			if _, err := store.Confirm(e.ID, caller.Name, time.Now(), retain); err != nil {
				return err
			}
		} else if _, err := store.Delete(e.ID); err != nil {
			return err
		}
		if err := recordE(root, caller.auditRecord("memory."+args[0]+"ed", "/memory", audit.Success,
			memoryDetail(e))); err != nil {
			return err
		}
		w.Human("%sed %s\n", strings.TrimSuffix(args[0], "e"), e.ID)
		return nil
	case "edit":
		if len(args) < 3 {
			return errors.New("quilzo memory edit ID TEXT")
		}
		e, err := store.Get(args[1])
		if err != nil {
			return err
		}
		// The person it is about, or an administrator for an agent's own
		// procedures: nobody rewrites what is remembered about somebody else.
		if !((e.About != "" && e.About == caller.Name && caller.Verified) || (e.About == "" && admin)) {
			return errors.New("only the person a memory is about rewrites it; an administrator can delete it")
		}
		e, err = store.Edit(e.ID, strings.Join(args[2:], " "), caller.Name, time.Now())
		if err != nil {
			return err
		}
		if err := recordE(root, caller.auditRecord("memory.edited", "/memory", audit.Success, memoryDetail(e))); err != nil {
			return err
		}
		w.Human("rewrote %s; it is recalled as you wrote it\n", e.ID)
		return nil
	case "receipt":
		fs := flag.NewFlagSet("memory receipt", flag.ContinueOnError)
		about := fs.String("about", "", "the person; yourself unless you administer")
		out := fs.String("o", "", "write it here instead of printing it")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *about == "" {
			*about = caller.Name
		}
		if *about != caller.Name && !admin {
			return errors.New("a receipt about somebody else is an administrator's")
		}
		rf, err := buildMemoryReceipt(root, *about, time.Now())
		if err != nil {
			return err
		}
		if rf == nil {
			return fmt.Errorf("nothing has been forgotten, deleted or rewritten about %s", *about)
		}
		body, err := json.MarshalIndent(rf, "", " ")
		if err != nil {
			return err
		}
		if *out == "" {
			_, err = os.Stdout.Write(append(body, '\n'))
			return err
		}
		if err := os.WriteFile(*out, body, 0o600); err != nil {
			return err
		}
		w.Human("%s about %s, each with its proof, against a head of %d signed by %s\n",
			count(len(rf.Entries), "record"), *about, rf.Head.Size, rf.Head.KeyID)
		w.Human("  %scheck it anywhere: quilzo agent verify-receipt %s --keys head.pub.json%s\n", dim, *out, reset)
		return nil
	case "forget":
		fs := flag.NewFlagSet("memory forget", flag.ContinueOnError)
		about := fs.String("about", "", "the person; yourself unless you administer")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *about == "" {
			*about = caller.Name
		}
		if *about != caller.Name && !admin {
			return errors.New("you can have agents forget you; forgetting somebody else is an administrator's")
		}
		n, err := forgetPerson(root, *about, caller.Name)
		if err != nil {
			return err
		}
		w.Human("every agent has forgotten %s: %s removed\n", *about, count(n, "memory"))
		return nil
	}
	return fmt.Errorf("unknown memory command %q; try list, confirm, delete, edit, forget or receipt", args[0])
}

// forgetPerson removes everything any agent remembers about somebody, and
// records which entries, by id.
func forgetPerson(root, about, by string) (int, error) {
	gone, err := memoryStore(root).Forget(about)
	if err != nil {
		return 0, err
	}
	record(root, audit.Record{Action: "memory.forgotten", Resource: "/memory", Outcome: audit.Success,
		Principal: by, Kind: audit.KindHuman, Verified: true,
		Detail: map[string]string{"subject": about, "count": strconv.Itoa(len(gone)),
			"memories": clip(strings.Join(gone, " "), 2000)}})
	return len(gone), nil
}

// memoryJob removes expired memory on the server's schedule.
func memoryJob(root string) upkeep.Job {
	return upkeep.Job{Name: "memory", Do: func(now time.Time) (int, error) {
		gone, err := memoryStore(root).Sweep(now)
		if len(gone) > 0 {
			record(root, audit.Record{Action: "memory.expired", Resource: "/memory", Outcome: audit.Success,
				Principal: "quilzo", Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"count": strconv.Itoa(len(gone))}})
		}
		return len(gone), err
	}}
}

// memoryAdmin is the Memory screen's hooks.
func memoryAdmin(root string) *admin.MemoryAdmin {
	store := memoryStore(root)
	note := func(action, id, by string, e memory.Entry) {
		record(root, audit.Record{Action: action, Resource: "/memory", Outcome: audit.Success,
			Principal: by, Kind: audit.KindHuman, Verified: true, Detail: memoryDetail(e)})
	}
	return &admin.MemoryAdmin{Store: store,
		Confirm: func(id, by string) error {
			e, err := store.Get(id)
			if err != nil {
				return err
			}
			retain := time.Duration(0)
			if set, err := loadAgents(root); err == nil {
				retain = time.Duration(set.Agents[e.Agent].Memory.Retain)
			}
			if _, err := store.Confirm(id, by, time.Now(), retain); err != nil {
				return err
			}
			note("memory.confirmed", id, by, e)
			return nil
		},
		Delete: func(id, by string) error {
			e, err := store.Delete(id)
			if err != nil {
				return err
			}
			note("memory.deleted", id, by, e)
			return nil
		},
		Edit: func(id, text, by string) error {
			e, err := store.Edit(id, text, by, time.Now())
			if err != nil {
				return err
			}
			note("memory.edited", id, by, e)
			return nil
		},
		Forget: func(about, by string) (int, error) { return forgetPerson(root, about, by) },
		Receipt: func(about string) ([]byte, error) {
			rf, err := buildMemoryReceipt(root, about, time.Now())
			if err != nil || rf == nil {
				return nil, err
			}
			return json.MarshalIndent(rf, "", " ")
		},
	}
}

// memoryDetail is what the log says about a change to one memory: which,
// whose and about whom, never what it said.
func memoryDetail(e memory.Entry) map[string]string {
	d := map[string]string{"memory": e.ID, "agent": e.Agent, "kind": e.Kind}
	if e.About != "" {
		d["subject"] = e.About
	}
	return d
}

// memoryReceiptFormat is the receipt of what was forgotten, deleted or
// rewritten about one person.
const memoryReceiptFormat = "quilzo-memory-receipt/1"

// buildMemoryReceipt is every record of memory about somebody being
// forgotten, deleted or rewritten, each with its proof; nil when there is
// none.
//
// The log names the person by a handle only its key makes, so the receipt
// carries the handle as its subject, which is what anybody checking it
// compares, and the name for the person reading it.
func buildMemoryReceipt(root, about string, now time.Time) (*agentReceiptFile, error) {
	log, err := openAudit(root)
	if err != nil {
		return nil, err
	}
	handle := about
	if log.Pseudonymous() {
		handle = audit.Pseudonym(log.Key(), about)
	}
	rf := &agentReceiptFile{Format: memoryReceiptFormat, Subject: handle, Person: about, Made: now.UTC()}
	err = proveRecords(root, rf, now, func(e audit.Event) bool {
		return memoryReceiptAction[e.Action] && e.Detail["subject"] == handle
	})
	if err != nil || len(rf.Entries) == 0 {
		return nil, err
	}
	return rf, nil
}

var memoryReceiptAction = map[string]bool{"memory.forgotten": true, "memory.deleted": true, "memory.edited": true}
