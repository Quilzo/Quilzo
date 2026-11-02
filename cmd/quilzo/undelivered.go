// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// Writes agents made that did not get through, after being tried as often
// as was safe (internal/mcpclient retries a write only with its
// idempotency key): listed for a person to see and settle, never sent
// again by themselves. Which run and step, which integration and tool,
// the key, and what the far side said; never the arguments, which the
// run's own record holds for whoever may read it.
//
//	quilzo integrations undelivered [--dismiss N | --clear]

// MaxUndelivered is how many are kept; past it the oldest go.
const MaxUndelivered = 500

var undeliveredMu sync.Mutex

func undeliveredPath(root string) string { return filepath.Join(root, "undelivered.jsonl") }

// keepUndelivered keeps one, and records that it happened.
func keepUndelivered(root string) func(agentexec.Undelivered) {
	return func(u agentexec.Undelivered) {
		undeliveredMu.Lock()
		defer undeliveredMu.Unlock()
		list, _ := loadUndelivered(root)
		list = append(list, u)
		if len(list) > MaxUndelivered {
			list = list[len(list)-MaxUndelivered:]
		}
		_ = saveUndelivered(root, list)
		record(root, audit.Record{Action: "integration.undelivered", Resource: "/integrations/" + u.Integration,
			Outcome: audit.Failure, Principal: "quilzo", Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"agent": u.Agent, "tool": u.Tool, "run": u.Run, "step": strconv.Itoa(u.Step), "write": u.Key}})
	}
}

func loadUndelivered(root string) ([]agentexec.Undelivered, error) {
	f, err := os.Open(undeliveredPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []agentexec.Undelivered
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		var u agentexec.Undelivered
		if json.Unmarshal(sc.Bytes(), &u) == nil {
			out = append(out, u)
		}
	}
	return out, sc.Err()
}

func saveUndelivered(root string, list []agentexec.Undelivered) error {
	if len(list) == 0 {
		if err := os.Remove(undeliveredPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	var b []byte
	for _, u := range list {
		line, err := json.Marshal(u)
		if err != nil {
			return err
		}
		b = append(append(b, line...), '\n')
	}
	return atomicfile.Write(undeliveredPath(root), b, 0o600)
}

// dismissUndelivered takes one off the list, by its place in it (1 is the
// oldest), or all of them when n is 0.
func dismissUndelivered(root string, n int) (int, error) {
	undeliveredMu.Lock()
	defer undeliveredMu.Unlock()
	list, err := loadUndelivered(root)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return len(list), saveUndelivered(root, nil)
	}
	if n < 1 || n > len(list) {
		return 0, fmt.Errorf("there is no undelivered write %d; there are %d", n, len(list))
	}
	list = append(list[:n-1], list[n:]...)
	return 1, saveUndelivered(root, list)
}

// integrationsUndelivered is quilzo integrations undelivered.
func integrationsUndelivered(root string, args []string) error {
	caller := resolveCaller(root, flagToken)
	dismiss, clear := 0, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--clear":
			clear = true
		case "--dismiss":
			if i+1 >= len(args) {
				return errors.New("--dismiss needs the number the list shows")
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 1 {
				return errors.New("--dismiss needs the number the list shows")
			}
			dismiss, i = v, i+1
		default:
			return fmt.Errorf("usage: quilzo integrations undelivered [--dismiss N | --clear]")
		}
	}
	if clear || dismiss > 0 {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return err
		}
		n, err := dismissUndelivered(root, dismiss)
		if err != nil {
			return err
		}
		record(root, caller.auditRecord("integration.undelivered.dismissed", "/integrations", audit.Success,
			map[string]string{"count": strconv.Itoa(n)}))
		w.Human("  %sdismissed %d%s\n", green, n, reset)
		return nil
	}
	list, err := loadUndelivered(root)
	if err != nil {
		return err
	}
	if w.JSON(list) {
		return nil
	}
	if len(list) == 0 {
		w.Human("  %severy write agents made got through%s\n", green, reset)
		return nil
	}
	for i, u := range list {
		w.Human("%s%d%s  %s%s %s%s by %s, %s\n", bold, i+1, reset, yellow, u.Integration, u.Tool, reset, u.Agent,
			u.At.Local().Format("2 Jan 15:04"))
		w.Human("    %s%s%s\n", dim, u.Error, reset)
		if u.Run != "" {
			w.Human("    %srun %s, step %d, key %s%s\n", dim, u.Run, u.Step, u.Key, reset)
		}
	}
	w.Human("\n  %snot sent again by itself: settle it at the far side, then quilzo integrations undelivered --dismiss N%s\n", dim, reset)
	return nil
}
