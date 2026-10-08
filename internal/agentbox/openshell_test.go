// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTheOpenShellPolicyAllowsOnlyThisMachine(t *testing.T) {
	s := Spec{Run: "run-20261007-ab12cd34", Agent: "coder", Program: "/usr/local/bin/claude",
		Read: []string{"/opt/agent", "/usr"}}
	p := string(Policy(s, "host.openshell.internal", map[string]int{"mcp": 41001, "proxy": 41003, "model": 41002}))
	for _, want := range []string{
		"version: 1\n",
		"filesystem_policy:\n  include_workdir: true\n  read_only:\n",
		`    - "/opt/agent"`,
		"  read_write:\n    - \"/tmp\"\n    - \"/dev/null\"\n",
		"landlock:\n  compatibility: hard_requirement\n",
		"network_policies:\n  quilzo_run:\n    name: \"quilzo-run-20261007-ab12cd34\"\n",
		"      - host: \"host.openshell.internal\"\n        port: 41001\n        protocol: tcp\n        enforcement: enforce\n",
		"port: 41002", "port: 41003",
		"    binaries:\n      - path: \"/usr/local/bin/claude\"\n",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("the policy lacks %q:\n%s", want, p)
		}
	}
	if strings.Count(p, `"/usr"`) != 1 {
		t.Error("a path is listed twice")
	}
	// Nothing else is reachable: one rule, three endpoints, all this machine.
	if strings.Count(p, "- host:") != 3 || strings.Count(p, "host.openshell.internal") != 3 {
		t.Errorf("endpoints other than this machine:\n%s", p)
	}
	// A value that would end the scalar stays inside it.
	odd := string(Policy(Spec{Run: "r", Agent: "a\"\nb: c", Program: "/x"}, "h", nil))
	if strings.Contains(odd, "\nb: c") {
		t.Errorf("an agent's name broke out of its line:\n%s", odd)
	}
}

func TestTheEnvironmentReachesTheServicesAndCannotBeInjected(t *testing.T) {
	env := envFile([]string{
		"QUILZO_MCP_URL=http://127.0.0.1:8701/mcp",
		"HTTPS_PROXY=http://run:s3cret@127.0.0.1:8703",
		"NO_PROXY=127.0.0.1,localhost",
		"QUILZO_GOAL=fix it'; rm -rf / ; echo '",
	}, "host.openshell.internal", map[uint16]int{8701: 41001, 8703: 41003})
	for _, want := range []string{
		"export QUILZO_MCP_URL='http://host.openshell.internal:41001/mcp'\n",
		"export HTTPS_PROXY='http://run:s3cret@host.openshell.internal:41003'\n",
		"export NO_PROXY='host.openshell.internal'\n",
		`export QUILZO_GOAL='fix it'\''; rm -rf / ; echo '\'''` + "\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("lacks %q:\n%s", want, env)
		}
	}
}

func TestAnOpenShellRunCreatesUsesAndDeletesOneSandbox(t *testing.T) {
	sock, _ := os.MkdirTemp("", "qzos-")
	defer os.RemoveAll(sock)
	ln, err := net.Listen("unix", filepath.Join(sock, "mcp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "the run's interface") }))
	work := t.TempDir()
	var calls [][]string
	var policy, env, reached string
	o := OpenShell{Listen: "127.0.0.1", Reach: "host.openshell.internal", Image: "openclaw",
		Exec: func(ctx context.Context, argv []string, s Spec) (int, error) {
			calls = append(calls, argv)
			if argv[1] != "create" {
				return 0, nil
			}
			for i, a := range argv {
				switch a {
				case "--policy":
					b, _ := os.ReadFile(argv[i+1])
					policy = string(b)
				case "--upload":
					b, _ := os.ReadFile(strings.TrimSuffix(argv[i+1], ":/tmp/.quilzo-env"))
					env = string(b)
				}
			}
			// The sandbox reaching the run's interface on the port its
			// policy names, as the program would.
			for _, l := range strings.Split(env, "\n") {
				if v, ok := strings.CutPrefix(l, "export QUILZO_MCP_URL='http://host.openshell.internal:"); ok {
					port := strings.TrimSuffix(v, "/mcp'")
					res, err := http.Get("http://127.0.0.1:" + port + "/mcp")
					if err == nil {
						b, _ := io.ReadAll(res.Body)
						reached = string(b)
					}
				}
			}
			return 3, errors.New("the gateway went away")
		}}
	res, err := o.Run(context.Background(), Spec{Run: "run-1", Agent: "coder", Program: "/usr/local/bin/agent",
		Args: []string{"--goal", "x"}, Workdir: work, Wall: time.Minute,
		Env:      []string{"QUILZO_MCP_URL=http://127.0.0.1:8701/mcp", "QUILZO_RUN_TOKEN=secret"},
		Services: []Service{{Name: "mcp", Socket: filepath.Join(sock, "mcp.sock"), Port: PortMCP}}})
	if err == nil || res.Exit != 3 {
		t.Fatalf("the CLI's failure was not reported: %v %+v", err, res)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "sandbox delete quilzo-run-1" {
		t.Fatalf("calls %q", calls)
	}
	create := strings.Join(calls[0], " ")
	for _, want := range []string{"sandbox create --name quilzo-run-1 --policy ", " --no-tty --upload ",
		" --from openclaw -- /bin/sh -c ", " sh /usr/local/bin/agent --goal x"} {
		if !strings.Contains(create, want) {
			t.Errorf("create lacks %q: %s", want, create)
		}
	}
	if strings.Contains(create, "secret") {
		t.Error("the run's credential is on a command line")
	}
	if !strings.Contains(env, "QUILZO_RUN_TOKEN='secret'") || !strings.Contains(policy, "host.openshell.internal") {
		t.Errorf("env %q policy %q", env, policy)
	}
	if reached != "the run's interface" {
		t.Errorf("the sandbox's port reached %q", reached)
	}
	if _, err := os.Stat(filepath.Join(work, "quilzo-env")); !os.IsNotExist(err) {
		t.Error("the environment file, with the run's credential, was left behind")
	}
}

func TestOpenShellSaysWhatItNeeds(t *testing.T) {
	if a := (OpenShell{CLI: "/nonexistent/openshell"}).Check(); a.OK {
		t.Fatal("available with no address set")
	}
	a := (OpenShell{Exec: func(context.Context, []string, Spec) (int, error) { return 0, nil }}).Check()
	if a.OK || !strings.Contains(a.Why, "agents.openshell_listen") {
		t.Fatalf("%+v", a)
	}
	if n := SandboxName("Run_2026/../x" + strings.Repeat("y", 80)); len(n) > 63 || strings.ContainsAny(n, "_/.") {
		t.Fatalf("%q", n)
	}
}
