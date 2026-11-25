// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// network.mode offline holds on the command line when the configuration
// does not load. The mode was read through the configuration as a whole and
// a file that would not load left the default, open, so one unknown key, a
// value of the wrong type or a file cut off by a full disk ran every command
// at an offline deployment with the network on, and `quilzo network` said
// open. A file refused for something else still says what the mode is; one
// that cannot say holds the command offline, and says why.
func TestABrokenConfigurationDoesNotTurnTheNetworkBackOn(t *testing.T) {
	root := filepath.Join(t.TempDir(), "st")
	if _, e, code := cliRun(t, root, "", "init"); code != 0 {
		t.Fatalf("init: %s", e)
	}
	for _, c := range []struct {
		what, body, want string
		said             bool
	}{
		{"an unknown key", `{"values":{"network.mode":"offline","auth.thottle":"false"}}`, "offline", false},
		{"a value of the wrong type", `{"values":{"network.mode":"offline","api.page.max":5}}`, "offline", false},
		{"a truncated file", `{"values":{"network.mode":"offline","site.na`, "offline", true},
		{"the mode written twice", `{"values":{"network.mode":"offline","network.mode":"open"}}`, "offline", true},
		{"the mode of the wrong type", `{"values":{"network.mode":false}}`, "offline", true},
		{"an unknown key, open", `{"values":{"network.mode":"open","auth.thottle":"false"}}`, "open", false},
	} {
		if err := os.WriteFile(configPath(root), []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		o, e, code := cliRun(t, root, "", "--json", "network")
		var got struct{ Mode string }
		if code != 0 || json.Unmarshal([]byte(o), &got) != nil {
			t.Errorf("%s: network exited %d: %s", c.what, code, firstLines(o+e, 4))
			continue
		}
		if got.Mode != c.want {
			t.Errorf("%s: the network is %q, want %q", c.what, got.Mode, c.want)
		}
		if said := strings.Contains(e, "held offline"); said != c.said {
			t.Errorf("%s: said it was held offline %v, want %v:\n%s", c.what, said, c.said, e)
		}
	}
}
