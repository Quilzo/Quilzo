// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/sandbox"
)

// A process that was to be confined and was not refuses to start: the
// check proves the restriction, it does not assume it.
func TestAnUnconfinedSiteDoesNotPassForAConfinedOne(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "policy.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkSiteConfined(root); err == nil || !strings.Contains(err.Error(), "policy.json") {
		t.Fatalf("an unconfined process passed the check: %v", err)
	}
}

// The public site runs confined: it serves pages and takes a form while
// the store's policy, tokens and configuration, and its root, are out of
// its reach.
func TestThePublicSiteRunsConfined(t *testing.T) {
	if sandbox.ABI() == 0 {
		t.Skip("this kernel has no Landlock")
	}
	if w == nil {
		w = out.New(false)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("QUILZO_TOKEN", "")
	root, tpl := t.TempDir()+"/st", t.TempDir()+"/tpl"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-templates", tpl, "-examples", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	token, _, err := ts.Issue("site", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	policyBefore, _ := os.ReadFile(filepath.Join(root, "policy.json"))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	cmd := exec.Command(os.Args[0], "quilzo-main", "--root", root, "site", "--addr", addr, "--templates", tpl)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN="+token)
	stdout, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	lines := bufio.NewScanner(stdout)
	confined, up := false, false
	deadline := time.Now().Add(30 * time.Second)
	for !up && time.Now().Before(deadline) && lines.Scan() {
		confined = confined || strings.Contains(lines.Text(), "confined: writes only the site's own state")
		up = strings.HasPrefix(lines.Text(), "site on http://")
	}
	if !up || !confined {
		t.Fatalf("the site did not start confined (up %v, confined %v)\n%s", up, confined, stderr.String())
	}
	go func() {
		for lines.Scan() {
		}
	}()

	// Announced as it starts to listen, so asked again until it answers.
	base := "http://" + addr
	var res *http.Response
	for try := 0; try < 50; try++ {
		if res, err = http.Get(base + "/"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("the home page: %v %v", res, err)
	}
	form := url.Values{"shop": {"Paper Co"}, "contact": {"Ola"}, "email": {"ola@example.com"},
		"city": {"Leeds"}, "detail": {"hello"}, "form_started": {strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)}}
	req, _ := http.NewRequest(http.MethodPost, base+"/form/wholesale", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err = http.DefaultClient.Do(req)
	if err != nil || res.StatusCode >= 400 {
		t.Fatalf("the form, confined: %v %v\n%s", res, err, stderr.String())
	}
	got, _ := os.ReadDir(filepath.Join(submissionDir(root), "wholesale"))
	if len(got) != 1 {
		t.Fatalf("the confined site did not keep the submission: %v", got)
	}
	if after, _ := os.ReadFile(filepath.Join(root, "policy.json")); !bytes.Equal(after, policyBefore) {
		t.Error("the policy changed under the site")
	}
}

// The systemd unit in deploy/ lets the site write exactly what it writes:
// a path missing there is a feature that fails under the unit, and one too
// many is more of the store than the site needs.
func TestTheUnitLetsTheSiteWriteWhatItWrites(t *testing.T) {
	b, err := os.ReadFile("../../deploy/quilzo-site.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "ReadWritePaths="); ok {
			for _, p := range strings.Fields(v) {
				unit[p] = true
			}
		}
	}
	dirs, files := siteWritable("/srv/quilzo/.quilzo")
	want := map[string]bool{}
	for _, p := range append(dirs, files...) {
		want[p] = true
		if !unit[p] {
			t.Errorf("the unit does not let the site write %s", p)
		}
	}
	for p := range unit {
		if !want[p] {
			t.Errorf("the unit lets the site write %s, which it does not", p)
		}
	}
}
