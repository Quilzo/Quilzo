// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
)

// exportedFiles splits export_site's answer into its files, by the header
// it puts before each one.
func exportedFiles(t *testing.T, answer string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, part := range strings.Split("\n"+answer, "\n===== ")[1:] {
		head, body, ok := strings.Cut(part, " =====\n")
		if !ok {
			t.Fatalf("an export_site file without its header: %.80q", part)
		}
		files[head] = strings.TrimSpace(body)
	}
	return files
}

// exportRecords are the "export" records in the audit log.
func exportRecords(t *testing.T, root string) []audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range evs {
		if e.Action == "export" {
			out = append(out, e)
		}
	}
	return out
}

// exportPaths are the paths of an export's files, in order.
func exportPaths(m map[string]string) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// MCP's export_site built an export of its own: the draft's pages and the
// banner, and nothing else. An agent taking the site out over MCP got no
// products and no stockists, the draft rather than what is published, and
// no record that the site had been taken out at all. `quilzo export` and
// export_site build one export, and come out the same, recorded alike.
func TestTheCLIAndMCPExportTheSameFiles(t *testing.T) {
	root, _ := identityStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	// A draft that is not what is published: the export is of what is.
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["unpublished-draft"] = map[string]any{"title": "Not published yet"}
	if _, err := site.SaveDraft(s, pages, "a draft", "dana"); err != nil {
		t.Fatal(err)
	}

	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	dir := filepath.Join(t.TempDir(), "export")
	if err := cmdExport(root, []string{"json", "--to", dir}); err != nil {
		t.Fatal(err)
	}
	cli := map[string]string{}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		rel, _ := filepath.Rel(dir, path)
		cli[filepath.ToSlash(rel)] = strings.TrimSpace(string(b))
		return err
	}); err != nil {
		t.Fatal(err)
	}

	text, mcpErr := callTool(t, buildMCP(root, s, withRole("dana", auth.RoleAdmin), "templates"),
		"quilzo_read", "export_site", map[string]any{"format": "json"})
	if mcpErr != nil {
		t.Fatal(mcpErr)
	}
	over := exportedFiles(t, text)

	if got, want := strings.Join(exportPaths(over), " "), strings.Join(exportPaths(cli), " "); got != want {
		t.Fatalf("export_site wrote %s; quilzo export wrote %s", got, want)
	}
	if _, ok := cli["content/products.json"]; !ok {
		t.Fatalf("the export holds no products: %v", exportPaths(cli))
	}
	for path, body := range cli {
		if path != "README.md" && over[path] != body {
			t.Errorf("%s differs between quilzo export and export_site", path)
		}
	}
	if strings.Contains(over["content/pages.json"], "unpublished-draft") {
		t.Error("export_site exported the draft rather than what is published")
	}

	recs := exportRecords(t, root)
	if len(recs) != 2 {
		t.Fatalf("%d export records for one export on the command line and one over MCP", len(recs))
	}
	for _, r := range recs[1:] {
		for _, k := range []string{"format", "pages", "records", "files"} {
			if r.Detail[k] != recs[0].Detail[k] {
				t.Errorf("the export over MCP records %s=%q, and the command line's %q", k, r.Detail[k], recs[0].Detail[k])
			}
		}
	}
}

// The Transfer screen built an export of its own too, of the draft's pages
// alone, while its hint said the export "carries when each page last
// actually changed, and the redirects". Its download is the one export, as
// `quilzo export --ref draft` writes it, recorded alike.
func TestTheCLIAndTheAdminExportTheSameFiles(t *testing.T) {
	root, _ := identityStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueSession("passkey:dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	dir := filepath.Join(t.TempDir(), "export")
	if err := cmdExport(root, []string{"json", "--ref", "draft", "--to", dir}); err != nil {
		t.Fatal(err)
	}

	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Audit = func(action, resource string, d map[string]string) { record(root, adminRecord(action, resource, d)) }
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	srv.Transfer = transferHooks(root, s, cfg, sessionCaller)
	req := httptest.NewRequest("POST", "/transfer/export", strings.NewReader("format=json"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("the download: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	download := exportedFiles(t, rec.Body.String())
	written := map[string]string{}
	entries, _ := os.ReadDir(filepath.Join(dir, "content"))
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, "content", e.Name()))
		written["content/"+e.Name()] = strings.TrimSpace(string(b))
	}
	for _, name := range []string{"last-changed.json", "README.md"} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		written[name] = strings.TrimSpace(string(b))
	}
	if got, want := strings.Join(exportPaths(download), " "), strings.Join(exportPaths(written), " "); got != want {
		t.Fatalf("the download holds %s; quilzo export wrote %s", got, want)
	}
	for path, body := range written {
		if path != "README.md" && download[path] != body {
			t.Errorf("%s differs between quilzo export and the download", path)
		}
	}
	recs := exportRecords(t, root)
	if len(recs) != 2 {
		t.Fatalf("%d export records for one export on the command line and one download", len(recs))
	}
	for _, k := range []string{"format", "pages", "records", "files"} {
		if recs[1].Detail[k] != recs[0].Detail[k] {
			t.Errorf("the download records %s=%q, and the command line's %q", k, recs[1].Detail[k], recs[0].Detail[k])
		}
	}
}
