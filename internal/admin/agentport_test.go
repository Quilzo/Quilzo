// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"encoding/json"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

// importStudio is the studio, offering what an imported agent asks for.
func importStudio(t *testing.T) (*Server, string, *studio) {
	t.Helper()
	srv, token := setup(t)
	st := wireStudio(srv)
	known := map[string]bool{}
	for _, c := range []string{"read_page", "list_pages", "search_pages", "similar_pages", "search", "write_page",
		"file_read", "file_list", "file_write"} {
		known[c] = true
	}
	srv.Agents.Known = func() []string {
		var out []string
		for c := range known {
			out = append(out, c)
		}
		return out
	}
	srv.Agents.Save = func(m agent.Manifest, isNew bool, _ Actor) error {
		if err := m.Validate(known); err != nil {
			return err
		}
		for _, d := range m.Delegates {
			if _, ok := st.declared[d]; !ok {
				return &json.UnsupportedValueError{Str: d + " is not declared"}
			}
		}
		st.declared[m.Name] = m
		return nil
	}
	return srv, token, st
}

func uploadAgent(t *testing.T, srv *Server, token, file string, fields map[string]string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "agentport", "testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", file)
	fw.Write(b)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/agents/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("reading %s answered %d: %.300s", file, res.Code, res.Body.String())
	}
	return res.Body.String()
}

// The import is read and shown, with what is the reader's to decide, and
// nothing is declared until they say so; then the agents they chose are
// declared, the one handed work first.
func TestAnAgentFromAnotherPlatformIsReadThenDeclaredOnTheScreen(t *testing.T) {
	srv, token, st := importStudio(t)
	body := get(t, srv, "/agents/import", token).Body.String()
	whole(t, body)
	for _, want := range []string{"Claude Code subagent", "Amazon Bedrock Agents", `enctype="multipart/form-data"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the import page is missing %q", want)
		}
	}

	body = uploadAgent(t, srv, token, "agents.yaml", nil)
	whole(t, body)
	for _, want := range []string{"CrewAI agents", "Yours to decide", "SerperDevTool", `name="pick" value="lead"`,
		`name="pick" value="researcher"`, "Your personal goal is:"} {
		if !strings.Contains(html.UnescapeString(body), want) {
			t.Errorf("the report is missing %q", want)
		}
	}
	if len(st.declared) != 0 {
		t.Fatal("reading the file declared an agent")
	}
	agents := regexp.MustCompile(`name="agents" value="([^"]*)"`).FindStringSubmatch(body)
	if agents == nil {
		t.Fatal("the report carries no agents to declare")
	}
	code, loc := postFormLoc(t, srv, token, "/agents/import", url.Values{"do": {"declare"},
		"agents": {html.UnescapeString(agents[1])}, "pick": {"lead", "researcher"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/agents?") ||
		!strings.Contains(loc, "m=Imported+researcher%2C+lead.") {
		t.Fatalf("declaring answered %d to %s", code, loc)
	}
	if st.declared["lead"].Name == "" || st.declared["researcher"].Name == "" ||
		st.declared["lead"].Instructions == "" {
		t.Fatalf("declared %+v", st.declared)
	}

	// Read again, both are declared already and neither is offered.
	body = uploadAgent(t, srv, token, "agents.yaml", nil)
	if strings.Contains(body, `name="pick"`) || !strings.Contains(body, "is declared already") {
		t.Error("an agent declared already was offered again")
	}
}

// One agent, renamed as it is read, lands on its own page; a file that is
// not an agent says so; and what comes back from the page is checked again.
func TestOneImportedAgentIsNamedAndCheckedAgain(t *testing.T) {
	srv, token, st := importStudio(t)
	body := uploadAgent(t, srv, token, "code-reviewer.md", map[string]string{"name": "Reviewer"})
	agents := regexp.MustCompile(`name="agents" value="([^"]*)"`).FindStringSubmatch(body)
	if agents == nil || !strings.Contains(body, `value="reviewer"`) {
		t.Fatalf("no agent to declare:\n%.2000s", body)
	}
	code, loc := postFormLoc(t, srv, token, "/agents/import", url.Values{"do": {"declare"},
		"agents": {html.UnescapeString(agents[1])}, "pick": {"reviewer"}})
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, "/agents/edit/reviewer?") || !strings.Contains(loc, "m=Imported") {
		t.Fatalf("declaring answered %d to %s", code, loc)
	}
	if m := st.declared["reviewer"]; m.Model != "sonnet" || m.Instructions == "" {
		t.Fatalf("declared %+v", m)
	}
	edit := get(t, srv, "/agents/edit/reviewer", token).Body.String()
	whole(t, edit)
	if !strings.Contains(edit, `name="instructions"`) || !strings.Contains(edit, `value="sonnet"`) ||
		!strings.Contains(edit, "/agents/export/reviewer") {
		t.Error("the editor does not show its instructions, its model or the way out")
	}

	body = uploadAgent(t, srv, token, "../../agent/agent.go", nil)
	if !strings.Contains(body, `role="alert"`) {
		t.Error("a file that is not an agent was not said to be one")
	}

	// Widened on the way back from the page: refused by the same check.
	var ms []agent.Manifest
	json.Unmarshal([]byte(html.UnescapeString(agents[1])), &ms)
	ms[0].Name, ms[0].Capabilities = "wider", append(ms[0].Capabilities, "shell.exec")
	b, _ := json.Marshal(ms)
	_, loc = postFormLoc(t, srv, token, "/agents/import", url.Values{"do": {"declare"},
		"agents": {string(b)}, "pick": {"wider"}})
	if _, ok := st.declared["wider"]; ok || !strings.Contains(loc, "e=") {
		t.Errorf("a widened declaration was declared (%s)", loc)
	}
}

// Exported, the declaration is shown in the chosen format with what it
// leaves, and downloads as a file.
func TestAnAgentIsTakenToAnotherPlatformFromTheScreen(t *testing.T) {
	srv, token, _ := importStudio(t)
	studioAct(t, srv, token, declareForm("answers"))
	body := get(t, srv, "/agents/export/answers?to=m365", token).Body.String()
	whole(t, body)
	for _, want := range []string{"Microsoft 365 Copilot", "answers.declarativeAgent.json", "Not carried",
		"Claude Code subagent"} {
		if !strings.Contains(body, want) {
			t.Errorf("the export page is missing %q", want)
		}
	}
	res := get(t, srv, "/agents/export/answers?to=claude-subagent&file=answers.md", token)
	if res.Code != http.StatusOK || !strings.HasPrefix(res.Body.String(), "---\nname: answers\n") ||
		!strings.Contains(res.Header().Get("Content-Disposition"), `filename="answers.md"`) {
		t.Fatalf("download %d %q:\n%s", res.Code, res.Header().Get("Content-Disposition"), res.Body.String())
	}
	if get(t, srv, "/agents/export/answers?to=bedrock", token).Code != http.StatusBadRequest {
		t.Error("exported to a format only read")
	}
	if get(t, srv, "/agents/export/nobody", token).Code != http.StatusNotFound {
		t.Error("exported an agent nobody declared")
	}
}
