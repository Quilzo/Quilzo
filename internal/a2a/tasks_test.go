// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package a2a

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func taskHost(agents ...string) (Host, *[]string) {
	var sent []string
	return Host{
		Agents: func() []string { return agents },
		Send: func(r *http.Request, agent, text string) (Task, error) {
			sent = append(sent, agent+": "+text)
			return Task{ID: "t1", ContextID: "c1", Status: TaskStatus{State: StateCompleted},
				Artifacts: []Artifact{{ArtifactID: "answer", Parts: []Part{{Text: "done"}}}}}, nil
		},
		Get: func(r *http.Request, id string) (Task, error) {
			if id != "t1" {
				return Task{}, Errorf(CodeTaskNotFound, "no task "+id)
			}
			return Task{ID: "t1", Status: TaskStatus{State: StateWorking}}, nil
		},
		List: func(r *http.Request, limit int) ([]Task, error) { return []Task{{ID: "t1"}}, nil },
		Cancel: func(r *http.Request, id string) (Task, error) {
			return Task{}, Errorf(CodeTaskNotCancelable, "it finished")
		},
	}, &sent
}

func rpc(t *testing.T, h Host, version, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest("POST", "/a2a", strings.NewReader(body))
	if version != "" {
		req.Header.Set("A2A-Version", version)
	}
	w := httptest.NewRecorder()
	h.Serve(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	return out
}

func code(m map[string]any) int {
	e, _ := m["error"].(map[string]any)
	if e == nil {
		return 0
	}
	return int(e["code"].(float64))
}

const send = `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m1","role":"ROLE_USER",` +
	`"parts":[{"text":"Summarise the pricing page"}],"metadata":{"agent":"tidy"}}}}`

func TestAMessageBecomesATaskForTheAgentItNames(t *testing.T) {
	h, sent := taskHost("tidy", "support")
	out := rpc(t, h, "1.0", send)
	task, _ := out["result"].(map[string]any)["task"].(map[string]any)
	if task == nil || task["id"] != "t1" || len(*sent) != 1 || (*sent)[0] != "tidy: Summarise the pricing page" {
		t.Fatalf("%v %v", out, *sent)
	}
	if got := rpc(t, h, "1.0", `{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":"t1"}}`); got["result"].(map[string]any)["status"].(map[string]any)["state"] != StateWorking {
		t.Fatalf("%v", got)
	}
	if got := rpc(t, h, "1.0", `{"jsonrpc":"2.0","id":3,"method":"GetTask","params":{"id":"nope"}}`); code(got) != CodeTaskNotFound {
		t.Fatalf("%v", got)
	}
	if got := rpc(t, h, "1.0", `{"jsonrpc":"2.0","id":4,"method":"ListTasks","params":{}}`); len(got["result"].(map[string]any)["tasks"].([]any)) != 1 {
		t.Fatalf("%v", got)
	}
	if got := rpc(t, h, "1.0", `{"jsonrpc":"2.0","id":5,"method":"CancelTask","params":{"id":"t1"}}`); code(got) != CodeTaskNotCancelable {
		t.Fatalf("%v", got)
	}
}

func TestWhatIsNotATaskHereIsSaidPrecisely(t *testing.T) {
	h, sent := taskHost("tidy", "support")
	for name, c := range map[string]struct {
		version, body string
		code          int
	}{
		"0.3, or no header":   {"", send, CodeVersionNotSupported},
		"another version":     {"2.0", send, CodeVersionNotSupported},
		"not JSON":            {"1.0", "{", codeParse},
		"no id":               {"1.0", `{"jsonrpc":"2.0","method":"GetTask","params":{"id":"t1"}}`, codeInvalidRequest},
		"no such method":      {"1.0", `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}`, codeMethodNotFound},
		"streaming":           {"1.0", `{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{}}`, CodeUnsupportedOperation},
		"push":                {"1.0", `{"jsonrpc":"2.0","id":1,"method":"CreateTaskPushNotificationConfig","params":{}}`, CodePushNotSupported},
		"extended card":       {"1.0", `{"jsonrpc":"2.0","id":1,"method":"GetExtendedAgentCard","params":{}}`, CodeExtendedCardNone},
		"a file":              {"1.0", strings.Replace(send, `{"text":"Summarise the pricing page"}`, `{"url":"https://x.example/f.pdf"}`, 1), CodeContentTypeNotAllowed},
		"nothing said":        {"1.0", strings.Replace(send, "Summarise the pricing page", "  ", 1), codeInvalidParams},
		"too long":            {"1.0", strings.Replace(send, "Summarise the pricing page", strings.Repeat("a", MaxText+1), 1), codeInvalidParams},
		"no agent named":      {"1.0", strings.Replace(send, `,"metadata":{"agent":"tidy"}`, "", 1), codeInvalidParams},
		"an agent not here":   {"1.0", strings.Replace(send, `"agent":"tidy"`, `"agent":"admin"`, 1), codeInvalidParams},
		"the agent's message": {"1.0", strings.Replace(send, "ROLE_USER", "ROLE_AGENT", 1), codeInvalidParams},
		"continuing a task":   {"1.0", strings.Replace(send, `"messageId":"m1"`, `"messageId":"m1","taskId":"t1"`, 1), CodeUnsupportedOperation},
		"images only":         {"1.0", strings.Replace(send, `"message":{`, `"configuration":{"acceptedOutputModes":["image/png"]},"message":{`, 1), CodeContentTypeNotAllowed},
	} {
		if got := rpc(t, h, c.version, c.body); code(got) != c.code {
			t.Errorf("%s: %v", name, got)
		}
	}
	if len(*sent) != 0 {
		t.Fatalf("something ran: %v", *sent)
	}
	// One agent needs no naming.
	one, sent := taskHost("tidy")
	if got := rpc(t, one, "1.0", strings.Replace(send, `,"metadata":{"agent":"tidy"}`, "", 1)); code(got) != 0 || len(*sent) != 1 {
		t.Fatalf("%v", got)
	}
	// A host's own refusal reaches the sender as it was given.
	one.Send = func(*http.Request, string, string) (Task, error) { return Task{}, Errorf(-32050, "may not run agents") }
	if got := rpc(t, one, "1.0", send); code(got) != -32050 {
		t.Fatalf("%v", got)
	}
	one.Send = func(*http.Request, string, string) (Task, error) { return Task{}, errors.New("disk full") }
	if got := rpc(t, one, "1.0", send); code(got) != codeInternal {
		t.Fatalf("%v", got)
	}
	// Only POST.
	w := httptest.NewRecorder()
	h.Serve(w, httptest.NewRequest("GET", "/a2a", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal(w.Code)
	}
}

func TestTheCardSaysWhereTasksAreTaken(t *testing.T) {
	c := From(nil, nil, Options{BaseURL: "https://shop.example", TaskURL: "https://admin.shop.example/a2a"})
	if len(c.SupportedInterfaces) != 1 || c.SupportedInterfaces[0].ProtocolVersion != "1.0" ||
		c.SupportedInterfaces[0].ProtocolBinding != "JSONRPC" || c.Validate() != nil {
		t.Fatalf("%+v %v", c.SupportedInterfaces, c.Validate())
	}
	if c := From(nil, nil, Options{BaseURL: "https://shop.example"}); len(c.SupportedInterfaces) != 0 {
		t.Fatal("an interface with no task address")
	}
	c = From(nil, nil, Options{BaseURL: "https://shop.example", TaskURL: "http://admin.shop.example/a2a"})
	if c.Validate() == nil {
		t.Fatal("a plain http task address validated")
	}
}
