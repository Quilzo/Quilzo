// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"strings"
	"testing"
	"time"
)

func TestACardOfEitherRevisionIsRead(t *testing.T) {
	v1 := `{"name":"Help Desk Agent","description":"Answers tickets","version":"2.1",
		"provider":{"organization":"Zendesk"},
		"supportedInterfaces":[{"url":"https://agents.example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],
		"skills":[{"id":"triage","name":"Triage a ticket"}],"capabilities":{},"defaultInputModes":[],"defaultOutputModes":[]}`
	e, err := ReadCard([]byte(v1), "https://agents.example.com/.well-known/agent-card.json")
	if err != nil || e.Name != "help-desk-agent" || e.Provider != "Zendesk" || e.Endpoint != "https://agents.example.com/a2a" ||
		e.Protocol != "A2A 1.0 JSONRPC" || len(e.Skills) != 1 || e.Skills[0] != "Triage a ticket" || len(e.Digest) != 64 {
		t.Fatalf("%+v %v", e, err)
	}
	v03 := `{"protocolVersion":"0.3.0","name":"Sales​ Bot","url":"https://crm.example.com/a2a","skills":[]}`
	e, err = ReadCard([]byte(v03), "https://crm.example.com/card")
	if err != nil || e.Name != "sales-bot" || e.Protocol != "A2A 0.3.0" || e.Endpoint != "https://crm.example.com/a2a" {
		t.Fatalf("%+v %v", e, err)
	}
	for name, body := range map[string]string{
		"not json": "<html>", "no name": `{"description":"x"}`, "too big": `{"name":"` + strings.Repeat("a", MaxCard) + `"}`,
	} {
		if _, err := ReadCard([]byte(body), "u"); err == nil {
			t.Errorf("%s was read as a card", name)
		}
	}
	for _, bad := range []string{"javascript:alert(1)", "ftp://agents.example.com/a2a", "//agents.example.com/a2a"} {
		if e, _ := ReadCard([]byte(`{"name":"x","url":"`+bad+`"}`), "u"); e.Endpoint != "" {
			t.Fatalf("%s was kept as an endpoint", bad)
		}
	}
	var r Registry
	if err := r.Add(External{Name: "help", CardURL: "a"}); err != nil {
		t.Fatal(err)
	}
	if r.Add(External{Name: "help", CardURL: "b"}) == nil || r.Add(External{Name: "other", CardURL: "a"}) == nil ||
		r.Add(External{Name: "Bad Name", CardURL: "c"}) == nil {
		t.Fatal("a duplicate or a bad name was registered")
	}
	if !r.Remove("help") || r.Remove("help") {
		t.Fatal("remove")
	}
}

func TestAnAIServiceIsKnownByItsHostAndNotByALookalike(t *testing.T) {
	for host, want := range map[string]string{
		"api.openai.com": "OpenAI", "platform.openai.com": "OpenAI", "chatgpt.com": "OpenAI",
		"API.Anthropic.com.": "Anthropic", "claude.ai:443": "Anthropic",
		"myco.openai.azure.com": "Azure OpenAI", "bedrock-runtime.eu-west-1.amazonaws.com": "Amazon Bedrock",
		"generativelanguage.googleapis.com": "Google Gemini",
	} {
		if got, ok := AIService(host); !ok || got != want {
			t.Errorf("%s: %q %v", host, got, ok)
		}
	}
	for _, host := range []string{"openai.com.evil.example", "notopenai.com", "example.com", "", "azure.com", "amazonaws.com", "s3.amazonaws.com"} {
		if s, ok := AIService(host); ok {
			t.Errorf("%s was taken for %s", host, s)
		}
	}
}

// An agent's program reaching a model provider is one sighting per agent
// and host, however often; anything else it reached is not one.
func TestAnAgentReachingAModelDirectlyIsSeen(t *testing.T) {
	now := time.Now()
	got := Sightings([]Reach{
		{At: now.Add(-2 * time.Hour), Agent: "tidy", Host: "api.openai.com"},
		{At: now.Add(-time.Hour), Agent: "tidy", Host: "API.OpenAI.com"},
		{At: now, Agent: "helper", Host: "api.anthropic.com"},
		{At: now, Agent: "tidy", Host: "pypi.org"},
	})
	if len(got) != 2 || got[0].Who != "helper" || got[1].Who != "tidy" || got[1].Count != 2 ||
		got[1].Service != "OpenAI" || !got[1].First.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("%+v", got)
	}
}
