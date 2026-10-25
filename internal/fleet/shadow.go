// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"sort"
	"strings"
	"time"
)

// An agent's own program reaching an AI service directly.
//
// An agent's models are meant to be called through the gateway, where what
// is sent is masked, counted against a budget and written down. Its program
// runs in a box whose outbound connections are on the record
// (agent.egress), so one that went to a model provider by itself is in the
// log, and is worth a person's look: not forbidden here, but unseen by the
// gateway, the budget and the log of what the model was told.
//
// What people across the estate reach — proxy and DNS logs, app grants —
// is in those systems' logs, and so is Vaigil's to find.

// The AI services a program reaches directly: model APIs and the
// assistants' own sites. A host is matched exactly or as a subdomain of one
// of these, so lookalikes (openai.com.example.net) are not.
var aiHosts = map[string]string{
	"openai.com": "OpenAI", "chatgpt.com": "OpenAI",
	"anthropic.com": "Anthropic", "claude.ai": "Anthropic",
	"generativelanguage.googleapis.com": "Google Gemini", "gemini.google.com": "Google Gemini",
	"aiplatform.googleapis.com": "Google Vertex AI",
	"openai.azure.com":          "Azure OpenAI", "cognitiveservices.azure.com": "Azure AI",
	"copilot.microsoft.com": "Microsoft Copilot",
	"mistral.ai":            "Mistral",
	"api.cohere.com":        "Cohere", "api.cohere.ai": "Cohere",
	"api.groq.com": "Groq", "api.together.xyz": "Together AI", "api.fireworks.ai": "Fireworks AI",
	"deepseek.com":  "DeepSeek",
	"openrouter.ai": "OpenRouter",
	"perplexity.ai": "Perplexity",
	"x.ai":          "xAI", "grok.com": "xAI",
	"api-inference.huggingface.co": "Hugging Face", "router.huggingface.co": "Hugging Face",
	"integrate.api.nvidia.com": "NVIDIA NIM",
	"api.replicate.com":        "Replicate",
	"poe.com":                  "Poe",
}

// bedrock is AWS's, by region: bedrock-runtime.REGION.amazonaws.com.
const bedrock = "Amazon Bedrock"

// AIService names the AI service a host belongs to.
func AIService(host string) (string, bool) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	if h == "" {
		return "", false
	}
	if strings.HasPrefix(h, "bedrock-runtime.") && strings.HasSuffix(h, ".amazonaws.com") {
		return bedrock, true
	}
	for {
		if s, ok := aiHosts[h]; ok {
			return s, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 || strings.Count(h, ".") < 2 {
			return "", false
		}
		h = h[i+1:]
	}
}

// Reach is one outbound connection an agent's program made, as the log
// recorded it.
type Reach struct {
	At    time.Time
	Agent string
	Host  string
}

// Sighting is an agent's program reaching an AI service directly.
type Sighting struct {
	Service string    `json:"service"`
	Where   string    `json:"where"`
	Who     string    `json:"who"`
	Count   int       `json:"count"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// Sightings finds the reaches that went to an AI service, one per service,
// host and agent, most recent first.
func Sightings(in []Reach) []Sighting {
	type key struct{ where, who string }
	seen := map[key]*Sighting{}
	for _, r := range in {
		service, ok := AIService(r.Host)
		if !ok {
			continue
		}
		k := key{strings.ToLower(r.Host), r.Agent}
		s := seen[k]
		if s == nil {
			s = &Sighting{Service: service, Where: k.where, Who: r.Agent, First: r.At, Last: r.At}
			seen[k] = s
		}
		s.Count++
		if r.At.Before(s.First) {
			s.First = r.At
		}
		if r.At.After(s.Last) {
			s.Last = r.At
		}
	}
	out := make([]Sighting, 0, len(seen))
	for _, s := range seen {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].Where+out[i].Who < out[j].Where+out[j].Who
	})
	return out
}
