// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package fleet

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// The AI services people and programs reach directly: model APIs and the
// assistants' own apps. A host is matched exactly or as a subdomain of one
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

// aiApps are the assistants' names as an identity provider's app grants
// and a browser's extension list give them.
var aiApps = map[string]string{
	"chatgpt": "OpenAI", "openai": "OpenAI", "claude": "Anthropic", "anthropic": "Anthropic",
	"gemini": "Google Gemini", "perplexity": "Perplexity", "copilot": "Microsoft Copilot",
	"otter.ai": "Otter.ai", "fireflies.ai": "Fireflies.ai", "deepseek": "DeepSeek", "grok": "xAI",
	"mistral": "Mistral", "poe": "Poe",
}

// AIApp names the AI service an app's name is, when it is one.
func AIApp(name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if s, ok := aiApps[n]; ok {
		return s, true
	}
	for word := range strings.FieldsSeq(strings.NewReplacer("-", " ", "_", " ", "(", " ", ")", " ").Replace(n)) {
		if s, ok := aiApps[word]; ok {
			return s, true
		}
	}
	return "", false
}

// Sighting is somebody reaching an AI service directly, as one source saw it.
type Sighting struct {
	Service string    `json:"service"`
	Where   string    `json:"where"`
	Who     string    `json:"who"`
	Source  string    `json:"source"`
	Count   int       `json:"count"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// rawHostish and rawAppish are the keys a source puts a destination or an
// app's name under.
var (
	rawHostish = []string{"host", "domain", "url", "uri", "dest", "destination", "server", "sni", "fqdn", "query"}
	rawAppish  = []string{"app", "application", "client_name", "oauth", "extension", "service"}
)

// Sightings finds direct use of AI services in security events, one per
// service, place, person and source, most recent first. own are sources to
// leave out, such as Quilzo's own model gateway.
func Sightings(events []telemetry.Event, own func(telemetry.Event) bool) []Sighting {
	type key struct{ service, where, who, source string }
	seen := map[key]*Sighting{}
	note := func(ev telemetry.Event, service, where string) {
		who := ev.Actor.String()
		if who == "" {
			who = ev.Device.String()
		}
		k := key{service, where, who, ev.Source}
		s := seen[k]
		if s == nil {
			s = &Sighting{Service: service, Where: where, Who: who, Source: ev.Source, First: ev.Time, Last: ev.Time}
			seen[k] = s
		}
		s.Count++
		if ev.Time.Before(s.First) {
			s.First = ev.Time
		}
		if ev.Time.After(s.Last) {
			s.Last = ev.Time
		}
	}
	for _, ev := range events {
		if own != nil && own(ev) {
			continue
		}
		found := map[string]string{}
		for _, o := range ev.Observables {
			switch o.Kind {
			case telemetry.ObservableHostname, telemetry.ObservableDomain, telemetry.ObservableURL:
				if h := hostOf(o.Value); h != "" {
					if s, ok := AIService(h); ok {
						found[h] = s
					}
				}
			}
		}
		for k, v := range ev.Raw {
			lk := strings.ToLower(k)
			if containsAny(lk, rawHostish) {
				if h := hostOf(v); h != "" {
					if s, ok := AIService(h); ok {
						found[h] = s
					}
				}
			}
			if containsAny(lk, rawAppish) {
				if s, ok := AIApp(v); ok {
					found["app: "+short(v, 60)] = s
				}
			}
		}
		for where, service := range found {
			note(ev, service, where)
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

// hostOf is the host in a hostname, a domain or an address.
func hostOf(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 2048 {
		return ""
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if strings.ContainsAny(v, " \t@") {
		return ""
	}
	return v
}

func containsAny(s string, parts []string) bool {
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
