// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package aievidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// An AI bill of materials, CycloneDX 1.6: what the organisation's AI is
// made of and depends on. The models behind each route; Quilzo's agents
// and chatbots as applications; the knowledge each chatbot answers from
// and each agent's memory as data; the tool servers and other vendors'
// agents as services, across a trust boundary; and which depends on which,
// from the declarations and from what the model ledger recorded.

// BOM is the document.
type BOM struct {
	Format       string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     BOMMeta      `json:"metadata"`
	Components   []Component  `json:"components"`
	Services     []Service    `json:"services,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// BOMMeta says what it describes and when.
type BOMMeta struct {
	Timestamp string    `json:"timestamp"`
	Component Component `json:"component"`
}

// Component is a model, an application or data.
type Component struct {
	BOMRef      string     `json:"bom-ref"`
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	Version     string     `json:"version,omitempty"`
	Description string     `json:"description,omitempty"`
	Supplier    *Entity    `json:"supplier,omitempty"`
	Data        []Data     `json:"data,omitempty"`
	Properties  []Property `json:"properties,omitempty"`
}

// Data describes a dataset component.
type Data struct {
	Type           string `json:"type"`
	Name           string `json:"name"`
	Classification string `json:"classification,omitempty"`
}

// Service is something reached across a boundary.
type Service struct {
	BOMRef        string     `json:"bom-ref"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	Endpoints     []string   `json:"endpoints,omitempty"`
	Authenticated bool       `json:"authenticated"`
	TrustBoundary bool       `json:"x-trust-boundary"`
	Properties    []Property `json:"properties,omitempty"`
}

// Entity is a supplier.
type Entity struct {
	Name string `json:"name"`
}

// Property is anything CycloneDX has no field for.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency is what one thing uses.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func prop(name, value string) Property { return Property{Name: "quilzo:" + name, Value: value} }

// AIBOM is the AI bill of materials.
func AIBOM(in Inputs) *BOM {
	b := &BOM{Format: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Metadata: BOMMeta{Timestamp: in.Now.UTC().Format("2006-01-02T15:04:05Z"),
			Component: Component{BOMRef: "organisation-ai", Type: "application", Name: nonEmpty(in.Name, "This organisation") + "'s AI",
				Version: in.Version, Description: "The agents, chatbots, models, data and services this Quilzo governs"}}}
	deps := map[string]map[string]bool{}
	dep := func(from, to string) {
		if deps[from] == nil {
			deps[from] = map[string]bool{}
		}
		deps[from][to] = true
	}
	routeRef := map[string]string{}
	for _, r := range in.Routes {
		ref := "model:" + r.Name
		routeRef[r.Name] = ref
		c := Component{BOMRef: ref, Type: "machine-learning-model", Name: nonEmpty(r.Model, r.Name),
			Properties: []Property{prop("route", r.Name), prop("personal-data", strconv.FormatBool(r.Personal)),
				prop("on-own-network", strconv.FormatBool(r.Local))}}
		if r.Host != "" {
			c.Supplier = &Entity{Name: r.Host}
		}
		b.Components = append(b.Components, c)
	}
	if in.Direct != "" {
		routeRef[""] = "model:direct"
		b.Components = append(b.Components, Component{BOMRef: "model:direct", Type: "machine-learning-model",
			Name: "the configured model", Supplier: &Entity{Name: in.Direct}, Properties: []Property{prop("route", "direct")}})
	}
	toolRef := map[string]string{}
	for _, t := range in.Tools {
		ref := "service:" + t.Name
		for _, u := range t.Uses {
			toolRef[u] = ref
		}
		sv := Service{BOMRef: ref, Name: t.Name, Description: t.Purpose, Authenticated: t.Secret != "", TrustBoundary: true,
			Properties: []Property{prop("enabled", strconv.FormatBool(t.Enabled)), prop("writes", strconv.FormatBool(t.Writes)),
				prop("tools", strings.Join(t.Uses, " "))}}
		if t.Endpoint != "" {
			sv.Endpoints = []string{"https://" + t.Endpoint}
		}
		if t.Gateway != nil {
			sv.Properties = append(sv.Properties, prop("offered-through-gateway-to", t.Gateway.Role))
		}
		b.Services = append(b.Services, sv)
	}
	for _, e := range in.External {
		sv := Service{BOMRef: "external:" + e.Name, Name: e.Name, Description: e.Description, Authenticated: true, TrustBoundary: true,
			Properties: []Property{prop("kind", "external agent"), prop("card", e.CardURL), prop("answered-for-by", e.Sponsor)}}
		if e.Endpoint != "" {
			sv.Endpoints = []string{e.Endpoint}
		}
		b.Services = append(b.Services, sv)
	}
	for _, name := range sortedNames(in.Agents) {
		m := in.Agents[name]
		ref := "agent:" + name
		c := Component{BOMRef: ref, Type: "application", Name: name, Description: m.Purpose,
			Properties: []Property{prop("kind", string(m.Kind)), prop("autonomy", string(m.Autonomy)),
				prop("capabilities", strings.Join(m.Capabilities, " ")), prop("answered-for-by", in.Sponsors[name]),
				prop("reads", nonEmpty(m.Retrieval.Ref, "live"))}}
		b.Components = append(b.Components, c)
		dep("organisation-ai", ref)
		for _, t := range m.Tools {
			if r, ok := toolRef[t.Name]; ok {
				dep(ref, r)
			}
		}
		if m.Memory.Episodic || m.Memory.Semantic || m.Memory.Procedural {
			mref := "data:memory:" + name
			b.Components = append(b.Components, Component{BOMRef: mref, Type: "data", Name: name + "'s memory",
				Data:       []Data{{Type: "dataset", Name: name + "'s memory", Classification: "personal"}},
				Properties: []Property{prop("retain", m.Memory.Retain.String())}})
			dep(ref, mref)
		}
		for _, r := range in.Uses["agent:"+name] {
			if mr, ok := routeRef[r]; ok {
				dep(ref, mr)
			}
		}
	}
	for _, bot := range in.Chatbots {
		ref := "chatbot:" + bot.Name
		b.Components = append(b.Components, Component{BOMRef: ref, Type: "application", Name: bot.Name,
			Properties: []Property{prop("kind", "chatbot"), prop("public", strconv.FormatBool(bot.Public)),
				prop("discloses-ai", strconv.FormatBool(bot.Disclosed)), prop("uses-model", strconv.FormatBool(bot.UseModel))}})
		kref := "data:knowledge:" + bot.Name
		b.Components = append(b.Components, Component{BOMRef: kref, Type: "data", Name: bot.Name + "'s knowledge",
			Data:       []Data{{Type: "dataset", Name: "published pages and " + strconv.Itoa(bot.Documents) + " documents", Classification: "public"}},
			Properties: []Property{prop("screened-for-instructions", strconv.FormatBool(!bot.KeepInstructions))}})
		dep("organisation-ai", ref)
		dep(ref, kref)
		for _, r := range in.Uses[ref] {
			if mr, ok := routeRef[r]; ok {
				dep(ref, mr)
			}
		}
	}
	froms := make([]string, 0, len(deps))
	for f := range deps {
		froms = append(froms, f)
	}
	sort.Strings(froms)
	for _, f := range froms {
		var tos []string
		for t := range deps[f] {
			tos = append(tos, t)
		}
		sort.Strings(tos)
		b.Dependencies = append(b.Dependencies, Dependency{Ref: f, DependsOn: tos})
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d|%d", in.Name, b.Metadata.Timestamp, len(b.Components), len(b.Services), len(b.Dependencies))))
	h := hex.EncodeToString(sum[:16])
	b.SerialNumber = "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
	return b
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
