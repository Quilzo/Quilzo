// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/aievidence"
	"github.com/quilzo/quilzo/internal/posture"
)

func TestAIEvidenceIsShownAndTheBillOfMaterialsDownloaded(t *testing.T) {
	srv, token := setup(t)
	asked := 0
	srv.AIEvidence = &AIEvidence{Inputs: func(days int) (aievidence.Inputs, error) {
		asked = days
		return aievidence.Inputs{Name: "Northwind", From: time.Now().Add(-time.Duration(days) * 24 * time.Hour), Now: time.Now(),
			State:    posture.State{},
			Agents:   map[string]agent.Manifest{"tidy": {Name: "tidy", Purpose: "keep pages tidy"}},
			Sponsors: map[string]string{"tidy": "dana"}, Standing: map[string]bool{"tidy": true},
			Routes: []aievidence.Route{{Name: "hosted", Model: "gpt-x", Host: "api.example.com"}}}, nil
	}}
	body := get(t, srv, "/security/ai-evidence?days=30", token).Body.String()
	for _, want := range []string{"EU AI Act: a deployer", "Art. 26(6)", "ISO/IEC 42001: Annex A", "A.6.2.8", "Download the AI bill of materials"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if asked != 30 {
		t.Fatalf("asked for %d days", asked)
	}
	w := get(t, srv, "/security/ai-evidence/aibom.json", token)
	var bom map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &bom); err != nil || bom["bomFormat"] != "CycloneDX" ||
		!strings.Contains(w.Header().Get("Content-Disposition"), "ai-bom.cdx.json") {
		t.Fatalf("%v %s", err, w.Body.String())
	}
	if body := get(t, srv, "/security/frameworks", token).Body.String(); !strings.Contains(body, `href="/security/ai-evidence"`) {
		t.Fatal("Frameworks does not link to the evidence")
	}
}
