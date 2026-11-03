// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Making a picture, a video or a voice, or hearing a recording, asks the
// store's models, as assist, agent draft and evolve run do, and needs the
// same permission: an author denied use-models was refused the writing
// assistant and could still spend the models on media. What comes back is
// stored in the library, which is an author's write, so somebody given the
// models alone is refused that, before any model is asked. Attaching and
// the rest of media stay an author's.
func TestMakingMediaNeedsUseModels(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"erin", "author"}, [2]string{"rhea", "reader"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if err := p.Grant(auth.Binding{Principal: "erin", Permission: auth.ActUseModels, Resource: "/", Deny: true}); err != nil {
			return err
		}
		return p.Grant(auth.Binding{Principal: "rhea", Permission: auth.ActUseModels, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	token := map[string]string{}
	for who, role := range map[string]auth.Role{"dana": auth.RoleAdmin, "erin": auth.RoleAuthor, "rhea": auth.RoleReader} {
		secret, _, err := ts.Issue(who, who, role, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		token[who] = secret
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	old := flagToken
	t.Cleanup(func() { flagToken = old })

	making := map[string][]string{
		"generate":   {"generate", "a brass pen", "--alt", "A brass pen.", "--author", "x"},
		"film":       {"film", "a brass pen turning", "--author", "x"},
		"speak":      {"speak", "Welcome to Marginalia.", "--author", "x"},
		"transcribe": {"transcribe", "abc123", "--lang", "en", "--author", "x"},
	}
	for name, args := range making {
		if n, _ := lookupNeed("media", args); n.action != auth.ActUseModels {
			t.Errorf("media %s needs %s", name, n.action)
		}
		flagToken = token["erin"]
		err := authoriseCommand(root, "media", args)
		if err == nil || !strings.Contains(err.Error(), "use-models") || !strings.Contains(err.Error(), "spends the store's models") {
			t.Errorf("media %s, by an author denied the models: %v", name, err)
		}
		flagToken = token["dana"]
		if err := authoriseCommand(root, "media", args); err != nil {
			t.Errorf("media %s, by an administrator: %v", name, err)
		}
		// The models alone pass the table and are refused the library,
		// before any model is asked: there is no route, and the refusal is
		// the library's, not the missing route's.
		flagToken = token["rhea"]
		if err := authoriseCommand(root, "media", args); err != nil {
			t.Errorf("media %s, by somebody given the models: %v", name, err)
		}
		if err := cmdMedia(root, args); err == nil || !strings.Contains(err.Error(), "edit-draft") {
			t.Errorf("media %s stored for somebody who may not write: %v", name, err)
		}
	}
	// What does not ask a model is an author's as it was.
	flagToken = token["erin"]
	for _, args := range [][]string{{"captions", "v", "t", "--lang", "en"}, {"edit", "abc"}, {"add", "x.png"}} {
		if err := authoriseCommand(root, "media", args); err != nil {
			t.Errorf("media %s, by an author: %v", args[0], err)
		}
	}
}
