// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
)

// Features from a repository: a pull request's CI checks a package and
// shows what it would do, and the CI that runs on merge installs it, with a
// token exchanged for the job (tokenexchange.go) and nothing stored in the
// repository. An install takes the same card, plan and approvals as one
// made on the Make screen: one that needs two people waits for a person in
// Approvals, with the job as the one who asked.

// ErrForbidden marks a refusal of who is asking, as against a package that
// is not usable.
var ErrForbidden = errors.New("not permitted")

// FeatureProgram is what a program's token may do with packages.
type FeatureProgram struct {
	// Check reads a package for a token, changing nothing.
	Check func(body []byte, tok auth.Token) (*feature.Package, feature.Card, feature.Plan, error)
	// Install installs for a token, or leaves it waiting; secrets are new
	// webhooks' signing secrets.
	Install func(body []byte, tok auth.Token) (waiting string, secrets []string, err error)
}

type featureAnswer struct {
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	Card     feature.Card `json:"card"`
	Plan     feature.Plan `json:"plan"`
	Markdown string       `json:"markdown"`
	// Installed and Waiting say what an install did; Secrets are shown once.
	Installed bool     `json:"installed,omitempty"`
	Waiting   string   `json:"waiting,omitempty"`
	Secrets   []string `json:"secrets,omitempty"`
}

func (s *Server) handleFeatureProgram(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int, why string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": why})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed, "a package is sent with POST")
		return
	}
	if s.FeatureProgram == nil {
		fail(http.StatusNotFound, "this build was started without the feature store")
		return
	}
	token, _ := authzToken(r)
	if token == "" {
		tokenChallenge(w, "", nil)
		fail(http.StatusUnauthorized, "a token in the Authorization header")
		return
	}
	c, err := s.interfaceCaller(r, token, "")
	if err != nil {
		tokenChallenge(w, "", err)
		fail(http.StatusUnauthorized, err.Error())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, feature.MaxBytes+1))
	if err != nil || len(body) > feature.MaxBytes {
		fail(http.StatusRequestEntityTooLarge, fmt.Sprintf("a package is at most %d MiB", feature.MaxBytes>>20))
		return
	}
	tok, _ := c.Data.(auth.Token)
	var answer featureAnswer
	// The plan is what the install would change, so it is worked out first.
	p, card, plan, err := s.FeatureProgram.Check(body, tok)
	if p != nil {
		answer.Name, answer.Version, answer.Card, answer.Plan = p.Name, p.Version, card, plan
	}
	if err == nil && strings.HasSuffix(r.URL.Path, "/install") {
		answer.Waiting, answer.Secrets, err = s.FeatureProgram.Install(body, tok)
		answer.Installed = err == nil && answer.Waiting == ""
	}
	if p != nil {
		answer.Markdown = featureMarkdown(card, plan, answer)
	}
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, ErrForbidden) {
			code = http.StatusForbidden
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "markdown": answer.Markdown})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

// featureMarkdown is the card and the plan as a pull request comment.
func featureMarkdown(c feature.Card, p feature.Plan, a featureAnswer) string {
	var b strings.Builder
	approvers := "one administrator approves it"
	if c.Approvers == 2 {
		approvers = "two different people approve it"
	}
	fmt.Fprintf(&b, "### %s %s\n\n%s\n\n**Risk %s**: %s.\n", c.Title, c.Version, c.Purpose, c.Risk, approvers)
	for _, why := range c.Because {
		fmt.Fprintf(&b, "- two people, because %s\n", why)
	}
	section := func(title string, lines []feature.Line) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n**%s**\n\n", title)
		for _, l := range lines {
			flag := ""
			if l.Flag != "" {
				flag = " _(" + l.Flag + ")_"
			}
			fmt.Fprintf(&b, "- %s%s\n", l.Text, flag)
		}
	}
	section("Stores", c.Stores)
	section("Collects", c.Collects)
	section("Shows", c.Shows)
	section("Sends", c.Sends)
	section("Agents", c.Agents)
	section("Chatbots", c.Chatbots)
	section("Roles", c.Roles)
	b.WriteString("\n| Change | Kind | Name |\n|---|---|---|\n")
	for _, st := range p.Steps {
		fmt.Fprintf(&b, "| %s | %s | `%s` |\n", st.Action, st.Ref.Kind, strings.ReplaceAll(st.Ref.Name, "|", `\|`))
	}
	for _, conflict := range p.Conflicts {
		fmt.Fprintf(&b, "\n> Cannot install: %s\n", conflict)
	}
	switch {
	case a.Installed:
		b.WriteString("\nInstalled.\n")
	case a.Waiting != "":
		fmt.Fprintf(&b, "\nWaiting for a second person in Approvals (request %s).\n", a.Waiting)
	}
	return b.String()
}
