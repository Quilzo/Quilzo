// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/federate"
)

// A pipeline's job, as its platform's signed token names it.
//
// GitHub Actions and GitLab CI each sign a token for every job naming the
// repository it ran in and the workflow that ran it. The token is checked
// where it is exchanged (internal/federate, at /token/exchange), and what
// it names is carried on the short token it is exchanged for, so the push
// is held to the job and not to anything the job says about itself.

var (
	// reRepository is a repository as GitHub names it, owner/name, or a
	// project as GitLab does, with its groups.
	reRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){1,8}$`)
	// reWorkflow is the path of a workflow's file in its repository.
	reWorkflow = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){0,8}\.ya?ml$`)
)

// Workload is the job a token's claims name: for GitHub, the repository
// claim and the workflow file from workflow_ref; for GitLab, project_path
// and the file from ci_config_ref_uri. Claims that name neither give none,
// and a push from a job with none is refused.
func Workload(issuer string, claims map[string]any) evidence.Workload {
	str := func(k string) string { v, _ := claims[k].(string); return strings.TrimSpace(v) }
	w := evidence.Workload{Platform: issuer, Ref: str("ref"), Run: str("run_id")}
	switch {
	case str("repository") != "":
		// octo/docs/.github/workflows/evidence.yml@refs/heads/main
		w.Repository = str("repository")
		ref, _, _ := strings.Cut(str("workflow_ref"), "@")
		w.Workflow = strings.TrimPrefix(ref, w.Repository+"/")
		if w.Workflow == ref {
			w.Workflow = ""
		}
	case str("project_path") != "":
		// gitlab.com/group/project//.gitlab-ci.yml@refs/heads/main
		w.Repository = str("project_path")
		ref, _, _ := strings.Cut(str("ci_config_ref_uri"), "@")
		if _, file, ok := strings.Cut(ref, "//"); ok {
			w.Workflow = file
		}
		if w.Run == "" {
			w.Run = str("pipeline_id")
		}
	}
	if !reRepository.MatchString(w.Repository) {
		w.Repository = ""
	}
	if !reWorkflow.MatchString(w.Workflow) {
		w.Workflow = ""
	}
	return w
}

// WorkloadClaims are the claims a short token keeps of the job it was
// exchanged for, in the form Workload reads them back.
func WorkloadClaims(w evidence.Workload) map[string]string {
	if w.Repository == "" {
		return nil
	}
	return map[string]string{"platform": w.Platform, "repository": w.Repository, "workflow": w.Workflow,
		"ref": w.Ref, "run": w.Run}
}

// WorkloadOf reads back what WorkloadClaims kept.
func WorkloadOf(kept map[string]string) evidence.Workload {
	return evidence.Workload{Platform: kept["platform"], Repository: kept["repository"], Workflow: kept["workflow"],
		Ref: kept["ref"], Run: kept["run"]}
}

// Issuers are the platforms whose jobs push, as a trust names them.
func Issuers() []string { return []string{federate.GitHub, federate.GitLab} }

// CheckPush says whether a job may push to a source, in the words the
// refusal is given in.
func CheckPush(s *Sources, source string, job evidence.Workload) error {
	src, _, err := s.Source(source)
	if err != nil {
		return err
	}
	if err := evidence.PushAllowed(src, job); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}
