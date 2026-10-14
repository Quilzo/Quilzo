// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"strings"
)

// Permissions for working with agents.
//
// The four rungs decide what somebody may do to content, and they were the
// whole model while Quilzo was a content system. Agents brought decisions
// that are not about content: who may start an agent, who may approve what
// it waits to do, who may change what it is allowed to do, who may spend the
// store's models, who may install a feature. Each was given to the nearest
// rung, so all but two meant "administrator of everything", and letting the
// marketing lead approve the marketing agent meant handing them the keys to
// the whole store.
//
// So each is a permission of its own. By default it still follows the rung
// it always followed, and nothing changes for a store that grants none. It
// can also be granted alone, on part of the store: approve on
// /@agents/newsletter is somebody who decides what the newsletter agent
// waits to do and nothing else. A grant of a permission is a binding like
// any other: it lives in the same policy, is shown by the same explain, ends
// when it expires, and can be denied.
//
// The list is short on purpose. Every permission is a question a person has
// to answer when they grant access, and a list nobody can read in full is a
// list nobody checks; a new decision gets a permission when it cannot be
// expressed as one of these.

const (
	// ActRunAgents starts an agent's run.
	ActRunAgents Action = "run-agents"
	// ActApprove decides what an agent waits for a person to decide.
	ActApprove Action = "approve"
	// ActManageAgents declares, changes and withdraws agents: what they may
	// do, their credentials, their evaluations and the lessons they read.
	ActManageAgents Action = "manage-agents"
	// ActUseModels asks the store's models on one's own behalf: the writing
	// assistant, drafting, and the model gateway at /v1.
	ActUseModels Action = "use-models"
	// ActInstall installs, removes and rolls back features.
	ActInstall Action = "install-features"
)

// Permission is one permission that can be granted on its own.
type Permission struct {
	Action Action
	// Summary says what holding it lets somebody do.
	Summary string
}

// Permissions are the permissions that can be granted on their own, in the
// order people read them.
var Permissions = []Permission{
	{ActRunAgents, "start an agent's run"},
	{ActApprove, "decide what an agent waits for a person to decide"},
	{ActManageAgents, "declare and change agents: what they may do, their credentials, evaluations and lessons"},
	{ActUseModels, "use the store's models: the writing assistant, drafting, and the model gateway"},
	{ActInstall, "install, remove and roll back features"},
}

// IsPermission reports whether an action can be granted on its own.
func IsPermission(a Action) bool {
	for _, p := range Permissions {
		if p.Action == a {
			return true
		}
	}
	return false
}

// PermissionNamed finds a grantable permission by name.
func PermissionNamed(name string) (Permission, bool) {
	for _, p := range Permissions {
		if string(p.Action) == strings.TrimSpace(name) {
			return p, true
		}
	}
	return Permission{}, false
}

// AreaAgents is the agents, and AgentResource one agent, as a grant names
// them: a permission on /@agents covers every agent; on /@agents/NAME, that
// one.
const AreaAgents = "/@agents"

// AgentResource is the resource one agent is checked against.
func AgentResource(name string) string { return AreaAgents + "/" + name }

// What is what a binding grants, in words: a role, or a permission.
func (b Binding) What() string {
	if b.Permission != "" {
		return string(b.Permission)
	}
	return string(b.Role)
}

// grantsPermission reports whether a binding is a live grant of an action's
// permission over a target.
func grantsPermission(b *Binding, action Action, target string, liveAt int64) bool {
	if b.Permission != action || b.Deny || (b.Expires != 0 && liveAt >= b.Expires) {
		return false
	}
	if !covers(b.Resource, target) {
		return false
	}
	// A permission granted over the site reaches a guarded area only as a
	// role would: by being granted on the area itself.
	return IsArea(b.Resource) || !guarded(target)
}

// permissionText is a binding of a permission, for a reason or a trail.
func permissionText(b *Binding) string {
	return fmt.Sprintf("the %s permission on %s", b.Permission, normalise(b.Resource))
}

// AreaData is the records an application holds, and DataResource one
// collection of them: a role on /@data/samples reads, or writes, the
// samples and nothing else. A role on the whole site covers every
// collection, as it always did; a role on a section of pages covers none,
// because a page section and a collection that happen to share a name are
// not the same thing.
const AreaData = "/@data"

// DataResource is the resource one collection is checked against.
func DataResource(collection string) string { return AreaData + "/" + collection }

// AnywhereUnder reports whether a principal may perform an action on an
// area or on anything inside it: whether a screen for the area has
// anything to show them.
func (p *Policy) AnywhereUnder(principal string, action Action, area string) bool {
	if p.Evaluate(principal, action, area).Allowed {
		return true
	}
	p.mu.RLock()
	var inside []string
	for i := range p.Bindings {
		b := &p.Bindings[i]
		if b.Principal == principal && !b.Deny && covers(area, b.Resource) {
			inside = append(inside, b.Resource)
		}
	}
	p.mu.RUnlock()
	for _, r := range inside {
		if p.Evaluate(principal, action, r).Allowed {
			return true
		}
	}
	return false
}
