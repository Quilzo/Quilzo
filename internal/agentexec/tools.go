// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
)

// The one thing an agent could be authorised to do and could not do.
//
// # What was already here
//
// All of it except the call. Manifest.Tools declares a host allow-list with no
// wildcards and a vault-named credential; Session.MayCallTool resolves the
// host from the declaration rather than from anything a model said, refuses a
// request that names a different one, spends the tool budget and taints the
// run; agent.Integrations.Resolve answers "something asked to call create_issue
// — may it, and through what"; and internal/mcpclient refuses any tool the
// integration did not declare, including one the server has newly advertised.
//
// Dispatch had no branch for it. An authorised tool action fell through to the
// reader's default and came back "is permitted for this agent and not
// implemented here", so the whole apparatus guarded an action nothing
// performed.
//
// # The model names a tool and nothing else
//
// Not a host, not an endpoint, not an integration. The tool name is looked up
// in the manifest — which needed `grant` to write — and again in the install's
// integrations, and the two have to agree. That is the Action-Selector
// pattern: the model chooses which declared thing to do, and every parameter
// of how it is done was decided by a person in advance.
//
// Arguments are the exception, and they have to be: a tool call without
// arguments is a tool call that cannot say anything. They are passed through
// to the far side, which is the far side's problem to validate — and they are
// bounded here so a model cannot spend this program's memory composing one.
//
// # Why the result is not trusted
//
// It is whatever a third-party host returned on this request. internal/agent's
// run loop already records every observation as untrusted, and MayCallTool
// taints the session, so an agent that has called out cannot publish without a
// person. Nothing here re-decides that.

// MaxToolArgs bounds how many arguments one call may carry.
//
// A closed number rather than a size, because the failure being prevented is a
// model composing a large structure rather than a large string: the far side
// bounds what it accepts, and this bounds what this process assembles first.
const MaxToolArgs = 32

// MaxToolValue bounds one argument's length.
const MaxToolValue = 4 << 10

// Caller performs one tool call on one integration.
//
// An interface rather than *mcpclient.Client, because this package must not
// import one: internal/agentexec reaches the store and internal/mcpclient
// reaches the network, and a package that does both is one where a mistake in
// either half becomes a mistake in the other.
type Caller interface {
	Call(ctx context.Context, in agent.Integration, tool string,
		args map[string]any) (string, error)
}

// Tools performs the tool calls an agent holds.
type Tools struct {
	// Installed is what this deployment has declared and enabled. Nil means
	// none, which is the honest answer for an install with no integrations
	// and is treated as a refusal rather than as permission.
	Installed func() (agent.Integrations, error)
	// Call reaches the far side. Nil means nothing does, which is the state
	// this package was in.
	Call Caller
}

// Perform is the agent.Perform for tool actions on a session.
func (t Tools) Perform(s *agent.Session) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		name := strings.TrimSpace(a.Tool)
		if name == "" {
			return "", fmt.Errorf("no tool was named")
		}

		// The declaration, re-asked. Session.MayCallTool has already
		// authorised this in the run loop; asking again here is what removes
		// the precondition that the loop remembered to — the same reason
		// every read in this package re-asks Session.Check.
		declared, ok := s.ToolFor(name)
		if !ok {
			return "", fmt.Errorf(
				"%q is not one of this agent's declared tools", name)
		}

		if t.Installed == nil || t.Call == nil {
			return "", fmt.Errorf(
				"%q is declared and this build has no way to call it", name)
		}
		set, err := t.Installed()
		if err != nil {
			return "", err
		}
		in, err := set.Resolve(name)
		if err != nil {
			// Resolve's own message says whether nothing offers it, it is
			// disabled, or two integrations offer it and the choice is not
			// one anybody reviewed.
			return "", err
		}

		// The manifest and the install have to agree about where this goes.
		//
		// Both were written by somebody with `grant`, and they are separate
		// files: a manifest naming a host and an integration pointing
		// somewhere else is a disagreement between two deliberate statements,
		// and resolving it silently would mean picking one of them without
		// saying which.
		if !sameHost(declared.Host, in.Endpoint) {
			return "", fmt.Errorf(
				"%s declares the tool %q reaches %s and the %s integration "+
					"points at %s; nothing is called until they agree",
				s.Manifest().Name, name, declared.Host, in.Name, in.Endpoint)
		}

		args, err := boundArgs(a.Input)
		if err != nil {
			return "", err
		}
		return t.Call.Call(ctx, in, name, args)
	}
}

// sameHost reports whether a tool's declared host is the integration's.
//
// An exact comparison, ignoring case, because both sides are bare hostnames:
// agent.checkHost refuses a ":" or a "/" in an endpoint, so it can carry no
// scheme, no port and no path, and internal/mcpclient builds the URL by
// prefixing "https://".
//
// Deliberately not normalising a URL out of either side. Stripping a scheme
// and a port here would be dead code for input the validator already refuses —
// and worse than dead: if an endpoint ever did gain a port, this would compare
// the hosts, ignore the port difference, and call a different service than the
// manifest named. TestAnEndpointIsStillABareHost fails if that assumption
// stops holding, which is the moment to revisit this.
func sameHost(declared, endpoint string) bool {
	h := strings.ToLower(strings.TrimSpace(declared))
	return h != "" && h == strings.ToLower(strings.TrimSpace(endpoint))
}

// boundArgs copies what a model asked to send, within limits.
//
// Scalars only. A nested structure is where a model spends this process's
// memory and where a far side's parser is most likely to disagree with this
// one about what it received — and no tool this program ships needs one.
func boundArgs(in map[string]any) (map[string]any, error) {
	if len(in) > MaxToolArgs {
		return nil, fmt.Errorf(
			"a tool call may carry %d arguments and this one has %d",
			MaxToolArgs, len(in))
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		// The host, when a model sent one, is not an argument. It was the
		// thing Session.MayCallTool refused to take instruction from, and
		// passing it on to the far side would be sending it anyway.
		if strings.EqualFold(k, "host") {
			continue
		}
		switch val := v.(type) {
		case string:
			if len(val) > MaxToolValue {
				return nil, fmt.Errorf(
					"the argument %q is %d bytes and the limit is %d",
					k, len(val), MaxToolValue)
			}
			out[k] = val
		case bool, float64, int:
			out[k] = val
		default:
			return nil, fmt.Errorf(
				"the argument %q is a %T; a tool call carries text, numbers "+
					"and true or false", k, v)
		}
	}
	return out, nil
}
