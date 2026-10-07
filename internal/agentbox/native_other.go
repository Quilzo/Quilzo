// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build !linux

package agentbox

import (
	"context"
	"fmt"
	"os"
)

// Native needs Linux's namespaces, Landlock and seccomp. Elsewhere it says
// so, and a program runs only on another backend.
type Native struct {
	Exe        string
	Init, Shim []string
}

func (n Native) Name() string { return "native" }

func (n Native) Check() Availability {
	return Availability{Why: "the native box is built from Linux's own parts; use another backend here"}
}

func (n Native) Run(context.Context, Spec) (Result, error) {
	return Result{}, fmt.Errorf("%w: %s", ErrUnavailable, n.Check().Why)
}

// InitMain and ShimMain exist only to be dispatched to; here they refuse.
func InitMain() {
	fmt.Fprintln(os.Stderr, "quilzo box: needs Linux")
	os.Exit(125)
}

func ShimMain(string) {
	fmt.Fprintln(os.Stderr, "quilzo box: needs Linux")
	os.Exit(125)
}
