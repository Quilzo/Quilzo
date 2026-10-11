// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build !unix

package shell

import (
	"errors"
	"os"
)

func tryLock(*os.File) error {
	return errors.New("a workspace is claimed only on Linux and other Unix systems")
}

func unlock(*os.File) {}
