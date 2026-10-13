// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

//go:build !unix

package main

import "errors"

func holdCell(string) (func(), error) {
	return nil, errors.New("desktop cells run only on Linux")
}
