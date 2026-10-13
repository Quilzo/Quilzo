// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import "errors"

func holdCell(string) (func(), error) {
	return nil, errors.New("desktop cells run only on Linux")
}
