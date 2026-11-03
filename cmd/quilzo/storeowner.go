// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

// startedByStoreOwner reports whether this process runs as the operating
// system account the store belongs to, or as the superuser: who may start
// one of the program's servers without a token (need.server, privilege.go).
//
// A variable so a test can be somebody else; storeOwnedByMe is per system
// (storeowner_unix.go, storeowner_other.go).
var startedByStoreOwner = storeOwnedByMe
