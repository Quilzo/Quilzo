// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

// Commands that were part of Quilzo and have left it.
//
// Rooms, calls, the AI note-taker and the frame encryption under calls
// became a product of their own, and their commands went with them. Somebody
// who types one of them, out of habit or from a script written last year,
// is owed the reason rather than "there is no such command" and a guess at
// what they mistyped: they typed it correctly, and it is the program that
// changed. So each of these names is answered by one sentence saying so,
// wherever the name arrives: as the command, after `help`, or at the
// authorisation check that every command passes through.
//
// The answer is a usage error, exit status 2, because nothing failed and
// nothing was refused: the command line asked for something this program
// does not do. What these commands kept in a store is left where it is, and
// the store opens, checks, backs up and restores with it in place.
var movedOut = map[string]bool{
	"room": true, "call": true, "huddle": true,
	"scribe": true, "errand": true, "sframe": true,
}

// errMovedOut is the one sentence a removed command is answered with.
func errMovedOut(cmd string) error {
	return errMisused{fmt.Errorf("`quilzo %s` is no longer part of Quilzo: rooms, calls "+
		"and the AI note-taker have moved out of Quilzo into a separate product", cmd)}
}
