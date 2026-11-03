// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/auth"
)

// What making media takes: the store's models, and the library.
//
// media generate, film, speak and transcribe each ask a model, which is
// spent and recorded under the person, so the table in front of them asks
// for use-models (privilege.go), as it does for assist, agent draft and
// evolve run. They needed only edit-draft, so an author denied the models
// was refused the writing assistant and could still spend them on a
// picture, a video or a voice.
//
// What comes back is stored in the library, and that is an author's write.
// The table asks one thing of a command, so each of these asks for the
// other itself, before any model is asked: a refusal there costs nothing.

// mediaModelsHint is what a refusal at the table says beside the policy's
// own reason, so the person refused knows why making media is not theirs
// when adding a file is.
const mediaModelsHint = "making a picture, a video or a voice, or hearing a recording, spends the store's " +
	"models: that is the use-models permission, as for the writing assistant, and storing what comes " +
	"back is edit-draft"

// mayStoreMade refuses somebody who may ask the models and may not write
// what they make into the library. what is what would have been made.
func mayStoreMade(root string, caller *Caller, what string) error {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return fmt.Errorf("%s is stored in the library, which is an author's write: %w", what, err)
	}
	return nil
}
