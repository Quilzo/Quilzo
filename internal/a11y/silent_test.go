// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package a11y

import "testing"

// soundOf answers as the media library would: one recording it knows is
// silent, one it knows has sound, and everything else unknown.
func soundOf(src string) (bool, bool) {
	switch src {
	case "/media/quiet":
		return false, true
	case "/media/loud":
		return true, true
	}
	return false, false
}

var withLibrary = Options{Sound: soundOf}

// A recording the library knows has no sound needs a description, not a
// captions track — and is refused without one, under the criterion it is
// owed.
func TestASilentVideoNeedsADescriptionNotCaptions(t *testing.T) {
	labelled := page(`<figure><video controls src="/media/quiet" aria-label="Violet light drifting over a grid"></video></figure>`)
	if r := CheckWith("loop", labelled, withLibrary); r.Blocks() {
		t.Errorf("a described silent video was refused: %v", r.Findings)
	}
	captioned := page(`<figure><video controls><source src="/media/quiet"></video>` +
		`<figcaption>The title loop: violet light over a neon grid.</figcaption></figure>`)
	if r := CheckWith("loop", captioned, withLibrary); r.Blocks() {
		t.Errorf("a silent video with a caption beside it was refused: %v", r.Findings)
	}
	bare := page(`<figure><video controls src="/media/quiet"></video><figcaption> </figcaption></figure>`)
	r := CheckWith("loop", bare, withLibrary)
	if !hasRule(r, "silent-video-has-no-alternative") || hasRule(r, "video-has-no-captions") {
		t.Errorf("an undescribed silent video: %v", r.Findings)
	}
}

// Sound, or nobody knowing, keeps the captions rule exactly as it was.
func TestAVideoWithSoundOrUnknownStillNeedsCaptions(t *testing.T) {
	for _, src := range []string{"/media/loud", "/media/never-probed"} {
		r := CheckWith("talk", page(`<video controls src="`+src+`" aria-label="A talk"></video>`), withLibrary)
		if !hasRule(r, "video-has-no-captions") {
			t.Errorf("%s published without captions: %v", src, r.Findings)
		}
	}
	// And a check given no library at all is as strict as it always was.
	if r := Check("loop", page(`<video controls src="/media/quiet" aria-label="x"></video>`)); !hasRule(r, "video-has-no-captions") {
		t.Errorf("without the library, a silent video was taken on trust: %v", r.Findings)
	}
}

const stopControl = `<input class="backdrop-stop" type="checkbox" id="stop-hero" data-stop-motion>` +
	`<label for="stop-hero">Stop the moving background</label>`

func backdrop(src string) string {
	return `<div class="backdrop" aria-hidden="true"><video muted loop playsinline autoplay aria-hidden="true">` +
		`<source src="` + src + `"></video></div>`
}

// A backdrop is a silent recording with a way to stop it, and nothing else.
func TestABackdropIsSilentAndStoppable(t *testing.T) {
	if r := CheckWith("home", page(stopControl+backdrop("/media/quiet")), withLibrary); r.Blocks() {
		t.Errorf("a silent, stoppable backdrop was refused: %v", r.Findings)
	}
	r := CheckWith("home", page(backdrop("/media/quiet")), withLibrary)
	if !hasRule(r, "backdrop-cannot-be-stopped") {
		t.Errorf("a backdrop nothing stops was accepted: %v", r.Findings)
	}
	for _, src := range []string{"/media/loud", "/media/never-probed"} {
		r := CheckWith("home", page(stopControl+backdrop(src)), withLibrary)
		if !hasRule(r, "backdrop-has-sound") {
			t.Errorf("%s became a muted backdrop: %v", src, r.Findings)
		}
	}
}

// The attributes alone switch nothing off: a decorative-looking video the
// library has not vouched for is refused, and a captioned one passes as it
// always did.
func TestTheMarkupAloneDoesNotMakeABackdrop(t *testing.T) {
	if r := Check("home", page(stopControl+backdrop("/media/quiet"))); !r.Blocks() {
		t.Error("markup alone exempted a video from every rule")
	}
	captioned := `<video muted loop autoplay aria-hidden="true" src="/media/loud">` +
		`<track kind="captions" srclang="en" src="/media/loud.vtt"></video>`
	if r := CheckWith("home", page(captioned), withLibrary); r.Blocks() {
		t.Errorf("a captioned video that passed before is refused now: %v", r.Findings)
	}
}
