// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// aRecording makes a short real video, or skips.
//
// Skipped rather than faked, because the thing being tested is what an
// external tool says about a real container — and a fixture this program
// invented would test nothing but itself. The tools are not a build
// dependency, so a machine without them runs the rest of this file and the
// degradation tests below, which are the ones that matter on such a machine.
func aRecording(t *testing.T) []byte {
	t.Helper()
	bin, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("no ffmpeg here, which is a configuration this supports")
	}
	dir := t.TempDir()
	out := dir + "/probe.webm"
	cmd := exec.Command(bin, "-v", "error", "-f", "lavfi",
		"-i", "testsrc=size=320x240:rate=10:duration=3",
		"-c:v", "libvpx", "-b:v", "100k", "-y", out)
	if err := cmd.Run(); err != nil {
		t.Skipf("this ffmpeg cannot make the fixture: %v", err)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A recording's shape is read, which nothing could do.
//
// A stored video had Width and Height of zero, because those are set only for
// images — so a page carrying one emitted no intrinsic size and reflowed as
// the video arrived. The same failure the AVIF box walk exists to prevent for
// pictures, on the format where the file is largest and the reflow worst.
func TestARecordingsShapeIsRead(t *testing.T) {
	body := aRecording(t)
	sh, known, err := Probe("webm", body)
	if err != nil {
		t.Fatal(err)
	}
	if !known {
		t.Fatal("nothing was determined about a real recording")
	}
	if sh.Width != 320 || sh.Height != 240 {
		t.Errorf("it reports %dx%d, want 320x240", sh.Width, sh.Height)
	}
	if sh.Seconds < 2.5 || sh.Seconds > 3.5 {
		t.Errorf("it reports %.2f seconds, want about 3", sh.Seconds)
	}
}

// A still comes out, and it is a picture this library would accept.
//
// Verified rather than trusted: a tool that handed back an error page must not
// become a picture on a page, which is the rule the WebP encoder's output is
// already held to.
func TestAPosterFrameIsAPicture(t *testing.T) {
	body := aRecording(t)
	still, err := PosterFrom("webm", body, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(still) == 0 {
		t.Fatal("no frame came back")
	}
	if !bytes.HasPrefix(still, []byte{0x89, 'P', 'N', 'G'}) {
		t.Fatal("what came back is not a PNG")
	}
	f, err := Accept("poster.png", still, time.Now())
	if err != nil {
		t.Fatalf("the extracted frame is not storable: %v", err)
	}
	if f.Width != 320 || f.Height != 240 {
		t.Errorf("the still is %dx%d, want the recording's 320x240",
			f.Width, f.Height)
	}
}

// Nothing to read it with is a configuration, not a failure.
//
// A store with no ffprobe holds the same recordings and says nothing about
// their insides. Reporting that as an error would make every upload on such a
// machine look broken, which is how somebody comes to believe the tool is a
// dependency after all.
func TestNoToolIsNotAnError(t *testing.T) {
	t.Setenv("PATH", "/nonexistent")
	if _, ok := HaveFFprobe(); ok {
		t.Fatal("ffprobe was found with an empty PATH, so this checks nothing")
	}
	sh, known, err := Probe("webm", []byte("not really a recording"))
	if err != nil {
		t.Errorf("an absent tool was reported as an error: %v", err)
	}
	if known {
		t.Errorf("something was claimed about a recording nothing read: %+v", sh)
	}
	still, err := PosterFrom("webm", []byte("not really a recording"), 1)
	if err != nil {
		t.Errorf("an absent extractor was reported as an error: %v", err)
	}
	if still != nil {
		t.Error("a frame came back from nowhere")
	}
}

// Nonsense in is an error out, not a claim.
func TestGarbageIsRefused(t *testing.T) {
	if _, err := exec.LookPath("ffprobe"); err != nil {
		t.Skip("no ffprobe here")
	}
	if _, known, err := Probe("webm", []byte("this is not a container")); err == nil && known {
		t.Error("a shape was claimed for something that is not a recording")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("no ffmpeg here")
	}
	if still, err := PosterFrom("webm", []byte("this is not a container"), 0); err == nil &&
		len(still) > 0 {
		t.Error("a frame came out of something that is not a recording")
	}
}

// The subprocess is told it may open nothing but the file it was given.
//
// The real hazard in handing a media tool an untrusted container is not a
// crash, it is a playlist: a crafted input that names http:// or /etc/passwd
// and has the tool fetch it. A source check, because the flag that says no is
// the kind of thing a later edit tidies away.
func TestTheToolsMayOpenNothingButTheFile(t *testing.T) {
	body, err := os.ReadFile("probe.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if n := strings.Count(text, `"-protocol_whitelist", "file"`); n < 2 {
		t.Errorf("only %d of the two subprocess calls limits its protocols; "+
			"the one that does not can be made to open a URL by the file it "+
			"is reading", n)
	}
	if !strings.Contains(text, "exec.CommandContext") {
		t.Error("a subprocess runs without a timeout, so a crafted container " +
			"that makes a demuxer loop is an upload that never returns")
	}
}
