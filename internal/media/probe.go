// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package media

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// What a recording is, when there is something on the machine that can say.
//
// # Why this is detected and not required
//
// The same arrangement cwebp has, for the same reason: this program has no
// dependencies and will not gain one, and there is no video decoder in Go's
// standard library — not the codec, not the container, not the format. Writing
// one is not a trade anybody should take.
//
// So ffmpeg is used if the operator has it and the pipeline works without it.
// A store with no ffmpeg holds the same recordings, serves them the same way,
// and says what it could not work out; a store with one gets intrinsic sizes
// and a poster frame. Neither is a broken installation.
//
// # What it fixes
//
// A stored video had Width and Height of zero, because those are set only for
// images. So a page carrying one emitted no intrinsic size and reflowed as the
// video arrived — the same failure the AVIF box walk exists to prevent for
// pictures, on the format where the file is largest and the reflow worst.
//
// And it had no poster, so a player showed a black rectangle until enough had
// loaded to draw a frame. The section kind has a poster field and it took a
// second upload of a still somebody had to make themselves.
//
// # What is done about the bytes going to somebody else's program
//
// A recording is a file from outside, and ffmpeg is a large amount of C that
// parses it. Three things, none of which make that safe and all of which make
// it bounded:
//
//   - A timeout. cwebp has none and gets away with it on an image whose pixel
//     count is already capped; a crafted container that makes a demuxer loop is
//     a different proposition, and a publish that hangs is worse than one that
//     does less.
//   - Protocols limited to file. The real hazard in handing a media tool an
//     untrusted container is not a crash, it is a playlist: a crafted input
//     that names http:// or /etc/passwd and has the tool fetch it. This is the
//     flag that says no.
//   - Output bounded and verified. A tool that returned an error page instead
//     of a PNG must not become the bytes this site serves, which is the rule
//     toWebP already applies to its own output.

// probeTimeout bounds one call.
//
// Generous, because a long recording on a slow disk is an ordinary reason to
// take a while, and short enough that a hung demuxer does not become a hung
// upload.
const probeTimeout = 30 * time.Second

// maxPoster bounds what an extractor may hand back.
const maxPoster = maxImage

// Shape is what a recording turns out to be.
type Shape struct {
	Width, Height int
	// Seconds is the duration. Zero means it could not be determined, which
	// is different from a recording of no length and is why this is not an
	// int.
	Seconds float64
}

// HaveFFmpeg reports whether a poster frame can be extracted, so an interface
// can say what it will do rather than silently doing less.
func HaveFFmpeg() (string, bool) {
	bin, err := exec.LookPath("ffmpeg")
	return bin, err == nil
}

// HaveFFprobe reports whether a recording's shape can be read.
func HaveFFprobe() (string, bool) {
	bin, err := exec.LookPath("ffprobe")
	return bin, err == nil
}

// Probe reads the width, height and duration of a recording.
//
// The second return says whether anything could be determined at all. A store
// with no ffprobe gets false and no error: the tool being absent is a
// configuration, not a failure, and reporting it as one would make every
// upload on such a machine look broken.
func Probe(format string, body []byte) (Shape, bool, error) {
	bin, ok := HaveFFprobe()
	if !ok {
		return Shape{}, false, nil
	}
	path, cleanup, err := spill(body)
	if err != nil {
		return Shape{}, false, err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-v", "error", "-hide_banner",
		// No protocol but the file itself. See the note at the top: the
		// hazard is a container that names something else for the tool to
		// open.
		"-protocol_whitelist", "file",
		"-print_format", "json",
		"-show_entries", "stream=width,height:format=duration",
		path)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return Shape{}, false, fmt.Errorf("ffprobe could not read it: %w", err)
	}

	var parsed struct {
		Streams []struct {
			Width  int `json:"width"`
			Height int `json:"height"`
		} `json:"streams"`
		Format struct {
			Duration string `json:"duration"`
		} `json:"format"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		return Shape{}, false, fmt.Errorf("ffprobe said something unreadable: %w", err)
	}

	var sh Shape
	// The first stream with a size is the picture. An audio stream reports
	// none, and a recording with several video streams is one where the first
	// is what a player shows.
	for _, s := range parsed.Streams {
		if s.Width > 0 && s.Height > 0 {
			sh.Width, sh.Height = s.Width, s.Height
			break
		}
	}
	if d, err := strconv.ParseFloat(parsed.Format.Duration, 64); err == nil && d > 0 {
		sh.Seconds = d
	}
	// Bounded the same way an image is. A container claiming a hundred
	// thousand pixels a side is not a recording, and the number would go into
	// a width attribute on a page.
	if sh.Width*sh.Height > MaxPixels {
		return Shape{}, false, fmt.Errorf(
			"it claims %dx%d, which is not a recording anybody made",
			sh.Width, sh.Height)
	}
	return sh, sh.Width > 0 || sh.Seconds > 0, nil
}

// PosterFrom extracts one still, as PNG.
//
// at is where to take it from, in seconds. A moment in rather than the first
// frame, because the first frame of a recording is very often black — a fade
// in, a slate, a camera still adjusting — and a poster nobody can see is the
// thing this exists to replace.
func PosterFrom(format string, body []byte, at float64) ([]byte, error) {
	bin, ok := HaveFFmpeg()
	if !ok {
		return nil, nil
	}
	if at < 0 {
		at = 0
	}
	path, cleanup, err := spill(body)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin,
		"-v", "error", "-hide_banner", "-nostdin",
		"-protocol_whitelist", "file",
		// Before -i, so the seek is done by skipping rather than by decoding
		// everything up to that point. On an hour of video the difference is
		// the whole operation.
		"-ss", strconv.FormatFloat(at, 'f', 3, 64),
		"-i", path,
		"-frames:v", "1",
		"-f", "image2pipe", "-vcodec", "png",
		"-")
	var out, errb bytes.Buffer
	cmd.Stdout = &limitedWriter{to: &out, left: maxPoster}
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg could not take a frame: %w", err)
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("ffmpeg produced no frame")
	}
	// Verified rather than trusted, the same as the WebP encoder's output. A
	// tool that handed back an error page must not become a picture on a page.
	if !bytes.HasPrefix(out.Bytes(), []byte{0x89, 'P', 'N', 'G'}) {
		return nil, fmt.Errorf("ffmpeg returned something that is not a PNG")
	}
	return out.Bytes(), nil
}

// spill writes bytes to a temporary file and returns how to remove it.
//
// A file rather than a pipe, because seeking is the whole operation for a
// poster and a demuxer cannot seek in a stream. The name is generated — no
// part of it comes from a caller — and the file is removed whatever happens,
// including when the tool is killed by the timeout.
func spill(body []byte) (string, func(), error) {
	f, err := os.CreateTemp("", "quilzo-media-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() {
		f.Close()
		os.Remove(f.Name())
	}
	if _, err := f.Write(body); err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return f.Name(), cleanup, nil
}

// limitedWriter stops a subprocess filling memory.
//
// Silently, because the point is a bound rather than a diagnosis: a tool
// sending more than a picture's worth of bytes is one whose output is going to
// fail verification anyway, and the caller's message about that is the useful
// one.
type limitedWriter struct {
	to   *bytes.Buffer
	left int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		return len(p), nil
	}
	if len(p) > w.left {
		p = p[:w.left]
	}
	n, err := w.to.Write(p)
	w.left -= n
	return len(p), err
}
