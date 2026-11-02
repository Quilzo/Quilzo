// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package vector

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Store keeps a provider's vectors for texts, so a text is embedded once
// and not again on every publish.
//
// Kept by the model's name and the text's hash, never the text: what a
// page said is in the store's history already, and a second copy here
// would be one more place a deleted page lived on. A vector is kept as
// float32s: half the size of float64, and more precision than any
// embedding model's own.
type Store struct{ Dir string }

// MaxDims is the most dimensions a stored vector may have.
const MaxDims = 8192

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (s Store) modelDir(model string) string { return filepath.Join(s.Dir, hash(model)[:16]) }

func (s Store) path(model, text string) string {
	h := hash(text)
	return filepath.Join(s.modelDir(model), h[:2], h)
}

// Get is a text's vector from a model, when one is kept.
func (s Store) Get(model, text string) ([]float64, bool) {
	b, err := os.ReadFile(s.path(model, text))
	if err != nil || len(b) == 0 || len(b)%4 != 0 || len(b)/4 > MaxDims {
		return nil, false
	}
	v := make([]float64, len(b)/4)
	for i := range v {
		v[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:])))
	}
	return v, true
}

// Put keeps a text's vector from a model.
func (s Store) Put(model, text string, v []float64) error {
	if len(v) == 0 || len(v) > MaxDims {
		return errors.New("a vector of no dimensions, or too many")
	}
	b := make([]byte, 4*len(v))
	for i, x := range v {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return errors.New("a vector is numbers")
		}
		binary.LittleEndian.PutUint32(b[i*4:], math.Float32bits(float32(x)))
	}
	p := s.path(model, text)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(p, b, 0o600)
}

// Touch says a model's vectors changed, for whoever caches them.
func (s Store) Touch(model string, now time.Time) error {
	if err := os.MkdirAll(s.modelDir(model), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(s.modelDir(model), "stamp"), []byte(now.UTC().Format(time.RFC3339Nano)), 0o600)
}

// Stamp is when a model's vectors last changed: zero when never.
func (s Store) Stamp(model string) time.Time {
	b, err := os.ReadFile(filepath.Join(s.modelDir(model), "stamp"))
	if err != nil {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, string(b))
	return t
}
