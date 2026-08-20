package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/quilzo/quilzo/internal/schema"
)

// Content that fails its type answers 422, not 500.
//
// It answered 500 until somebody looked: a record missing a required field
// paged an on-call engineer, spent an error budget on a typo, and told the
// client to retry something that could never succeed however many times it
// was sent. The distinction a caller needs is "your content is wrong" versus
// "this server is broken", and only the writer knows which.
func TestInvalidContentIsAClientErrorNotAServerError(t *testing.T) {
	if !schema.IsInvalid(&schema.Invalid{Where: "products"}) {
		t.Fatal("a schema.Invalid is not recognised as invalid content, so " +
			"every caller will keep reporting it as a server fault")
	}
	// And an ordinary error is not mistaken for one, or a real failure would
	// start being reported to clients as their own fault.
	if schema.IsInvalid(errors.New("the disk is full")) {
		t.Error("an unrelated error was classified as invalid content")
	}
	// Wrapped, because the write path returns it through several layers.
	wrapped := fmt.Errorf("writing records: %w", &schema.Invalid{Where: "x"})
	if !schema.IsInvalid(wrapped) {
		t.Error("a wrapped validation error was not recognised")
	}
}
