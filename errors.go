package rompatcher

import "errors"

var (
	// ErrUnknownFormat means the patch signature is not recognized.
	ErrUnknownFormat = errors.New("rompatcher: unknown patch format")
	// ErrInvalidPatch means the patch structure or values are malformed.
	ErrInvalidPatch = errors.New("rompatcher: invalid patch")
	// ErrSourceMismatch means source validation failed.
	ErrSourceMismatch = errors.New("rompatcher: source does not match patch")
	// ErrTargetMismatch means generated output validation failed.
	ErrTargetMismatch = errors.New("rompatcher: patched output does not match patch")
	// ErrPatchMismatch means the patch's own checksum failed.
	ErrPatchMismatch = errors.New("rompatcher: patch checksum mismatch")
	// ErrOutputTooLarge means a configured or default size limit was exceeded.
	ErrOutputTooLarge = errors.New("rompatcher: size limit exceeded")
	// ErrUnsupported means the requested operation is unavailable for the format.
	ErrUnsupported = errors.New("rompatcher: operation is not supported by this format")
	// ErrUnexpectedEnd means the patch ended before a complete value was read.
	ErrUnexpectedEnd = errors.New("rompatcher: unexpected end of patch")
	// ErrAmbiguousArchive means an archive entry must be selected explicitly.
	ErrAmbiguousArchive = errors.New("rompatcher: archive contains multiple candidate entries")
)
