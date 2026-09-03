package rompatcher

import "errors"

var (
	ErrUnknownFormat    = errors.New("rompatcher: unknown patch format")
	ErrInvalidPatch     = errors.New("rompatcher: invalid patch")
	ErrSourceMismatch   = errors.New("rompatcher: source checksum mismatch")
	ErrTargetMismatch   = errors.New("rompatcher: target checksum mismatch")
	ErrPatchMismatch    = errors.New("rompatcher: patch checksum mismatch")
	ErrOutputTooLarge   = errors.New("rompatcher: requested output exceeds the configured size limit")
	ErrUnsupported      = errors.New("rompatcher: operation is not supported by this format")
	ErrUnexpectedEnd    = errors.New("rompatcher: unexpected end of patch")
	ErrAmbiguousArchive = errors.New("rompatcher: archive contains multiple candidate entries")
)
