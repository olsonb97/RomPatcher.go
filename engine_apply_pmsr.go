package rompatcher

import (
	"context"
	"fmt"
	"io"
)

func applyPMSRStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(4)
	count, err := d.u32be()
	if err != nil {
		return 0, err
	}
	targetSize := int64(41943040)
	for index := uint32(0); index < count; index++ {
		offset, err := d.u32be()
		if err != nil {
			return 0, err
		}
		length, err := d.u32be()
		if err != nil || int64(length) > d.remaining() {
			return 0, ErrInvalidPatch
		}
		end := int64(offset) + int64(length)
		if end < int64(offset) {
			return 0, ErrInvalidPatch
		}
		if end > targetSize {
			targetSize = end
		}
		_ = d.skip(int64(length))
	}
	if !d.eof() {
		return 0, fmt.Errorf("%w: trailing PMSR data", ErrInvalidPatch)
	}
	if opts.Validate {
		if sourceSize != 41943040 {
			return 0, sourceSizeMismatch(FormatPMSR, sourceSize, opts, 41943040)
		}
		got, err := crc32ReaderAt(opts, source, sourceSize, FormatPMSR, "validate-source")
		if err != nil {
			return 0, err
		}
		if got != 0xa7f5cd7e {
			return 0, checksum32Mismatch(ErrSourceMismatch, FormatPMSR, "CRC32", 0xa7f5cd7e, got)
		}
	}
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	if err := initializeOutput(source, sourceSize, targetSize, output, opts, FormatPMSR); err != nil {
		return 0, err
	}
	d = newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(8)
	scratch := make([]byte, fileChunkSize)
	for index := uint32(0); index < count; index++ {
		offset, err := d.u32be()
		if err != nil {
			return 0, err
		}
		length, err := d.u32be()
		if err != nil {
			return 0, err
		}
		if err := writePatchRange(ctx, patch, d.off, output, int64(offset), int64(length), scratch); err != nil {
			return 0, err
		}
		_ = d.skip(int64(length))
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatPMSR, Completed: int64(index + 1), Total: int64(count)}); err != nil {
			return 0, err
		}
	}
	return targetSize, nil
}
