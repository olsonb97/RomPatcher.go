package rompatcher

import (
	"context"
	"fmt"
	"io"
)

func applyUPSStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, readOutput io.ReaderAt, output io.WriterAt, opts ApplyOptions) (int64, error) {
	if patchSize < 16 {
		return 0, fmt.Errorf("%w: UPS header", ErrInvalidPatch)
	}
	footer, err := readPatchFooter(patch, patchSize)
	if err != nil {
		return 0, err
	}
	patchCRC, err := crc32PatchRange(ctx, patch, 0, patchSize-4)
	if err != nil {
		return 0, err
	}
	if patchCRC != footer[2] {
		return 0, checksum32Mismatch(ErrPatchMismatch, FormatUPS, "CRC32", footer[2], patchCRC)
	}
	d := newReaderDecoder(ctx, patch, patchSize-12)
	_ = d.seek(4)
	declaredSource, err := readBPSVLVReader(d)
	if err != nil {
		return 0, err
	}
	declaredTarget, err := readBPSVLVReader(d)
	if err != nil {
		return 0, err
	}
	actualSize := uint64(sourceSize)
	var sourceCRC uint32
	checked := false
	if opts.Validate || actualSize == declaredTarget {
		sourceCRC, err = crc32ReaderAt(opts, source, sourceSize, FormatUPS, "validate-source")
		if err != nil {
			return 0, err
		}
		checked = true
	}
	undo := checked && !(actualSize == declaredSource && sourceCRC == footer[0]) && actualSize == declaredTarget && sourceCRC == footer[1]
	if opts.Validate && !undo && !(actualSize == declaredSource && sourceCRC == footer[0]) {
		if actualSize == declaredSource && actualSize != declaredTarget {
			return 0, checksum32Mismatch(ErrSourceMismatch, FormatUPS, "CRC32", footer[0], sourceCRC)
		}
		if actualSize == declaredTarget && actualSize != declaredSource {
			return 0, checksum32Mismatch(ErrSourceMismatch, FormatUPS, "CRC32", footer[1], sourceCRC)
		}
		if actualSize == declaredSource && actualSize == declaredTarget {
			expected := fmt.Sprintf("%08x or %08x", footer[0], footer[1])
			return 0, checksumMismatch(ErrSourceMismatch, FormatUPS, "CRC32", expected, fmt.Sprintf("%08x", sourceCRC))
		}
		return 0, sourceSizeMismatch(FormatUPS, sourceSize, opts, declaredSource, declaredTarget)
	}
	targetSize := declaredTarget
	if undo {
		targetSize = declaredSource
	} else if !opts.Validate && declaredSource < actualSize && targetSize < actualSize {
		targetSize = actualSize
	}
	if targetSize > uint64(^uint64(0)>>1) {
		return 0, ErrInvalidPatch
	}
	if err := checkOutputSize64(targetSize, actualSize, opts); err != nil {
		return 0, err
	}
	if err := initializeOutput(source, sourceSize, int64(targetSize), output, opts, FormatUPS); err != nil {
		return 0, err
	}
	maximum := declaredSource
	if declaredTarget > maximum {
		maximum = declaredTarget
	}
	position, records := uint64(0), int64(0)
	xorBuf := make([]byte, 0, 64<<10)
	sourceBuf := make([]byte, 64<<10)
	flushXOR := func(start uint64) error {
		if len(xorBuf) == 0 || start >= targetSize {
			xorBuf = xorBuf[:0]
			return nil
		}
		length := uint64(len(xorBuf))
		if targetSize-start < length {
			length = targetSize - start
		}
		old := sourceBuf[:length]
		clear(old)
		if start < actualSize {
			readLength := length
			if actualSize-start < readLength {
				readLength = actualSize - start
			}
			if err := readAtFull(source, old[:readLength], int64(start)); err != nil {
				return err
			}
		}
		for i := range old {
			old[i] ^= xorBuf[i]
		}
		if err := writeAtFull(output, old, int64(start)); err != nil {
			return err
		}
		xorBuf = xorBuf[:0]
		return nil
	}
	for !d.eof() {
		offset, err := readBPSVLVReader(d)
		if err != nil || position > ^uint64(0)-offset {
			return 0, ErrInvalidPatch
		}
		position += offset
		runLength := uint64(0)
		for {
			x, err := d.u8()
			if err != nil {
				return 0, fmt.Errorf("%w: unterminated UPS record", ErrInvalidPatch)
			}
			if x == 0 {
				if runLength == 0 {
					return 0, fmt.Errorf("%w: empty UPS record", ErrInvalidPatch)
				}
				if err := flushXOR(position - uint64(len(xorBuf))); err != nil {
					return 0, err
				}
				break
			}
			if position >= maximum {
				return 0, fmt.Errorf("%w: UPS record outside file range", ErrInvalidPatch)
			}
			xorBuf = append(xorBuf, x)
			position++
			runLength++
			if len(xorBuf) == cap(xorBuf) {
				if err := flushXOR(position - uint64(len(xorBuf))); err != nil {
					return 0, err
				}
			}
		}
		if position == ^uint64(0) {
			return 0, ErrInvalidPatch
		}
		position++
		records++
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatUPS, Completed: records}); err != nil {
			return 0, err
		}
	}
	if opts.Validate {
		want := footer[1]
		if undo {
			want = footer[0]
		}
		got, err := crc32ReaderAt(opts, readOutput, int64(targetSize), FormatUPS, "validate-target")
		if err != nil {
			return 0, err
		}
		if got != want {
			return 0, checksum32Mismatch(ErrTargetMismatch, FormatUPS, "CRC32", want, got)
		}
	}
	return int64(targetSize), nil
}
