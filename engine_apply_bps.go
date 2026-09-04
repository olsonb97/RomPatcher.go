package rompatcher

import (
	"context"
	"fmt"
	"io"
)

func applyBPSStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, readOutput io.ReaderAt, output io.WriterAt, opts ApplyOptions) (int64, error) {
	if patchSize < 16 {
		return 0, fmt.Errorf("%w: BPS header", ErrInvalidPatch)
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
		return 0, checksum32Mismatch(ErrPatchMismatch, FormatBPS, "CRC32", footer[2], patchCRC)
	}
	d := newReaderDecoder(ctx, patch, patchSize-12)
	_ = d.seek(4)
	declaredSource, err := readBPSVLVReader(d)
	if err != nil {
		return 0, err
	}
	targetSize, err := readBPSVLVReader(d)
	if err != nil {
		return 0, err
	}
	metadataLength, err := readBPSVLVReader(d)
	if err != nil || metadataLength > uint64(d.remaining()) {
		return 0, ErrInvalidPatch
	}
	_ = d.skip(int64(metadataLength))
	if targetSize > uint64(^uint64(0)>>1) {
		return 0, ErrInvalidPatch
	}
	if err := checkOutputSize64(targetSize, uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	if opts.Validate {
		if uint64(sourceSize) != declaredSource {
			return 0, sourceSizeMismatch(FormatBPS, sourceSize, opts, declaredSource)
		}
		got, err := crc32ReaderAt(opts, source, sourceSize, FormatBPS, "validate-source")
		if err != nil {
			return 0, err
		}
		if got != footer[0] {
			return 0, checksum32Mismatch(ErrSourceMismatch, FormatBPS, "CRC32", footer[0], got)
		}
	}
	state := bpsActionState{}
	scratch := make([]byte, fileChunkSize)
	var targetPattern []byte
	actions := int64(0)
	for !d.eof() {
		encoded, err := readBPSVLVReader(d)
		if err != nil {
			return 0, err
		}
		length := (encoded >> 2) + 1
		actionType := int(encoded & 3)
		var relative int64
		if actionType == bpsSourceCopy || actionType == bpsTargetCopy {
			encodedRelative, err := readBPSVLVReader(d)
			if err != nil {
				return 0, err
			}
			if encodedRelative>>1 > uint64(^uint64(0)>>1) {
				return 0, ErrInvalidPatch
			}
			relative = int64(encodedRelative >> 1)
			if encodedRelative&1 != 0 {
				relative = -relative
			}
		}
		position := state.position
		copyPosition, err := state.advance(actionType, length, relative, declaredSource, targetSize)
		if err != nil {
			return 0, err
		}
		length64 := int64(length)
		position64 := int64(position)
		switch actionType {
		case bpsSourceRead:
			if err := copyRange(opts, output, position64, source, position64, length64, FormatBPS, scratch); err != nil {
				return 0, err
			}
		case bpsTargetRead:
			if length > uint64(d.remaining()) {
				return 0, ErrUnexpectedEnd
			}
			if err := writePatchRange(ctx, patch, d.off, output, position64, length64, scratch); err != nil {
				return 0, err
			}
			_ = d.skip(length64)
		case bpsSourceCopy:
			if err := copyRange(opts, output, position64, source, int64(copyPosition), length64, FormatBPS, scratch); err != nil {
				return 0, err
			}
		case bpsTargetCopy:
			distance := position - copyPosition
			if distance <= fileChunkSize {
				if cap(targetPattern) < int(distance) {
					capacity := cap(targetPattern) * 2
					if capacity < int(distance) {
						capacity = int(distance)
					}
					if capacity > fileChunkSize {
						capacity = fileChunkSize
					}
					targetPattern = make([]byte, int(distance), capacity)
				} else {
					targetPattern = targetPattern[:int(distance)]
				}
				if err := readAtFull(readOutput, targetPattern, int64(copyPosition)); err != nil {
					return 0, err
				}
			}
			for copied := int64(0); copied < length64; {
				n := int64(fileChunkSize)
				if length64-copied < n {
					n = length64 - copied
				}
				buf := scratch[:n]
				if distance <= fileChunkSize {
					fillPattern(buf, targetPattern, int(uint64(copied)%distance))
				} else if err := readAtFull(readOutput, buf, int64(copyPosition)+copied); err != nil {
					return 0, err
				}
				if err := writeAtFull(output, buf, position64+copied); err != nil {
					return 0, err
				}
				copied += n
			}
		}
		actions++
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatBPS, Completed: actions}); err != nil {
			return 0, err
		}
	}
	if state.position != targetSize {
		return 0, ErrInvalidPatch
	}
	if opts.Validate {
		got, err := crc32ReaderAt(opts, readOutput, int64(targetSize), FormatBPS, "validate-target")
		if err != nil {
			return 0, err
		}
		if got != footer[1] {
			return 0, checksum32Mismatch(ErrTargetMismatch, FormatBPS, "CRC32", footer[1], got)
		}
	}
	return int64(targetSize), nil
}
