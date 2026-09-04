package rompatcher

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type rupStreamFile struct {
	index                  int
	sourceSize, targetSize uint64
	sourceMD5, targetMD5   string
	overflowMode           byte
	overflowOffset         int64
	overflowLength         uint64
}

func parseRUPStream(ctx context.Context, patch io.ReaderAt, patchSize int64, sourceMD5 string, validate bool) (rupStreamFile, error) {
	if patchSize < 0x801 {
		return rupStreamFile{}, fmt.Errorf("%w: RUP header", ErrInvalidPatch)
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(0x800)
	var first, selected rupStreamFile
	haveFirst, matched, ended := false, false, false
	current := rupStreamFile{index: -1}
	fileIndex := 0
	for !d.eof() {
		command, err := d.u8()
		if err != nil {
			return selected, err
		}
		switch command {
		case 0:
			if !d.eof() {
				return selected, fmt.Errorf("%w: data after RUP end command", ErrInvalidPatch)
			}
			ended = true
		case 1:
			nameLength, err := readRUPVLVReader(d)
			if err != nil || nameLength > uint64(d.remaining()) {
				return selected, ErrInvalidPatch
			}
			_ = d.skip(int64(nameLength))
			if _, err := d.u8(); err != nil {
				return selected, err
			}
			sourceSize, err := readRUPVLVReader(d)
			if err != nil {
				return selected, err
			}
			targetSize, err := readRUPVLVReader(d)
			if err != nil {
				return selected, err
			}
			sourceHash, err := d.bytes(16)
			if err != nil {
				return selected, err
			}
			targetHash, err := d.bytes(16)
			if err != nil {
				return selected, err
			}
			current = rupStreamFile{index: fileIndex, sourceSize: sourceSize, targetSize: targetSize, sourceMD5: hex.EncodeToString(sourceHash), targetMD5: hex.EncodeToString(targetHash)}
			fileIndex++
			if sourceSize != targetSize {
				current.overflowMode, err = d.u8()
				if err != nil || current.overflowMode != 'A' && current.overflowMode != 'M' {
					return selected, ErrInvalidPatch
				}
				if sourceSize < targetSize && current.overflowMode != 'A' || sourceSize > targetSize && current.overflowMode != 'M' {
					return selected, fmt.Errorf("%w: inconsistent RUP overflow mode", ErrInvalidPatch)
				}
				current.overflowLength, err = readRUPVLVReader(d)
				if err != nil || current.overflowLength > uint64(d.remaining()) {
					return selected, ErrInvalidPatch
				}
				difference := sourceSize
				if targetSize > sourceSize {
					difference = targetSize - sourceSize
				} else {
					difference = sourceSize - targetSize
				}
				if current.overflowLength > difference {
					return selected, ErrInvalidPatch
				}
				current.overflowOffset = d.off
				_ = d.skip(int64(current.overflowLength))
			}
			if !haveFirst {
				first, haveFirst = current, true
			}
			if !matched && (sourceMD5 == current.sourceMD5 || sourceMD5 == current.targetMD5) {
				selected, matched = current, true
			}
		case 2:
			if current.index < 0 {
				return selected, fmt.Errorf("%w: RUP record before file", ErrInvalidPatch)
			}
			offset, err := readRUPVLVReader(d)
			if err != nil {
				return selected, err
			}
			length, err := readRUPVLVReader(d)
			if err != nil || length == 0 || length > uint64(d.remaining()) {
				return selected, ErrInvalidPatch
			}
			maximum := current.sourceSize
			if current.targetSize > maximum {
				maximum = current.targetSize
			}
			if length > maximum || offset > maximum-length {
				return selected, ErrInvalidPatch
			}
			_ = d.skip(int64(length))
		default:
			return selected, fmt.Errorf("%w: RUP command 0x%02x", ErrInvalidPatch, command)
		}
		if ended {
			break
		}
	}
	if !ended || !haveFirst {
		return selected, fmt.Errorf("%w: RUP end command missing", ErrInvalidPatch)
	}
	if matched {
		return selected, nil
	}
	if validate {
		return first, ErrSourceMismatch
	}
	return first, nil
}

func applyRUPStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, readOutput io.ReaderAt, output io.WriterAt, opts ApplyOptions) (int64, error) {
	sourceHash, err := md5ReaderAt(opts, source, sourceSize, FormatRUP, "validate-source")
	if err != nil {
		return 0, err
	}
	selected, err := parseRUPStream(ctx, patch, patchSize, sourceHash, opts.Validate)
	if err != nil {
		if errors.Is(err, ErrSourceMismatch) {
			actualSize := uint64(sourceSize)
			if actualSize == selected.sourceSize && actualSize != selected.targetSize {
				return 0, checksumMismatch(ErrSourceMismatch, FormatRUP, "MD5", selected.sourceMD5, sourceHash)
			}
			if actualSize == selected.targetSize && actualSize != selected.sourceSize {
				return 0, checksumMismatch(ErrSourceMismatch, FormatRUP, "MD5", selected.targetMD5, sourceHash)
			}
			if actualSize == selected.sourceSize && actualSize == selected.targetSize {
				expected := selected.sourceMD5 + " or " + selected.targetMD5
				return 0, checksumMismatch(ErrSourceMismatch, FormatRUP, "MD5", expected, sourceHash)
			}
			return 0, sourceSizeMismatch(FormatRUP, sourceSize, opts, selected.sourceSize, selected.targetSize)
		}
		return 0, err
	}
	undo := sourceHash == selected.targetMD5
	targetSize := selected.targetSize
	if undo {
		targetSize = selected.sourceSize
	}
	if targetSize > uint64(^uint64(0)>>1) {
		return 0, ErrInvalidPatch
	}
	if err := checkOutputSize64(targetSize, uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	if err := initializeOutput(source, sourceSize, int64(targetSize), output, opts, FormatRUP); err != nil {
		return 0, err
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(0x800)
	currentIndex := -1
	records := int64(0)
	buf, old := make([]byte, fileChunkSize), make([]byte, fileChunkSize)
	for !d.eof() {
		command, err := d.u8()
		if err != nil {
			return 0, err
		}
		if command == 0 {
			break
		}
		if command == 1 {
			currentIndex++
			nameLength, err := readRUPVLVReader(d)
			if err != nil || nameLength > uint64(d.remaining()) {
				return 0, ErrInvalidPatch
			}
			if err := d.skip(int64(nameLength)); err != nil {
				return 0, err
			}
			if _, err := d.u8(); err != nil {
				return 0, err
			}
			sourceLength, err := readRUPVLVReader(d)
			if err != nil {
				return 0, err
			}
			targetLength, err := readRUPVLVReader(d)
			if err != nil {
				return 0, err
			}
			if err := d.skip(32); err != nil {
				return 0, err
			}
			if sourceLength != targetLength {
				if _, err := d.u8(); err != nil {
					return 0, err
				}
				overflowLength, err := readRUPVLVReader(d)
				if err != nil || overflowLength > uint64(d.remaining()) {
					return 0, ErrInvalidPatch
				}
				if err := d.skip(int64(overflowLength)); err != nil {
					return 0, err
				}
			}
			continue
		}
		if command != 2 {
			return 0, ErrInvalidPatch
		}
		offset, err := readRUPVLVReader(d)
		if err != nil {
			return 0, err
		}
		length, err := readRUPVLVReader(d)
		if err != nil {
			return 0, err
		}
		if currentIndex != selected.index {
			_ = d.skip(int64(length))
			continue
		}
		applyLength := length
		if offset >= targetSize {
			applyLength = 0
		} else if targetSize-offset < applyLength {
			applyLength = targetSize - offset
		}
		for done := uint64(0); done < length; {
			n := uint64(len(buf))
			if length-done < n {
				n = length - done
			}
			if err := d.read(buf[:n]); err != nil {
				return 0, err
			}
			writeLength := n
			if done >= applyLength {
				writeLength = 0
			} else if applyLength-done < writeLength {
				writeLength = applyLength - done
			}
			if writeLength > 0 {
				clear(old[:writeLength])
				position := int64(offset + done)
				if position < sourceSize {
					readLength := int64(writeLength)
					if sourceSize-position < readLength {
						readLength = sourceSize - position
					}
					if err := readAtFull(source, old[:readLength], position); err != nil {
						return 0, err
					}
				}
				for i := range buf[:writeLength] {
					buf[i] ^= old[i]
				}
				if err := writeAtFull(output, buf[:writeLength], position); err != nil {
					return 0, err
				}
			}
			done += n
		}
		records++
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatRUP, Completed: records}); err != nil {
			return 0, err
		}
	}
	if selected.overflowLength > 0 && (selected.overflowMode == 'A' && !undo || selected.overflowMode == 'M' && undo) {
		start := selected.sourceSize
		if undo {
			start = selected.targetSize
		}
		buf := make([]byte, fileChunkSize)
		for done := uint64(0); done < selected.overflowLength; {
			n := uint64(len(buf))
			if selected.overflowLength-done < n {
				n = selected.overflowLength - done
			}
			if err := readAtFull(patch, buf[:n], selected.overflowOffset+int64(done)); err != nil {
				return 0, err
			}
			for i := range buf[:n] {
				buf[i] ^= 0xff
			}
			if err := writeAtFull(output, buf[:n], int64(start+done)); err != nil {
				return 0, err
			}
			done += n
		}
	}
	if opts.Validate {
		want := selected.targetMD5
		if undo {
			want = selected.sourceMD5
		}
		got, err := md5ReaderAt(opts, readOutput, int64(targetSize), FormatRUP, "validate-target")
		if err != nil {
			return 0, err
		}
		if got != want {
			return 0, checksumMismatch(ErrTargetMismatch, FormatRUP, "MD5", want, got)
		}
	}
	return int64(targetSize), nil
}
