package rompatcher

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
)

func ppfBytesEqualAt(source io.ReaderAt, sourceSize int64, offset uint64, expected []byte) (bool, error) {
	if offset > uint64(sourceSize) || uint64(len(expected)) > uint64(sourceSize)-offset {
		return false, nil
	}
	buf := make([]byte, len(expected))
	if err := readAtFull(source, buf, int64(offset)); err != nil {
		return false, err
	}
	return bytes.Equal(buf, expected), nil
}

func ppfUndoingAt(source io.ReaderAt, sourceSize int64, p *PPFPatch) (bool, error) {
	if !p.Undo || len(p.Records) == 0 {
		return false, nil
	}
	r := p.Records[0]
	return ppfBytesEqualAt(source, sourceSize, r.offset, r.data)
}

func validatePPFAt(source io.ReaderAt, sourceSize int64, p *PPFPatch) (bool, error) {
	undoing, err := ppfUndoingAt(source, sourceSize, p)
	if err != nil {
		return false, err
	}
	if !undoing {
		if p.InputSize != 0 && uint64(sourceSize) != uint64(p.InputSize) {
			return false, nil
		}
		if len(p.BlockCheck) != 0 {
			match, err := ppfBytesEqualAt(source, sourceSize, uint64(p.blockOffset()), p.BlockCheck)
			if err != nil || !match {
				return match, err
			}
		}
	}
	if p.Undo {
		for _, r := range p.Records {
			expected := r.undo
			if undoing {
				expected = r.data
			}
			if len(expected) != len(r.data) {
				return false, nil
			}
			match, err := ppfBytesEqualAt(source, sourceSize, r.offset, expected)
			if err != nil || !match {
				return match, err
			}
		}
	}
	return true, nil
}

func initializeOutput(source io.ReaderAt, sourceSize, targetSize int64, output io.WriterAt, opts ApplyOptions, format Format) error {
	copySize := sourceSize
	if targetSize < copySize {
		copySize = targetSize
	}
	if err := copyReaderAt(opts, output, source, copySize, format); err != nil {
		return err
	}
	if targetSize > copySize {
		return zeroRange(opts, output, copySize, targetSize-copySize, format)
	}
	return nil
}

func applyAPSN64At(source io.ReaderAt, sourceSize int64, _ io.ReaderAt, output io.WriterAt, p *APSN64Patch, opts ApplyOptions) (int64, bool, error) {
	targetSize := int64(p.TargetSize)
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, true, err
	}
	if opts.Validate && p.HeaderType == 1 {
		if sourceSize < 0x3f {
			return 0, true, ErrSourceMismatch
		}
		header := make([]byte, 0x3f)
		if err := readAtFull(source, header, 0); err != nil {
			return 0, true, err
		}
		if string(header[0x3c:0x3f]) != p.CartID || !bytes.Equal(header[0x10:0x18], p.CartCRC[:]) {
			return 0, true, ErrSourceMismatch
		}
	}
	if err := initializeOutput(source, sourceSize, targetSize, output, opts, p.Format()); err != nil {
		return 0, true, err
	}
	for i, r := range p.Records {
		length := len(r.data)
		if r.rleLen > 0 {
			length = r.rleLen
		}
		if r.offset < 0 || int64(r.offset) > targetSize-int64(length) {
			return 0, true, ErrInvalidPatch
		}
		if r.rleLen > 0 {
			buf := bytes.Repeat([]byte{r.rle}, r.rleLen)
			if err := writeAtFull(output, buf, int64(r.offset)); err != nil {
				return 0, true, err
			}
		} else if err := writeAtFull(output, r.data, int64(r.offset)); err != nil {
			return 0, true, err
		}
		if err := reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i + 1), Total: int64(len(p.Records))}); err != nil {
			return 0, true, err
		}
	}
	return targetSize, true, nil
}

func applyAPSGBAAt(source io.ReaderAt, sourceSize int64, _ io.ReaderAt, output io.WriterAt, p *APSGBAPatch, opts ApplyOptions) (int64, bool, error) {
	targetSize := int64(p.TargetSize)
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, true, err
	}
	if opts.Validate && sourceSize != int64(p.SourceSize) {
		return 0, true, ErrSourceMismatch
	}
	if err := initializeOutput(source, sourceSize, targetSize, output, opts, p.Format()); err != nil {
		return 0, true, err
	}
	for i, r := range p.Records {
		start := int64(r.offset)
		if start < 0 || start > sourceSize-apsGBABlockSize || start > targetSize-apsGBABlockSize || len(r.xor) != apsGBABlockSize {
			return 0, true, ErrInvalidPatch
		}
		buf := make([]byte, apsGBABlockSize)
		if err := readAtFull(source, buf, start); err != nil {
			return 0, true, err
		}
		if opts.Validate && CRC16(buf) != r.sourceCRC {
			return 0, true, ErrSourceMismatch
		}
		for j, x := range r.xor {
			buf[j] ^= x
		}
		if opts.Validate && CRC16(buf) != r.targetCRC {
			return 0, true, ErrTargetMismatch
		}
		if err := writeAtFull(output, buf, start); err != nil {
			return 0, true, err
		}
		if err := reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i + 1), Total: int64(len(p.Records))}); err != nil {
			return 0, true, err
		}
	}
	return targetSize, true, nil
}

func applyRUPAt(source io.ReaderAt, sourceSize int64, readOutput io.ReaderAt, output io.WriterAt, p *RUPPatch, opts ApplyOptions) (int64, bool, error) {
	sum, err := md5ReaderAt(opts, source, sourceSize, p.Format(), "validate-source")
	if err != nil {
		return 0, true, err
	}
	file, undo := p.matchingFile(sum)
	if file == nil {
		if opts.Validate {
			return 0, true, ErrSourceMismatch
		}
		if len(p.Files) == 0 {
			return 0, true, ErrInvalidPatch
		}
		file = &p.Files[0]
	}
	if err := validateRUPFile(file); err != nil {
		return 0, true, err
	}
	targetSize := file.TargetSize
	if undo {
		targetSize = file.SourceSize
	}
	if targetSize > uint64(^uint64(0)>>1) {
		return 0, true, ErrInvalidPatch
	}
	if err := checkOutputSize64(targetSize, uint64(sourceSize), opts); err != nil {
		return 0, true, err
	}
	if err := initializeOutput(source, sourceSize, int64(targetSize), output, opts, p.Format()); err != nil {
		return 0, true, err
	}
	scratch := make([]byte, fileChunkSize)
	for i, r := range file.Records {
		start := int64(r.offset)
		if start >= int64(targetSize) {
			continue
		}
		length := len(r.xor)
		if int64(length) > int64(targetSize)-start {
			length = int(int64(targetSize) - start)
		}
		for done := 0; done < length; {
			n := len(scratch)
			if length-done < n {
				n = length - done
			}
			buf := scratch[:n]
			clear(buf)
			position := start + int64(done)
			if position < sourceSize {
				readLength := n
				if sourceSize-position < int64(readLength) {
					readLength = int(sourceSize - position)
				}
				if err := readAtFull(source, buf[:readLength], position); err != nil {
					return 0, true, err
				}
			}
			for j, x := range r.xor[done : done+n] {
				buf[j] ^= x
			}
			if err := writeAtFull(output, buf, position); err != nil {
				return 0, true, err
			}
			done += n
			if err := checkCanceled(opts); err != nil {
				return 0, true, err
			}
		}
		if err := reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i + 1), Total: int64(len(file.Records))}); err != nil {
			return 0, true, err
		}
	}
	if file.OverflowMode == 'A' && !undo {
		start := int64(file.SourceSize)
		buf := make([]byte, len(file.Overflow))
		for i, b := range file.Overflow {
			buf[i] = b ^ 0xff
		}
		if err := writeAtFull(output, buf, start); err != nil {
			return 0, true, err
		}
	} else if file.OverflowMode == 'M' && undo {
		start := int64(file.TargetSize)
		buf := make([]byte, len(file.Overflow))
		for i, b := range file.Overflow {
			buf[i] = b ^ 0xff
		}
		if err := writeAtFull(output, buf, start); err != nil {
			return 0, true, err
		}
	}
	if opts.Validate {
		got, err := md5ReaderAt(opts, readOutput, int64(targetSize), p.Format(), "validate-target")
		if err != nil {
			return 0, true, err
		}
		want := file.TargetMD5
		if undo {
			want = file.SourceMD5
		}
		if got != want {
			return 0, true, ErrTargetMismatch
		}
	}
	return int64(targetSize), true, nil
}

func md5ReaderAt(opts ApplyOptions, r io.ReaderAt, size int64, format Format, phase string) (string, error) {
	h := md5.New()
	buf := make([]byte, fileChunkSize)
	for off := int64(0); off < size; {
		n := int64(len(buf))
		if size-off < n {
			n = size - off
		}
		if err := readAtFull(r, buf[:n], off); err != nil {
			return "", err
		}
		_, _ = h.Write(buf[:n])
		off += n
		if err := reportProgress(opts, Progress{Phase: phase, Format: format, Completed: off, Total: size}); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func applyBDFAt(source io.ReaderAt, sourceSize int64, output io.WriterAt, p *BDFPatch, opts ApplyOptions) (int64, bool, error) {
	if p.TargetSize > uint64(^uint64(0)>>1) {
		return 0, true, ErrInvalidPatch
	}
	targetSize := int64(p.TargetSize)
	if err := checkOutputSize64(p.TargetSize, uint64(sourceSize), opts); err != nil {
		return 0, true, err
	}
	oldPos, newPos := int64(0), int64(0)
	diffBuf := make([]byte, fileChunkSize)
	oldBuf := make([]byte, fileChunkSize)
	total := int64(0)
	if !p.compressed {
		total = int64(len(p.Records))
	}
	_, err := p.walkRecords(opts, uint64(sourceSize), func(recordIndex int, diff io.Reader, diffLength int64, extra io.Reader, extraLength, skip int64) error {
		diffEnd, ok := addInt64(newPos, diffLength)
		if !ok || diffEnd > targetSize {
			return ErrInvalidPatch
		}
		oldEnd, ok := addInt64(oldPos, diffLength)
		if !ok {
			return fmt.Errorf("%w: BSDIFF source position overflow", ErrInvalidPatch)
		}
		for done := int64(0); done < diffLength; {
			n := int64(len(diffBuf))
			if diffLength-done < n {
				n = diffLength - done
			}
			buf := diffBuf[:int(n)]
			if _, err := io.ReadFull(diff, buf); err != nil {
				return fmt.Errorf("%w: BSDIFF diff: %v", ErrInvalidPatch, err)
			}
			segmentOld, ok := addInt64(oldPos, done)
			if !ok {
				return fmt.Errorf("%w: BSDIFF source position overflow", ErrInvalidPatch)
			}
			within, sourceOffset, count := sourceSpan(segmentOld, n, sourceSize)
			if count > 0 {
				old := oldBuf[:int(count)]
				if err := readAtFull(source, old, sourceOffset); err != nil {
					return err
				}
				for j, b := range old {
					buf[int(within)+j] += b
				}
			}
			if err := writeAtFull(output, buf, newPos+done); err != nil {
				return err
			}
			done += n
			if err := checkCanceled(opts); err != nil {
				return err
			}
		}
		newPos, oldPos = diffEnd, oldEnd
		extraEnd, ok := addInt64(newPos, extraLength)
		if !ok || extraEnd > targetSize {
			return ErrInvalidPatch
		}
		for done := int64(0); done < extraLength; {
			n := int64(len(diffBuf))
			if extraLength-done < n {
				n = extraLength - done
			}
			buf := diffBuf[:int(n)]
			if _, err := io.ReadFull(extra, buf); err != nil {
				return fmt.Errorf("%w: BSDIFF extra: %v", ErrInvalidPatch, err)
			}
			if err := writeAtFull(output, buf, newPos+done); err != nil {
				return err
			}
			done += n
			if err := checkCanceled(opts); err != nil {
				return err
			}
		}
		newPos = extraEnd
		oldPos, ok = addInt64(oldPos, skip)
		if !ok {
			return fmt.Errorf("%w: BSDIFF source position overflow", ErrInvalidPatch)
		}
		return reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(recordIndex + 1), Total: total})
	})
	if err != nil {
		return 0, true, err
	}
	if newPos != targetSize {
		return 0, true, ErrInvalidPatch
	}
	return targetSize, true, nil
}

func applyVCDIFFAt(source io.ReaderAt, sourceSize int64, previous io.ReaderAt, output io.WriterAt, p *VCDIFFPatch, opts ApplyOptions) (int64, bool, error) {
	d := newDecoder(p.data)
	_ = d.seek(p.headerEnd)
	targetPosition := int64(0)
	decoders := new(vcdSecondaryDecoders)
	windowIndex := int64(0)
	for !d.eof() {
		w, err := decodeVCDWindow(d)
		if err != nil {
			return 0, true, err
		}
		if int64(w.targetLength) > int64(^uint64(0)>>1)-targetPosition {
			return 0, true, ErrInvalidPatch
		}
		if err := checkOutputSize64(uint64(targetPosition)+uint64(w.targetLength), uint64(sourceSize), opts); err != nil {
			return 0, true, err
		}
		data, instructions, addresses, next, err := p.windowSections(w, decoders, opts, uint64(sourceSize))
		if err != nil {
			return 0, true, err
		}
		readExternal := func(dst []byte, offset int64, target bool) error {
			input := source
			if target {
				input = previous
			}
			return readAtFull(input, dst, offset)
		}
		window, err := p.decodeTargetWindow(w, data, instructions, addresses, targetPosition, sourceSize, readExternal, opts)
		if err != nil {
			return 0, true, err
		}
		if err := writeAtFull(output, window, targetPosition); err != nil {
			return 0, true, err
		}
		targetPosition += int64(len(window))
		_ = d.seek(next)
		windowIndex++
		if err := reportProgress(opts, Progress{Phase: "apply-window", Format: p.Format(), Completed: windowIndex}); err != nil {
			return 0, true, err
		}
	}
	return targetPosition, true, nil
}
