package rompatcher

import (
	"bytes"
	"compress/bzip2"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
)

func detectFormatReaderAt(patch io.ReaderAt, patchSize int64) (Format, error) {
	if patchSize < 3 {
		return "", ErrUnknownFormat
	}
	length := patchSize
	if length > 8 {
		length = 8
	}
	var storage [8]byte
	magic := storage[:int(length)]
	if err := readAtFull(patch, magic, 0); err != nil {
		return "", err
	}
	switch {
	case bytes.HasPrefix(magic, []byte("PATCH")):
		return FormatIPS, nil
	case bytes.HasPrefix(magic, []byte("IPS32")):
		return FormatIPS32, nil
	case bytes.HasPrefix(magic, []byte("UPS1")):
		return FormatUPS, nil
	case bytes.HasPrefix(magic, []byte("BPS1")):
		return FormatBPS, nil
	case bytes.HasPrefix(magic, []byte("APS10")):
		return FormatAPSN64, nil
	case bytes.HasPrefix(magic, []byte("APS1")):
		return FormatAPSGBA, nil
	case bytes.HasPrefix(magic, []byte("NINJA2")):
		return FormatRUP, nil
	case bytes.HasPrefix(magic, []byte("PPF")):
		return FormatPPF, nil
	case bytes.HasPrefix(magic, []byte("BSDIFF40")):
		return FormatBDF, nil
	case bytes.HasPrefix(magic, []byte("PMSR")):
		return FormatPMSR, nil
	case len(magic) >= 3 && magic[0] == 0xd6 && magic[1] == 0xc3 && magic[2] == 0xc4:
		return FormatVCDIFF, nil
	default:
		return "", ErrUnknownFormat
	}
}

func formatReaderAt(ctx context.Context, patch io.ReaderAt, patchSize int64) (Format, error) {
	format, err := detectFormatReaderAt(patch, patchSize)
	if err != nil || format != FormatIPS {
		return format, err
	}
	info, err := scanIPSStream(ctx, patch, patchSize, 0, false)
	return info.format, err
}

func applyPatchReaderAt(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	format, err := detectFormatReaderAt(patch, patchSize)
	if err != nil {
		return 0, err
	}
	readOutput, outputReadable := output.(io.ReaderAt)
	switch format {
	case FormatIPS:
		return applyIPSStream(ctx, source, sourceSize, patch, patchSize, output, false, opts)
	case FormatIPS32:
		return applyIPSStream(ctx, source, sourceSize, patch, patchSize, output, true, opts)
	case FormatUPS:
		if opts.Validate && !outputReadable {
			return 0, outputReaderAtError(FormatUPS)
		}
		return applyUPSStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	case FormatBPS:
		if !outputReadable {
			return 0, outputReaderAtError(FormatBPS)
		}
		return applyBPSStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	case FormatAPSN64:
		return applyAPSN64Stream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatAPSGBA:
		return applyAPSGBAStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatRUP:
		if opts.Validate && !outputReadable {
			return 0, outputReaderAtError(FormatRUP)
		}
		return applyRUPStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	case FormatPPF:
		return applyPPFStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatBDF:
		return applyBDFStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatPMSR:
		return applyPMSRStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatVCDIFF:
		if !outputReadable {
			return 0, outputReaderAtError(FormatVCDIFF)
		}
		return applyVCDIFFStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	default:
		return 0, ErrUnknownFormat
	}
}

func outputReaderAtError(format Format) error {
	return fmt.Errorf("%w: %s output must implement io.ReaderAt", ErrUnsupported, format)
}

func writePatchRange(ctx context.Context, patch io.ReaderAt, patchOffset int64, output io.WriterAt, outputOffset, length int64, buf []byte) error {
	for done := int64(0); done < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int64(len(buf))
		if length-done < n {
			n = length - done
		}
		if err := readAtFull(patch, buf[:n], patchOffset+done); err != nil {
			return err
		}
		if err := writeAtFull(output, buf[:n], outputOffset+done); err != nil {
			return err
		}
		done += n
	}
	return nil
}

func fillValueAt(ctx context.Context, output io.WriterAt, offset, length int64, value byte, buf []byte) error {
	if len(buf) == 0 {
		return ErrInvalidPatch
	}
	fillBytes(buf, value)
	for done := int64(0); done < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int64(len(buf))
		if length-done < n {
			n = length - done
		}
		if err := writeAtFull(output, buf[:n], offset+done); err != nil {
			return err
		}
		done += n
	}
	return nil
}

type ipsStreamInfo struct {
	format     Format
	targetSize int64
	records    int64
}

func scanIPSStream(ctx context.Context, patch io.ReaderAt, patchSize, sourceSize int64, ips32 bool) (ipsStreamInfo, error) {
	info := ipsStreamInfo{format: FormatIPS, targetSize: sourceSize}
	headerSize := int64(5)
	terminator := uint32(0x454f46)
	if ips32 {
		info.format = FormatIPS32
		terminator = 0x45454f46
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	if err := d.seek(headerSize); err != nil {
		return info, err
	}
	for !d.eof() {
		var offset uint32
		var err error
		if ips32 {
			offset, err = d.u32be()
		} else {
			offset, err = d.u24be()
		}
		if err != nil {
			return info, fmt.Errorf("%w: IPS record offset", ErrInvalidPatch)
		}
		if offset == terminator {
			switch {
			case d.remaining() == 0:
				return info, nil
			case !ips32 && d.remaining() == 3:
				size, err := d.u24be()
				if err != nil {
					return info, err
				}
				info.targetSize = int64(size)
				return info, nil
			case ips32 && d.remaining() == 4:
				size, err := d.u32be()
				if err != nil {
					return info, err
				}
				info.targetSize = int64(size)
				return info, nil
			case !ips32:
				first, err := d.u8()
				if err != nil || first != '{' {
					return info, fmt.Errorf("%w: unsupported data after IPS EOF", ErrInvalidPatch)
				}
				reader := io.MultiReader(bytes.NewReader([]byte{'{'}), sectionReader(patch, d.off, d.remaining()))
				decoder := json.NewDecoder(reader)
				var metadata map[string]string
				if err := decoder.Decode(&metadata); err != nil || metadata == nil {
					return info, fmt.Errorf("%w: EBP metadata", ErrInvalidPatch)
				}
				if err := decoder.Decode(&struct{}{}); err != io.EOF {
					return info, fmt.Errorf("%w: EBP metadata", ErrInvalidPatch)
				}
				info.format = FormatEBP
				return info, nil
			default:
				return info, fmt.Errorf("%w: data after IPS32 EEOF", ErrInvalidPatch)
			}
		}
		length, err := d.u16be()
		if err != nil {
			return info, err
		}
		var recordLength int64
		if length == 0 {
			rle, err := d.u16be()
			if err != nil || rle == 0 {
				return info, fmt.Errorf("%w: invalid IPS RLE record", ErrInvalidPatch)
			}
			if _, err := d.u8(); err != nil {
				return info, err
			}
			recordLength = int64(rle)
		} else {
			recordLength = int64(length)
			if err := d.skip(recordLength); err != nil {
				return info, err
			}
		}
		end := int64(offset) + recordLength
		if end < int64(offset) {
			return info, ErrInvalidPatch
		}
		if end > info.targetSize {
			info.targetSize = end
		}
		info.records++
	}
	return info, fmt.Errorf("%w: IPS terminator missing", ErrInvalidPatch)
}

func applyIPSStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, ips32 bool, opts ApplyOptions) (int64, error) {
	info, err := scanIPSStream(ctx, patch, patchSize, sourceSize, ips32)
	if err != nil {
		return 0, err
	}
	if err := checkOutputSize64(uint64(info.targetSize), uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	if err := initializeOutput(source, sourceSize, info.targetSize, output, opts, info.format); err != nil {
		return 0, err
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(5)
	scratch := make([]byte, 64<<10)
	for index := int64(0); index < info.records; index++ {
		var offset uint32
		if ips32 {
			offset, err = d.u32be()
		} else {
			offset, err = d.u24be()
		}
		if err != nil {
			return 0, err
		}
		length, err := d.u16be()
		if err != nil {
			return 0, err
		}
		if length == 0 {
			rle, err := d.u16be()
			if err != nil {
				return 0, err
			}
			value, err := d.u8()
			if err != nil {
				return 0, err
			}
			if int64(offset) > info.targetSize-int64(rle) {
				return 0, ErrInvalidPatch
			}
			if err := fillValueAt(ctx, output, int64(offset), int64(rle), value, scratch); err != nil {
				return 0, err
			}
		} else {
			if int64(offset) > info.targetSize-int64(length) {
				return 0, ErrInvalidPatch
			}
			if err := writePatchRange(ctx, patch, d.off, output, int64(offset), int64(length), scratch); err != nil {
				return 0, err
			}
			_ = d.skip(int64(length))
		}
		if err := reportProgress(opts, Progress{Phase: "apply", Format: info.format, Completed: index + 1, Total: info.records}); err != nil {
			return 0, err
		}
	}
	return info.targetSize, nil
}

func crc32PatchRange(ctx context.Context, r io.ReaderAt, offset, size int64) (uint32, error) {
	h := crc32.NewIEEE()
	buf := make([]byte, checksumChunkSize)
	for done := int64(0); done < size; {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n := int64(len(buf))
		if size-done < n {
			n = size - done
		}
		if err := readAtFull(r, buf[:n], offset+done); err != nil {
			return 0, err
		}
		_, _ = h.Write(buf[:n])
		done += n
	}
	return h.Sum32(), nil
}

func readPatchFooter(patch io.ReaderAt, patchSize int64) ([3]uint32, error) {
	var result [3]uint32
	var footer [12]byte
	if patchSize < int64(len(footer)) {
		return result, ErrUnexpectedEnd
	}
	if err := readAtFull(patch, footer[:], patchSize-int64(len(footer))); err != nil {
		return result, err
	}
	for i := range result {
		result[i] = binary.LittleEndian.Uint32(footer[i*4 : i*4+4])
	}
	return result, nil
}

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
		return 0, ErrPatchMismatch
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
		return 0, ErrSourceMismatch
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
			return 0, ErrTargetMismatch
		}
	}
	return int64(targetSize), nil
}

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
		return 0, ErrPatchMismatch
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
			return 0, ErrSourceMismatch
		}
		got, err := crc32ReaderAt(opts, source, sourceSize, FormatBPS, "validate-source")
		if err != nil {
			return 0, err
		}
		if got != footer[0] {
			return 0, ErrSourceMismatch
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
			return 0, ErrTargetMismatch
		}
	}
	return int64(targetSize), nil
}

func applyAPSN64Stream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(5)
	headerType, err := d.u8()
	if err != nil {
		return 0, err
	}
	if _, err := d.u8(); err != nil {
		return 0, err
	}
	if err := d.skip(50); err != nil {
		return 0, err
	}
	var cartID []byte
	var cartCRC []byte
	if headerType == 1 {
		if err := d.skip(1); err != nil {
			return 0, err
		}
		cartID, err = d.bytes(3)
		if err != nil {
			return 0, err
		}
		cartCRC, err = d.bytes(8)
		if err != nil {
			return 0, err
		}
		if err := d.skip(5); err != nil {
			return 0, err
		}
	}
	target, err := d.u32le()
	if err != nil {
		return 0, err
	}
	targetSize := int64(target)
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	if opts.Validate && headerType == 1 {
		if sourceSize < 0x3f {
			return 0, ErrSourceMismatch
		}
		header := make([]byte, 0x3f)
		if err := readAtFull(source, header, 0); err != nil {
			return 0, err
		}
		if !bytes.Equal(bytes.TrimRight(cartID, "\x00"), bytes.TrimRight(header[0x3c:0x3f], "\x00")) || !bytes.Equal(cartCRC, header[0x10:0x18]) {
			return 0, ErrSourceMismatch
		}
	}
	if err := initializeOutput(source, sourceSize, targetSize, output, opts, FormatAPSN64); err != nil {
		return 0, err
	}
	records := int64(0)
	scratch := make([]byte, 255)
	for !d.eof() {
		offset, err := d.u32le()
		if err != nil {
			return 0, err
		}
		length, err := d.u8()
		if err != nil {
			return 0, err
		}
		if length == 0 {
			value, err := d.u8()
			if err != nil {
				return 0, err
			}
			rle, err := d.u8()
			if err != nil || rle == 0 || int64(offset) > targetSize-int64(rle) {
				return 0, ErrInvalidPatch
			}
			if err := fillValueAt(ctx, output, int64(offset), int64(rle), value, scratch); err != nil {
				return 0, err
			}
		} else {
			if int64(offset) > targetSize-int64(length) || int64(length) > d.remaining() {
				return 0, ErrInvalidPatch
			}
			if err := writePatchRange(ctx, patch, d.off, output, int64(offset), int64(length), scratch); err != nil {
				return 0, err
			}
			_ = d.skip(int64(length))
		}
		records++
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatAPSN64, Completed: records}); err != nil {
			return 0, err
		}
	}
	return targetSize, nil
}

func applyAPSGBAStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	const recordSize = int64(4 + 2 + 2 + apsGBABlockSize)
	if patchSize < 12 || (patchSize-12)%recordSize != 0 {
		return 0, fmt.Errorf("%w: APS GBA length", ErrInvalidPatch)
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(4)
	declaredSource, err := d.u32le()
	if err != nil {
		return 0, err
	}
	target, err := d.u32le()
	if err != nil {
		return 0, err
	}
	targetSize := int64(target)
	if opts.Validate && sourceSize != int64(declaredSource) {
		return 0, ErrSourceMismatch
	}
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	if err := initializeOutput(source, sourceSize, targetSize, output, opts, FormatAPSGBA); err != nil {
		return 0, err
	}
	records := (patchSize - 12) / recordSize
	input := make([]byte, apsGBABlockSize)
	xor := make([]byte, apsGBABlockSize)
	for index := int64(0); index < records; index++ {
		offset, err := d.u32le()
		if err != nil {
			return 0, err
		}
		sourceCRC, err := d.u16le()
		if err != nil {
			return 0, err
		}
		targetCRC, err := d.u16le()
		if err != nil {
			return 0, err
		}
		start := int64(offset)
		if start > sourceSize-apsGBABlockSize || start > targetSize-apsGBABlockSize {
			return 0, ErrInvalidPatch
		}
		if err := readAtFull(source, input, start); err != nil {
			return 0, err
		}
		if err := d.read(xor); err != nil {
			return 0, err
		}
		if opts.Validate && CRC16(input) != sourceCRC {
			return 0, ErrSourceMismatch
		}
		for i := range input {
			input[i] ^= xor[i]
		}
		if opts.Validate && CRC16(input) != targetCRC {
			return 0, ErrTargetMismatch
		}
		if err := writeAtFull(output, input, start); err != nil {
			return 0, err
		}
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatAPSGBA, Completed: index + 1, Total: records}); err != nil {
			return 0, err
		}
	}
	return targetSize, nil
}

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
			return 0, ErrSourceMismatch
		}
		got, err := crc32ReaderAt(opts, source, sourceSize, FormatPMSR, "validate-source")
		if err != nil {
			return 0, err
		}
		if got != 0xa7f5cd7e {
			return 0, ErrSourceMismatch
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

func applyBDFStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	if patchSize < 32 {
		return 0, fmt.Errorf("%w: BSDIFF header", ErrInvalidPatch)
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(8)
	controlRaw, err := d.u64le()
	if err != nil {
		return 0, err
	}
	diffRaw, err := d.u64le()
	if err != nil {
		return 0, err
	}
	targetRaw, err := d.u64le()
	if err != nil {
		return 0, err
	}
	controlSize, diffSize, targetSize := bsdiffInt(controlRaw), bsdiffInt(diffRaw), bsdiffInt(targetRaw)
	if controlSize < 0 || diffSize < 0 || targetSize < 0 || controlSize > patchSize-32 || diffSize > patchSize-32-controlSize {
		return 0, fmt.Errorf("%w: BSDIFF sizes", ErrInvalidPatch)
	}
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	control := bzip2.NewReader(sectionReader(patch, 32, controlSize))
	diff := bzip2.NewReader(sectionReader(patch, 32+controlSize, diffSize))
	extraSize := patchSize - 32 - controlSize - diffSize
	extra := bzip2.NewReader(sectionReader(patch, 32+controlSize+diffSize, extraSize))
	oldPosition, newPosition, records := int64(0), int64(0), int64(0)
	diffBuf, oldBuf := make([]byte, fileChunkSize), make([]byte, fileChunkSize)
	for newPosition < targetSize {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		diffLength, err := readBSDiffInt(control)
		if err != nil {
			return 0, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		extraLength, err := readBSDiffInt(control)
		if err != nil {
			return 0, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		skip, err := readBSDiffInt(control)
		if err != nil {
			return 0, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		if diffLength < 0 || extraLength < 0 || diffLength == 0 && extraLength == 0 || diffLength > targetSize-newPosition || extraLength > targetSize-newPosition-diffLength {
			return 0, fmt.Errorf("%w: BSDIFF control values", ErrInvalidPatch)
		}
		for done := int64(0); done < diffLength; {
			n := int64(len(diffBuf))
			if diffLength-done < n {
				n = diffLength - done
			}
			buf := diffBuf[:n]
			if _, err := io.ReadFull(diff, buf); err != nil {
				return 0, fmt.Errorf("%w: BSDIFF diff: %v", ErrInvalidPatch, err)
			}
			diffPosition, ok := addInt64(oldPosition, done)
			if !ok {
				return 0, ErrInvalidPatch
			}
			within, sourceOffset, count := sourceSpan(diffPosition, n, sourceSize)
			if count > 0 {
				old := oldBuf[:count]
				if err := readAtFull(source, old, sourceOffset); err != nil {
					return 0, err
				}
				for i, value := range old {
					buf[int(within)+i] += value
				}
			}
			if err := writeAtFull(output, buf, newPosition+done); err != nil {
				return 0, err
			}
			done += n
		}
		newPosition += diffLength
		var ok bool
		oldPosition, ok = addInt64(oldPosition, diffLength)
		if !ok {
			return 0, ErrInvalidPatch
		}
		for done := int64(0); done < extraLength; {
			n := int64(len(diffBuf))
			if extraLength-done < n {
				n = extraLength - done
			}
			buf := diffBuf[:n]
			if _, err := io.ReadFull(extra, buf); err != nil {
				return 0, fmt.Errorf("%w: BSDIFF extra: %v", ErrInvalidPatch, err)
			}
			if err := writeAtFull(output, buf, newPosition+done); err != nil {
				return 0, err
			}
			done += n
		}
		newPosition += extraLength
		oldPosition, ok = addInt64(oldPosition, skip)
		if !ok {
			return 0, ErrInvalidPatch
		}
		records++
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatBDF, Completed: records}); err != nil {
			return 0, err
		}
	}
	if err := requireCompressedEOF(control, "control"); err != nil {
		return 0, err
	}
	if err := requireCompressedEOF(diff, "diff"); err != nil {
		return 0, err
	}
	if err := requireCompressedEOF(extra, "extra"); err != nil {
		return 0, err
	}
	return targetSize, nil
}

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
		return selected, ErrSourceMismatch
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
			return 0, ErrTargetMismatch
		}
	}
	return int64(targetSize), nil
}

type ppfStreamInfo struct {
	version                 int
	imageType               byte
	blockCheck              []byte
	inputSize               uint32
	undo, undoing           bool
	recordStart, targetSize int64
	records                 int64
}

const (
	ppfFileIDStart = "@BEGIN_FILE_ID.DIZ"
	ppfFileIDEnd   = "@END_FILE_ID.DIZ"
)

func ppfAtFileID(patch io.ReaderAt, offset, remaining int64) (bool, error) {
	if remaining < int64(len(ppfFileIDStart)) {
		return false, nil
	}
	var buf [len(ppfFileIDStart)]byte
	if err := readAtFull(patch, buf[:], offset); err != nil {
		return false, err
	}
	return string(buf[:]) == ppfFileIDStart, nil
}

func skipPPFFileID(d *readerDecoder, version int) error {
	if err := d.skip(int64(len(ppfFileIDStart))); err != nil {
		return err
	}
	matched, length := 0, uint64(0)
	for !d.eof() {
		b, err := d.u8()
		if err != nil {
			return err
		}
		length++
		if b == ppfFileIDEnd[matched] {
			matched++
			if matched == len(ppfFileIDEnd) {
				length -= uint64(len(ppfFileIDEnd))
				var declared uint64
				if version == 3 {
					value, err := d.u16le()
					if err != nil {
						return err
					}
					declared = uint64(value)
				} else {
					value, err := d.u32le()
					if err != nil {
						return err
					}
					declared = uint64(value)
				}
				if declared != length || !d.eof() {
					return fmt.Errorf("%w: PPF FILE_ID.DIZ footer", ErrInvalidPatch)
				}
				return nil
			}
		} else if b == ppfFileIDEnd[0] {
			matched = 1
		} else {
			matched = 0
		}
	}
	return fmt.Errorf("%w: PPF FILE_ID.DIZ", ErrInvalidPatch)
}

func scanPPFStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64) (ppfStreamInfo, error) {
	info := ppfStreamInfo{targetSize: sourceSize}
	if patchSize < 56 {
		return info, fmt.Errorf("%w: PPF header", ErrInvalidPatch)
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(3)
	versionText, err := d.bytes(2)
	if err != nil {
		return info, err
	}
	versionByte, err := d.u8()
	if err != nil || versionText[1] != '0' || versionText[0] < '1' || versionText[0] > '3' || int(versionText[0]-'0') != int(versionByte)+1 {
		return info, fmt.Errorf("%w: PPF version", ErrInvalidPatch)
	}
	info.version = int(versionByte) + 1
	if err := d.skip(50); err != nil {
		return info, err
	}
	if info.version == 3 {
		info.imageType, err = d.u8()
		if err != nil {
			return info, err
		}
		block, err := d.u8()
		if err != nil || info.imageType > 1 || block > 1 {
			return info, ErrInvalidPatch
		}
		undo, err := d.u8()
		if err != nil || undo > 1 {
			return info, ErrInvalidPatch
		}
		info.undo = undo != 0
		reserved, err := d.u8()
		if err != nil || reserved != 0 {
			return info, ErrInvalidPatch
		}
		if block != 0 {
			info.blockCheck, err = d.bytes(1024)
			if err != nil {
				return info, err
			}
		}
	} else if info.version == 2 {
		info.inputSize, err = d.u32be()
		if err != nil {
			return info, err
		}
		info.blockCheck, err = d.bytes(1024)
		if err != nil {
			return info, err
		}
	}
	info.recordStart = d.off
	first := true
	var dataBuffer, compareBuffer [255]byte
	for !d.eof() {
		fileID, err := ppfAtFileID(patch, d.off, d.remaining())
		if err != nil {
			return info, err
		}
		if fileID {
			if err := skipPPFFileID(d, info.version); err != nil {
				return info, err
			}
			break
		}
		need := int64(5)
		if info.version == 3 {
			need = 9
		}
		if d.remaining() < need {
			return info, ErrUnexpectedEnd
		}
		low, _ := d.u32le()
		offset := uint64(low)
		if info.version == 3 {
			high, _ := d.u32le()
			offset |= uint64(high) << 32
		}
		length, err := d.u8()
		if err != nil || length == 0 || int64(length) > d.remaining() {
			return info, ErrInvalidPatch
		}
		dataOffset := d.off
		_ = d.skip(int64(length))
		if first && info.undo {
			data := dataBuffer[:int(length)]
			if err := readAtFull(patch, data, dataOffset); err != nil {
				return info, err
			}
			match, err := ppfBytesEqualAt(source, sourceSize, offset, data, compareBuffer[:])
			if err != nil {
				return info, err
			}
			info.undoing = match
		}
		if info.undo {
			if int64(length) > d.remaining() {
				return info, ErrUnexpectedEnd
			}
			_ = d.skip(int64(length))
		}
		if offset > uint64(^uint64(0)>>1) || int64(offset) > int64(^uint64(0)>>1)-int64(length) {
			return info, ErrInvalidPatch
		}
		end := int64(offset) + int64(length)
		if end > info.targetSize {
			info.targetSize = end
		}
		info.records++
		first = false
	}
	return info, nil
}

func applyPPFStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	info, err := scanPPFStream(ctx, source, sourceSize, patch, patchSize)
	if err != nil {
		return 0, err
	}
	if opts.Validate && !info.undoing {
		if info.inputSize != 0 && sourceSize != int64(info.inputSize) {
			return 0, ErrSourceMismatch
		}
		if len(info.blockCheck) != 0 {
			var validationBuffer [1024]byte
			offset := int64(0x9320)
			if info.version == 3 && info.imageType == 1 {
				offset = 0x80a0
			}
			match, err := ppfBytesEqualAt(source, sourceSize, uint64(offset), info.blockCheck, validationBuffer[:])
			if err != nil {
				return 0, err
			}
			if !match {
				return 0, ErrSourceMismatch
			}
		}
	}
	if err := checkOutputSize64(uint64(info.targetSize), uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	if err := initializeOutput(source, sourceSize, info.targetSize, output, opts, FormatPPF); err != nil {
		return 0, err
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(info.recordStart)
	var dataBuffer, undoBuffer [255]byte
	var validationBuffer [255]byte
	for index := int64(0); index < info.records; index++ {
		low, err := d.u32le()
		if err != nil {
			return 0, err
		}
		offset := uint64(low)
		if info.version == 3 {
			high, err := d.u32le()
			if err != nil {
				return 0, err
			}
			offset |= uint64(high) << 32
		}
		length, err := d.u8()
		if err != nil {
			return 0, err
		}
		data := dataBuffer[:int(length)]
		if err := d.read(data); err != nil {
			return 0, err
		}
		var undo []byte
		if info.undo {
			undo = undoBuffer[:int(length)]
			if err := d.read(undo); err != nil {
				return 0, err
			}
		}
		toWrite, expected := data, undo
		if info.undoing {
			toWrite, expected = undo, data
		}
		if opts.Validate && info.undo {
			match, err := ppfBytesEqualAt(source, sourceSize, offset, expected, validationBuffer[:])
			if err != nil {
				return 0, err
			}
			if !match {
				return 0, ErrSourceMismatch
			}
		}
		if err := writeAtFull(output, toWrite, int64(offset)); err != nil {
			return 0, err
		}
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatPPF, Completed: index + 1, Total: info.records}); err != nil {
			return 0, err
		}
	}
	return info.targetSize, nil
}

type vcdStreamHeader struct {
	table       [256][2]vcdInstruction
	nearSize    int
	sameSize    int
	secondaryID byte
	headerEnd   int64
}

func parseVCDStreamHeader(ctx context.Context, patch io.ReaderAt, patchSize int64, opts ApplyOptions, sourceSize uint64) (vcdStreamHeader, error) {
	header := vcdStreamHeader{table: vcdTable, nearSize: 4, sameSize: 3}
	if patchSize < 5 {
		return header, fmt.Errorf("%w: VCDIFF header", ErrInvalidPatch)
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	magic, err := d.bytes(4)
	if err != nil || magic[0] != 0xd6 || magic[1] != 0xc3 || magic[2] != 0xc4 || magic[3] != 0 {
		return header, fmt.Errorf("%w: VCDIFF header/version", ErrInvalidPatch)
	}
	indicator, err := d.u8()
	if err != nil {
		return header, err
	}
	if indicator&vcdDecompress != 0 {
		header.secondaryID, err = d.u8()
		if err != nil {
			return header, err
		}
	}
	if indicator&vcdCodeTable != 0 {
		length, err := readBE7Reader(d)
		if err != nil || length <= 2 || length-2 > uint64(d.remaining()) {
			return header, fmt.Errorf("%w: VCDIFF code table length", ErrInvalidPatch)
		}
		near, err := d.u8()
		if err != nil {
			return header, err
		}
		same, err := d.u8()
		if err != nil {
			return header, err
		}
		encodedSize := length - 2
		if encodedSize > outputSizeLimit(sourceSize, opts) {
			return header, ErrOutputTooLarge
		}
		encoded, err := d.bytes(int64(encodedSize))
		if err != nil {
			return header, err
		}
		header.table, err = decodeVCDCodeTable(encoded, 1)
		if err != nil {
			return header, err
		}
		header.nearSize, header.sameSize = int(near), int(same)
		if err := validateVCDTable(header.table, header.nearSize, header.sameSize); err != nil {
			return header, err
		}
	}
	if indicator&vcdAppHeader != 0 {
		length, err := readBE7Reader(d)
		if err != nil || length > uint64(d.remaining()) {
			return header, ErrInvalidPatch
		}
		_ = d.skip(int64(length))
	}
	if indicator&^(byte(vcdDecompress|vcdCodeTable|vcdAppHeader)) != 0 {
		return header, fmt.Errorf("%w: VCDIFF header flags", ErrInvalidPatch)
	}
	header.headerEnd = d.off
	return header, nil
}

func decodeVCDWindowReader(d *readerDecoder) (vcdWindow, int64, error) {
	w := vcdWindow{}
	indicator, err := d.u8()
	if err != nil {
		return w, 0, err
	}
	w.indicator = indicator
	if indicator&^(byte(vcdSource|vcdTarget|vcdAdler32)) != 0 || indicator&vcdSource != 0 && indicator&vcdTarget != 0 {
		return w, 0, fmt.Errorf("%w: VCDIFF window flags", ErrInvalidPatch)
	}
	if indicator&(vcdSource|vcdTarget) != 0 {
		value, err := readBE7Reader(d)
		if err != nil {
			return w, 0, err
		}
		w.sourceLength, err = checkedInt(value)
		if err != nil {
			return w, 0, err
		}
		value, err = readBE7Reader(d)
		if err != nil {
			return w, 0, err
		}
		w.sourcePosition, err = checkedInt(value)
		if err != nil {
			return w, 0, err
		}
	}
	deltaLength, err := readBE7Reader(d)
	if err != nil {
		return w, 0, err
	}
	deltaStart := d.off
	value, err := readBE7Reader(d)
	if err != nil {
		return w, 0, err
	}
	w.targetLength, err = checkedInt(value)
	if err != nil {
		return w, 0, err
	}
	w.deltaIndicator, err = d.u8()
	if err != nil || w.deltaIndicator&^byte(0x07) != 0 {
		return w, 0, fmt.Errorf("%w: VCDIFF delta indicator", ErrInvalidPatch)
	}
	value, err = readBE7Reader(d)
	if err != nil {
		return w, 0, err
	}
	w.dataLength, err = checkedInt(value)
	if err != nil {
		return w, 0, err
	}
	value, err = readBE7Reader(d)
	if err != nil {
		return w, 0, err
	}
	w.instructionLength, err = checkedInt(value)
	if err != nil {
		return w, 0, err
	}
	value, err = readBE7Reader(d)
	if err != nil {
		return w, 0, err
	}
	w.addressLength, err = checkedInt(value)
	if err != nil {
		return w, 0, err
	}
	if indicator&vcdAdler32 != 0 {
		checksum, err := d.u32be()
		if err != nil {
			return w, 0, err
		}
		w.adler = &checksum
	}
	bodyStart := d.off
	total := int64(w.dataLength) + int64(w.instructionLength) + int64(w.addressLength)
	if total < 0 || total > d.remaining() {
		return w, 0, ErrUnexpectedEnd
	}
	bodyEnd := bodyStart + total
	if uint64(bodyEnd-deltaStart) != deltaLength {
		return w, 0, fmt.Errorf("%w: VCDIFF delta encoding length", ErrInvalidPatch)
	}
	return w, bodyEnd, nil
}

func vcdStreamSections(ctx context.Context, patch io.ReaderAt, bodyStart int64, w vcdWindow, decoders *vcdSecondaryDecoders, p *VCDIFFPatch, opts ApplyOptions, sourceSize uint64) ([]byte, []byte, []byte, error) {
	limit, used := outputSizeLimit(sourceSize, opts), uint64(0)
	rawTotal := uint64(w.dataLength) + uint64(w.instructionLength) + uint64(w.addressLength)
	if rawTotal > limit {
		return nil, nil, nil, ErrOutputTooLarge
	}
	read := func(offset int64, length int) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if uint64(length) > limit-used {
			return nil, ErrOutputTooLarge
		}
		data := make([]byte, length)
		if err := readAtFull(patch, data, offset); err != nil {
			return nil, err
		}
		return data, nil
	}
	data, err := read(bodyStart, w.dataLength)
	if err != nil {
		return nil, nil, nil, err
	}
	instructions, err := read(bodyStart+int64(w.dataLength), w.instructionLength)
	if err != nil {
		return nil, nil, nil, err
	}
	addresses, err := read(bodyStart+int64(w.dataLength)+int64(w.instructionLength), w.addressLength)
	if err != nil {
		return nil, nil, nil, err
	}
	if w.deltaIndicator == 0 {
		return data, instructions, addresses, nil
	}
	if p.secondaryID == 0 {
		return nil, nil, nil, fmt.Errorf("%w: VCDIFF compressed section without a secondary compressor", ErrInvalidPatch)
	}
	if p.secondaryID != vcdLZMASecondaryID {
		return nil, nil, nil, p.unsupportedSecondary(w.deltaIndicator)
	}
	account := func(length int) error {
		if uint64(length) > limit-used {
			return ErrOutputTooLarge
		}
		used += uint64(length)
		return nil
	}
	if w.deltaIndicator&0x01 != 0 {
		data, err = decoders.data.decode(data, opts, sourceSize, limit-used)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if err := account(len(data)); err != nil {
		return nil, nil, nil, err
	}
	if w.deltaIndicator&0x02 != 0 {
		instructions, err = decoders.instructions.decode(instructions, opts, sourceSize, limit-used)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if err := account(len(instructions)); err != nil {
		return nil, nil, nil, err
	}
	if w.deltaIndicator&0x04 != 0 {
		addresses, err = decoders.addresses.decode(addresses, opts, sourceSize, limit-used)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if err := account(len(addresses)); err != nil {
		return nil, nil, nil, err
	}
	return data, instructions, addresses, nil
}

func applyVCDIFFStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, readOutput io.ReaderAt, output io.WriterAt, opts ApplyOptions) (int64, error) {
	header, err := parseVCDStreamHeader(ctx, patch, patchSize, opts, uint64(sourceSize))
	if err != nil {
		return 0, err
	}
	p := &VCDIFFPatch{table: header.table, nearSize: header.nearSize, sameSize: header.sameSize, secondaryID: header.secondaryID}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(header.headerEnd)
	decoders := new(vcdSecondaryDecoders)
	targetPosition, windowIndex := int64(0), int64(0)
	for !d.eof() {
		w, bodyEnd, err := decodeVCDWindowReader(d)
		if err != nil {
			return 0, err
		}
		if w.deltaIndicator != 0 && header.secondaryID == 0 {
			return 0, fmt.Errorf("%w: VCDIFF compressed section without a secondary compressor", ErrInvalidPatch)
		}
		if int64(w.targetLength) > int64(^uint64(0)>>1)-targetPosition {
			return 0, ErrInvalidPatch
		}
		if err := checkOutputSize64(uint64(targetPosition)+uint64(w.targetLength), uint64(sourceSize), opts); err != nil {
			return 0, err
		}
		bodyStart := d.off
		data, instructions, addresses, err := vcdStreamSections(ctx, patch, bodyStart, w, decoders, p, opts, uint64(sourceSize))
		if err != nil {
			return 0, err
		}
		readExternal := func(dst []byte, offset int64, target bool) error {
			input := source
			if target {
				input = readOutput
			}
			return readAtFull(input, dst, offset)
		}
		window, err := p.decodeTargetWindow(w, data, instructions, addresses, targetPosition, sourceSize, readExternal, opts)
		if err != nil {
			return 0, err
		}
		if err := writeAtFull(output, window, targetPosition); err != nil {
			return 0, err
		}
		targetPosition += int64(len(window))
		_ = d.seek(bodyEnd)
		windowIndex++
		if err := reportProgress(opts, Progress{Phase: "apply-window", Format: FormatVCDIFF, Completed: windowIndex}); err != nil {
			return 0, err
		}
	}
	return targetPosition, nil
}
