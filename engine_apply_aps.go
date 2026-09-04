package rompatcher

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

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
			return 0, fmt.Errorf("%w: APS N64 validation requires at least 63 source bytes, got %d", ErrSourceMismatch, sourceSize)
		}
		header := make([]byte, 0x3f)
		if err := readAtFull(source, header, 0); err != nil {
			return 0, err
		}
		if !bytes.Equal(bytes.TrimRight(cartID, "\x00"), bytes.TrimRight(header[0x3c:0x3f], "\x00")) {
			return 0, fmt.Errorf("%w: APS N64 cartridge ID expected %x, got %x", ErrSourceMismatch, bytes.TrimRight(cartID, "\x00"), bytes.TrimRight(header[0x3c:0x3f], "\x00"))
		}
		if !bytes.Equal(cartCRC, header[0x10:0x18]) {
			return 0, fmt.Errorf("%w: APS N64 header CRC expected %x, got %x", ErrSourceMismatch, cartCRC, header[0x10:0x18])
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
		return 0, sourceSizeMismatch(FormatAPSGBA, sourceSize, opts, uint64(declaredSource))
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
		if opts.Validate {
			actualCRC := CRC16(input)
			if actualCRC != sourceCRC {
				return 0, fmt.Errorf("%w: APS GBA record %d at offset 0x%x CRC16 expected %04x, got %04x", ErrSourceMismatch, index+1, offset, sourceCRC, actualCRC)
			}
		}
		for i := range input {
			input[i] ^= xor[i]
		}
		if opts.Validate {
			actualCRC := CRC16(input)
			if actualCRC != targetCRC {
				return 0, fmt.Errorf("%w: APS GBA record %d at offset 0x%x CRC16 expected %04x, got %04x", ErrTargetMismatch, index+1, offset, targetCRC, actualCRC)
			}
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
