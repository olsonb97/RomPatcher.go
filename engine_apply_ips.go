package rompatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

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
