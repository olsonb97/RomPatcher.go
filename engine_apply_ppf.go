package rompatcher

import (
	"context"
	"fmt"
	"io"
)

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
			return 0, sourceSizeMismatch(FormatPPF, sourceSize, opts, uint64(info.inputSize))
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
				return 0, fmt.Errorf("%w: PPF block check failed at offset 0x%x", ErrSourceMismatch, offset)
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
				return 0, fmt.Errorf("%w: PPF undo record %d does not match source at offset 0x%x", ErrSourceMismatch, index+1, offset)
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
