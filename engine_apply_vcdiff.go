package rompatcher

import (
	"context"
	"fmt"
	"io"
)

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
