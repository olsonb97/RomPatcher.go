package rompatcher

import (
	"fmt"
	"io"
)

func createAPSReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	if uint64(modifiedSize) > uint64(^uint32(0)) {
		return fmt.Errorf("%w: APS output exceeds 32-bit size", ErrUnsupported)
	}
	header := append([]byte("APS10"), 0, 0)
	description := opts.Description
	if description == "" {
		description = "no description"
	}
	header = append(header, fixedString(description, 50)...)
	romHeader := make([]byte, 0x40)
	if originalSize >= int64(len(romHeader)) {
		if err := readAtFull(original, romHeader, 0); err != nil {
			return err
		}
		z64 := romHeader[0] == 0x80 && romHeader[1] == 0x37 && romHeader[2] == 0x12 && romHeader[3] == 0x40
		v64 := romHeader[0] == 0x37 && romHeader[1] == 0x80 && romHeader[2] == 0x40 && romHeader[3] == 0x12
		if z64 || v64 {
			header[5] = 1
			header = append(header, byte(1))
			if v64 {
				header[len(header)-1] = 0
			}
			header = append(header, romHeader[0x3c:0x3f]...)
			header = append(header, romHeader[0x10:0x18]...)
			header = append(header, make([]byte, 5)...)
		}
	}
	header = appendU32LE(header, uint32(modifiedSize))
	if err := w.write(header); err != nil {
		return err
	}
	visit := func(start int64, _ []byte, data []byte) error {
		record := appendU32LE(nil, uint32(start))
		if repeatedByteRun(data) {
			return w.write(append(record, 0, data[0], byte(len(data))))
		}
		record = append(record, byte(len(data)))
		if err := w.write(record); err != nil {
			return err
		}
		return w.write(data)
	}
	return scanDifferenceRuns(w.ctx, original, originalSize, modified, modifiedSize, modifiedSize, 255, visit,
		func(done int64) error { return reportCreate(opts, FormatAPSN64, done, modifiedSize) })
}
