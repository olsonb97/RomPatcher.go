package rompatcher

import (
	"fmt"
	"io"
)

func createPPFReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	if modifiedSize < originalSize {
		return fmt.Errorf("%w: PPF cannot represent a smaller output", ErrUnsupported)
	}
	header := append([]byte("PPF30"), 2)
	description := opts.Description
	if description == "" {
		description = "Patch description"
	}
	header = append(header, fixedString(description, 50)...)
	header = append(header, 0, 0, 0, 0)
	if err := w.write(header); err != nil {
		return err
	}
	lastEnd := int64(0)
	visit := func(start int64, _ []byte, data []byte) error {
		record := appendU32LE(nil, uint32(start))
		record = appendU32LE(record, uint32(uint64(start)>>32))
		record = append(record, byte(len(data)))
		if err := w.write(record); err != nil {
			return err
		}
		if err := w.write(data); err != nil {
			return err
		}
		lastEnd = start + int64(len(data))
		return nil
	}
	err := scanDifferenceRuns(w.ctx, original, originalSize, modified, modifiedSize, modifiedSize, 255, visit,
		func(done int64) error { return reportCreate(opts, FormatPPF, done, modifiedSize) })
	if err != nil {
		return err
	}
	if modifiedSize > originalSize && lastEnd < modifiedSize {
		record := appendU32LE(nil, uint32(modifiedSize-1))
		record = appendU32LE(record, uint32(uint64(modifiedSize-1)>>32))
		record = append(record, 1, 0)
		return w.write(record)
	}
	return nil
}
