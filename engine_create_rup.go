package rompatcher

import (
	"io"
	"path/filepath"
	"strings"
	"time"
)

func createRUPReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	sourceMD5, err := md5Create(w.ctx, original, originalSize)
	if err != nil {
		return err
	}
	targetMD5, err := md5Create(w.ctx, modified, modifiedSize)
	if err != nil {
		return err
	}
	header := append([]byte("NINJA2"), 0)
	header = append(header, fixedString("", 84)...)
	header = append(header, fixedString("", 11)...)
	header = append(header, fixedString("", 256)...)
	header = append(header, fixedString("", 48)...)
	header = append(header, fixedString("", 48)...)
	header = append(header, fixedString(time.Now().Format("20060102"), 8)...)
	header = append(header, fixedString("", 512)...)
	header = append(header, fixedString(strings.ReplaceAll(opts.Description, "\n", "\\n"), 1074)...)
	if len(header) != 0x800 {
		return ErrInvalidPatch
	}
	if err := w.write(header); err != nil {
		return err
	}
	fileHeader := []byte{1}
	fileName := ""
	if opts.SourceName != "" {
		fileName = filepath.Base(opts.SourceName)
	}
	fileHeader = append(fileHeader, appendRUPVLV(nil, uint64(len(fileName)))...)
	fileHeader = append(fileHeader, fileName...)
	fileHeader = append(fileHeader, 0)
	fileHeader = append(fileHeader, appendRUPVLV(nil, uint64(originalSize))...)
	fileHeader = append(fileHeader, appendRUPVLV(nil, uint64(modifiedSize))...)
	fileHeader = append(fileHeader, sourceMD5...)
	fileHeader = append(fileHeader, targetMD5...)
	if err := w.write(fileHeader); err != nil {
		return err
	}
	if originalSize != modifiedSize {
		mode, tail, start := byte('A'), modified, originalSize
		if originalSize > modifiedSize {
			mode, tail, start = 'M', original, modifiedSize
		}
		length := originalSize - modifiedSize
		if length < 0 {
			length = -length
		}
		prefix := append([]byte{mode}, appendRUPVLV(nil, uint64(length))...)
		if err := w.write(prefix); err != nil {
			return err
		}
		buf := make([]byte, fileChunkSize)
		for done := int64(0); done < length; {
			n := int64(len(buf))
			if length-done < n {
				n = length - done
			}
			if err := readAtFull(tail, buf[:n], start+done); err != nil {
				return err
			}
			for i := range buf[:n] {
				buf[i] ^= 0xff
			}
			if err := w.write(buf[:n]); err != nil {
				return err
			}
			done += n
		}
	}
	scanSize := originalSize
	if modifiedSize < scanSize {
		scanSize = modifiedSize
	}
	visit := func(start int64, old, data []byte) error {
		record := []byte{2}
		record = append(record, appendRUPVLV(nil, uint64(start))...)
		record = append(record, appendRUPVLV(nil, uint64(len(data)))...)
		if err := w.write(record); err != nil {
			return err
		}
		for i := range data {
			data[i] ^= old[i]
		}
		return w.write(data)
	}
	err = scanDifferenceRuns(w.ctx, original, originalSize, modified, modifiedSize, scanSize, createRecordBuffer, visit,
		func(done int64) error { return reportCreate(opts, FormatRUP, done, scanSize) })
	if err != nil {
		return err
	}
	return w.write([]byte{0})
}
