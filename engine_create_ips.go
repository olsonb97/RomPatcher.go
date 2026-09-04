package rompatcher

import (
	"encoding/json"
	"fmt"
	"io"
)

func createIPSReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, format Format, opts CreateOptions) error {
	return createIPSFamilyReaderAt(original, originalSize, modified, modifiedSize, w, format, opts)
}

func createIPS32ReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	return createIPSFamilyReaderAt(original, originalSize, modified, modifiedSize, w, FormatIPS32, opts)
}

func createIPSFamilyReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, format Format, opts CreateOptions) error {
	ips32 := format == FormatIPS32
	if ips32 {
		if uint64(modifiedSize) > uint64(^uint32(0)) {
			return fmt.Errorf("files are too big for IPS32 format")
		}
	} else if modifiedSize > ipsMaxSize {
		return fmt.Errorf("files are too big for %s format", format)
	}
	if format == FormatEBP && modifiedSize < originalSize {
		return fmt.Errorf("%w: EBP cannot represent a smaller output", ErrUnsupported)
	}
	if format == FormatIPS && modifiedSize == ipsMaxSize && modifiedSize < originalSize {
		return fmt.Errorf("%w: IPS cannot encode a 0x1000000-byte truncate size", ErrUnsupported)
	}

	headerMagic, footerMagic, reservedOffset := "PATCH", "EOF", int64(0x454f46)
	if ips32 {
		headerMagic, footerMagic, reservedOffset = "IPS32", "EEOF", 0x45454f46
	}
	if err := w.write([]byte(headerMagic)); err != nil {
		return err
	}
	appendOffset := func(dst []byte, offset int64) []byte {
		if ips32 {
			return appendU32BE(dst, uint32(offset))
		}
		return appendU24BE(dst, uint32(offset))
	}
	lastEnd := int64(0)
	visit := func(start int64, _ []byte, data []byte) error {
		if start == reservedOffset {
			var prefix [1]byte
			if err := readAtFull(modified, prefix[:], start-1); err != nil {
				return err
			}
			start--
			data = append(prefix[:], data...)
		}
		if len(data) > 0xffff {
			return ErrInvalidPatch
		}
		recordHeader := appendOffset(nil, start)
		if repeatedByteRun(data) {
			recordHeader = appendU16BE(recordHeader, 0)
			recordHeader = appendU16BE(recordHeader, uint16(len(data)))
			if err := w.write(append(recordHeader, data[0])); err != nil {
				return err
			}
		} else {
			recordHeader = appendU16BE(recordHeader, uint16(len(data)))
			if err := w.write(recordHeader); err != nil {
				return err
			}
			if err := w.write(data); err != nil {
				return err
			}
		}
		lastEnd = start + int64(len(data))
		return nil
	}
	if err := scanDifferenceRuns(w.ctx, original, originalSize, modified, modifiedSize, modifiedSize, 0xfffe, visit,
		func(done int64) error { return reportCreate(opts, format, done, modifiedSize) }); err != nil {
		return err
	}
	if modifiedSize > originalSize && lastEnd < modifiedSize {
		if err := visit(modifiedSize-1, nil, []byte{0}); err != nil {
			return err
		}
	}
	if err := w.write([]byte(footerMagic)); err != nil {
		return err
	}
	if modifiedSize < originalSize {
		return w.write(appendOffset(nil, modifiedSize))
	}
	if format != FormatEBP {
		return nil
	}
	metadata := map[string]string{"patcher": "EBPatcher"}
	if len(opts.Metadata) == 0 {
		metadata["Author"], metadata["Title"], metadata["Description"] = "Unknown", "Untitled", "No description"
	} else {
		for key, value := range opts.Metadata {
			metadata[key] = value
		}
	}
	if opts.Description != "" {
		if _, exists := metadata["Description"]; !exists {
			metadata["Description"] = opts.Description
		}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return w.write(encoded)
}
