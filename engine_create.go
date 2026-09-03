package rompatcher

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const createRecordBuffer = 1 << 20

type patchStreamWriter struct {
	ctx   context.Context
	w     io.Writer
	hash  hash.Hash32
	size  int64
	limit uint64
}

func newPatchStreamWriter(ctx context.Context, w io.Writer, originalSize, modifiedSize int64, opts CreateOptions) *patchStreamWriter {
	return &patchStreamWriter{ctx: ctx, w: w, hash: crc32.NewIEEE(), limit: patchSizeLimit(originalSize, modifiedSize, opts)}
}

func patchSizeLimit(originalSize, modifiedSize int64, opts CreateOptions) uint64 {
	limit := opts.MaxPatchSize
	if limit == 0 {
		limit = 64 << 20
		inputSize := originalSize
		if modifiedSize > inputSize {
			inputSize = modifiedSize
		}
		if inputSize >= 0 && uint64(inputSize) <= (^uint64(0)-limit)/2 {
			limit += uint64(inputSize) * 2
		} else {
			limit = ^uint64(0)
		}
	}
	return limit
}

func (w *patchStreamWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if w.size < 0 || uint64(w.size) > w.limit || uint64(len(data)) > w.limit-uint64(w.size) {
		return 0, fmt.Errorf("%w: patch exceeds %d bytes", ErrOutputTooLarge, w.limit)
	}
	n, err := w.w.Write(data)
	if n < 0 || n > len(data) {
		return 0, fmt.Errorf("invalid Writer count %d", n)
	}
	if n > 0 {
		_, _ = w.hash.Write(data[:n])
		w.size += int64(n)
	}
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func (w *patchStreamWriter) write(data []byte) error {
	_, err := w.Write(data)
	return err
}

func createContext(opts CreateOptions) context.Context {
	if opts.Context != nil {
		return opts.Context
	}
	return context.Background()
}

func reportCreate(opts CreateOptions, format Format, completed, total int64) error {
	return reportCreatePhase(opts, "create", format, completed, total)
}

func reportCreatePhase(opts CreateOptions, phase string, format Format, completed, total int64) error {
	ctx := createContext(opts)
	if err := ctx.Err(); err != nil {
		return err
	}
	if opts.Progress != nil {
		opts.Progress(Progress{Phase: phase, Format: format, Completed: completed, Total: total})
	}
	return ctx.Err()
}

func validateCreateInputs(originalSize, modifiedSize int64) error {
	if originalSize < 0 || modifiedSize < 0 {
		return fmt.Errorf("%w: negative input size", ErrInvalidPatch)
	}
	return nil
}

func readRange(r io.ReaderAt, size, offset int64, dst []byte) error {
	clear(dst)
	if offset >= size || len(dst) == 0 {
		return nil
	}
	n := int64(len(dst))
	if size-offset < n {
		n = size - offset
	}
	return readAtFull(r, dst[:n], offset)
}

func scanDifferenceRuns(ctx context.Context, original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize, scanSize int64, maxRun int, visit func(int64, []byte, []byte) error, progress func(int64) error) error {
	if maxRun <= 0 || maxRun > createRecordBuffer {
		maxRun = createRecordBuffer
	}
	oldChunk := make([]byte, fileChunkSize)
	newChunk := make([]byte, fileChunkSize)
	oldRun := make([]byte, 0, maxRun)
	newRun := make([]byte, 0, maxRun)
	runStart := int64(-1)
	flush := func() error {
		if runStart < 0 {
			return nil
		}
		err := visit(runStart, oldRun, newRun)
		oldRun, newRun, runStart = oldRun[:0], newRun[:0], -1
		return err
	}
	for offset := int64(0); offset < scanSize; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int64(fileChunkSize)
		if scanSize-offset < n {
			n = scanSize - offset
		}
		oldData, newData := oldChunk[:n], newChunk[:n]
		if err := readRange(original, originalSize, offset, oldData); err != nil {
			return err
		}
		if err := readRange(modified, modifiedSize, offset, newData); err != nil {
			return err
		}
		for i := range newData {
			position := offset + int64(i)
			if oldData[i] == newData[i] {
				if err := flush(); err != nil {
					return err
				}
				continue
			}
			if runStart < 0 {
				runStart = position
			}
			oldRun = append(oldRun, oldData[i])
			newRun = append(newRun, newData[i])
			if len(newRun) == maxRun {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		offset += n
		if progress != nil {
			if err := progress(offset); err != nil {
				return err
			}
		}
	}
	return flush()
}

func hashReaderAt(ctx context.Context, r io.ReaderAt, size int64, h hash.Hash) ([]byte, error) {
	buf := make([]byte, checksumChunkSize)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := int64(len(buf))
		if size-offset < n {
			n = size - offset
		}
		if err := readAtFull(r, buf[:n], offset); err != nil {
			return nil, err
		}
		_, _ = h.Write(buf[:n])
		offset += n
	}
	return h.Sum(nil), nil
}

func md5Create(ctx context.Context, r io.ReaderAt, size int64) ([]byte, error) {
	return hashReaderAt(ctx, r, size, md5.New())
}

// CreateReaderAt creates a patch without loading either input into memory. BPS
// creation uses memory only when CreateOptions.BPSDelta is explicitly enabled.
// The output is written sequentially and is not closed by this function.
func CreateReaderAt(ctx context.Context, original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, output io.Writer, format Format, options *CreateOptions) (int64, error) {
	if isNilInterface(original) || isNilInterface(modified) || isNilInterface(output) {
		return 0, fmt.Errorf("original, modified, and output must be non-nil")
	}
	if err := validateCreateInputs(originalSize, modifiedSize); err != nil {
		return 0, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opts := CreateOptions{Context: ctx}
	if options != nil {
		opts = *options
		opts.Context = ctx
	}
	format = normalizeFormat(format)
	w := newPatchStreamWriter(ctx, output, originalSize, modifiedSize, opts)
	if format == FormatBPS && opts.BPSDelta {
		originalData, err := readAllAt(ctx, original, originalSize, func(done int64) error {
			return reportCreatePhase(opts, "read-original", format, done, originalSize)
		})
		if err != nil {
			return 0, err
		}
		modifiedData, err := readAllAt(ctx, modified, modifiedSize, func(done int64) error {
			return reportCreatePhase(opts, "read-modified", format, done, modifiedSize)
		})
		if err != nil {
			return 0, err
		}
		patch, err := createBPSDeltaPatch(originalData, modifiedData, opts)
		if err != nil {
			return 0, err
		}
		encoded, err := patch.MarshalBinary()
		if err != nil {
			return 0, err
		}
		if err := w.write(encoded); err != nil {
			return 0, err
		}
		if err := reportCreatePhase(opts, "complete", format, w.size, w.size); err != nil {
			return 0, err
		}
		return w.size, nil
	}
	var err error
	switch format {
	case FormatIPS, FormatEBP:
		err = createIPSReaderAt(original, originalSize, modified, modifiedSize, w, format, opts)
	case FormatIPS32:
		err = createIPS32ReaderAt(original, originalSize, modified, modifiedSize, w, opts)
	case FormatUPS:
		err = createUPSReaderAt(original, originalSize, modified, modifiedSize, w, opts)
	case FormatAPSN64:
		err = createAPSReaderAt(original, originalSize, modified, modifiedSize, w, opts)
	case FormatBPS:
		err = createBPSReaderAt(original, originalSize, modified, modifiedSize, w, opts)
	case FormatRUP:
		err = createRUPReaderAt(original, originalSize, modified, modifiedSize, w, opts)
	case FormatPPF:
		err = createPPFReaderAt(original, originalSize, modified, modifiedSize, w, opts)
	default:
		err = fmt.Errorf("%w: cannot create %q patches", ErrUnsupported, format)
	}
	if err != nil {
		return 0, err
	}
	if err := reportCreatePhase(opts, "complete", format, w.size, w.size); err != nil {
		return 0, err
	}
	return w.size, nil
}

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

func repeatedByteRun(data []byte) bool {
	if len(data) <= 2 {
		return false
	}
	for _, value := range data[1:] {
		if value != data[0] {
			return false
		}
	}
	return true
}

func createUPSReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	header := append([]byte("UPS1"), appendBPSVLV(nil, uint64(originalSize))...)
	header = append(header, appendBPSVLV(nil, uint64(modifiedSize))...)
	if err := w.write(header); err != nil {
		return err
	}
	oldChunk, newChunk := make([]byte, fileChunkSize), make([]byte, fileChunkSize)
	sourceHash, targetHash := crc32.NewIEEE(), crc32.NewIEEE()
	scanSize := modifiedSize
	if originalSize > scanSize {
		scanSize = originalSize
	}
	previousSeek, runStart, runLength := int64(1), int64(-1), int64(0)
	for offset := int64(0); offset < scanSize; {
		n := int64(fileChunkSize)
		if scanSize-offset < n {
			n = scanSize - offset
		}
		oldData, newData := oldChunk[:n], newChunk[:n]
		if err := readRange(original, originalSize, offset, oldData); err != nil {
			return err
		}
		if err := readRange(modified, modifiedSize, offset, newData); err != nil {
			return err
		}
		if sourceLength := min64(n, max64(0, originalSize-offset)); sourceLength > 0 {
			_, _ = sourceHash.Write(oldData[:sourceLength])
		}
		if targetLength := min64(n, max64(0, modifiedSize-offset)); targetLength > 0 {
			_, _ = targetHash.Write(newData[:targetLength])
		}
		segmentStart := -1
		flushSegment := func(end int) error {
			if segmentStart < 0 {
				return nil
			}
			for i := segmentStart; i < end; i++ {
				oldData[i] ^= newData[i]
			}
			err := w.write(oldData[segmentStart:end])
			segmentStart = -1
			return err
		}
		for i := range newData {
			position := offset + int64(i)
			if oldData[i] != newData[i] {
				if runStart < 0 {
					runStart = position
					currentSeek := runStart + 1
					if currentSeek < previousSeek {
						return ErrInvalidPatch
					}
					if err := w.write(appendBPSVLV(nil, uint64(currentSeek-previousSeek))); err != nil {
						return err
					}
				}
				if segmentStart < 0 {
					segmentStart = i
				}
				runLength++
				continue
			}
			if err := flushSegment(i); err != nil {
				return err
			}
			if runStart >= 0 {
				if err := w.write([]byte{0}); err != nil {
					return err
				}
				previousSeek = runStart + 1 + runLength + 1
				runStart, runLength = -1, 0
			}
		}
		if err := flushSegment(len(newData)); err != nil {
			return err
		}
		offset += n
		if err := reportCreate(opts, FormatUPS, offset, scanSize); err != nil {
			return err
		}
	}
	if runStart >= 0 {
		if err := w.write([]byte{0}); err != nil {
			return err
		}
	}
	footer := appendU32LE(nil, sourceHash.Sum32())
	footer = appendU32LE(footer, targetHash.Sum32())
	if err := w.write(footer); err != nil {
		return err
	}
	return w.write(appendU32LE(nil, w.hash.Sum32()))
}

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

func createBPSReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	header := append([]byte("BPS1"), appendBPSVLV(nil, uint64(originalSize))...)
	header = append(header, appendBPSVLV(nil, uint64(modifiedSize))...)
	header = append(header, appendBPSVLV(nil, uint64(len(opts.Description)))...)
	header = append(header, opts.Description...)
	if err := w.write(header); err != nil {
		return err
	}
	oldChunk, newChunk := make([]byte, fileChunkSize), make([]byte, fileChunkSize)
	sourceHash, targetHash := crc32.NewIEEE(), crc32.NewIEEE()
	state := byte(0xff)
	runLength := 0
	targetRelative := int64(0)
	literals := make([]byte, 0, createRecordBuffer)
	flush := func() error {
		if state == 0xff || runLength == 0 {
			return nil
		}
		action := (uint64(runLength-1) << 2) | uint64(state)
		if err := w.write(appendBPSVLV(nil, action)); err != nil {
			return err
		}
		if state == bpsTargetRead {
			if err := w.write(literals); err != nil {
				return err
			}
		}
		runLength = 0
		literals = literals[:0]
		return nil
	}
	scanSize := originalSize
	if modifiedSize > scanSize {
		scanSize = modifiedSize
	}
	for offset := int64(0); offset < scanSize; {
		n := int64(fileChunkSize)
		if scanSize-offset < n {
			n = scanSize - offset
		}
		oldData, newData := oldChunk[:n], newChunk[:n]
		if err := readRange(original, originalSize, offset, oldData); err != nil {
			return err
		}
		if err := readRange(modified, modifiedSize, offset, newData); err != nil {
			return err
		}
		sourceLength := min64(n, max64(0, originalSize-offset))
		targetLength := min64(n, max64(0, modifiedSize-offset))
		if sourceLength > 0 {
			_, _ = sourceHash.Write(oldData[:sourceLength])
		}
		if targetLength > 0 {
			_, _ = targetHash.Write(newData[:targetLength])
		}
		for i := 0; i < int(targetLength); {
			b := newData[i]
			sourceEqual := offset+int64(i) < originalSize && oldData[i] == b
			if !sourceEqual && i+4 < int(targetLength) && newData[i+1] == b && newData[i+2] == b && newData[i+3] == b && newData[i+4] == b {
				rleLength := 5
				for i+rleLength < int(targetLength) && newData[i+rleLength] == b {
					rleLength++
				}
				firstState := byte(bpsTargetRead)
				if state != firstState || runLength == createRecordBuffer {
					if err := flush(); err != nil {
						return err
					}
					state = firstState
				}
				runLength++
				if firstState == bpsTargetRead {
					literals = append(literals, b)
				}
				if err := flush(); err != nil {
					return err
				}
				copyLength := rleLength - 1
				if err := w.write(appendBPSVLV(nil, uint64(copyLength-1)<<2|bpsTargetCopy)); err != nil {
					return err
				}
				runStart := offset + int64(i)
				if runStart < targetRelative {
					return ErrInvalidPatch
				}
				if err := w.write(appendBPSVLV(nil, uint64(runStart-targetRelative)<<1)); err != nil {
					return err
				}
				targetRelative = runStart + int64(rleLength) - 1
				i += rleLength
				continue
			}
			next := byte(bpsTargetRead)
			if sourceEqual {
				next = bpsSourceRead
			}
			if state != next || runLength == createRecordBuffer {
				if err := flush(); err != nil {
					return err
				}
				state = next
			}
			runLength++
			if next == bpsTargetRead {
				literals = append(literals, b)
			}
			i++
		}
		offset += n
		if err := reportCreate(opts, FormatBPS, offset, scanSize); err != nil {
			return err
		}
	}
	if err := flush(); err != nil {
		return err
	}
	footer := appendU32LE(nil, sourceHash.Sum32())
	footer = appendU32LE(footer, targetHash.Sum32())
	if err := w.write(footer); err != nil {
		return err
	}
	return w.write(appendU32LE(nil, w.hash.Sum32()))
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

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
