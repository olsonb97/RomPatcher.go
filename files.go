package rompatcher

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

const fileChunkSize = 1 << 20

// ApplyReaderAt applies a patch from random-access inputs to a random-access
// output. Source and output data remain file-backed unless temporary header or
// checksum transformations require the compatibility memory path. Formats that
// must read already-produced output also require output to implement ReaderAt;
// *os.File satisfies both interfaces. The patch itself is parsed in memory. The
// returned size is the exact output length.
func ApplyReaderAt(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	if sourceSize < 0 || patchSize < 0 {
		return 0, fmt.Errorf("%w: negative input size", ErrInvalidPatch)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opts.Context = ctx
	patchData, err := readAllAt(ctx, patch, patchSize, nil)
	if err != nil {
		return 0, fmt.Errorf("read patch: %w", err)
	}
	p, err := Parse(patchData)
	if err != nil {
		return 0, err
	}
	if !opts.RemoveHeader && !opts.AddHeader && !opts.FixChecksum {
		if size, ok, err := applyOverlayAt(source, sourceSize, output, p, opts); ok {
			if err != nil {
				return 0, err
			}
			if err := reportProgress(opts, Progress{Phase: "complete", Format: p.Format(), Completed: size, Total: size}); err != nil {
				return 0, err
			}
			return size, nil
		}
	}
	sourceData, err := readAllAt(ctx, source, sourceSize, func(done int64) error {
		return reportProgress(opts, Progress{Phase: "read-source", Format: p.Format(), Completed: done, Total: sourceSize})
	})
	if err != nil {
		return 0, fmt.Errorf("read source: %w", err)
	}
	out, err := ApplyParsedWithOptions(sourceData, p, opts)
	if err != nil {
		return 0, err
	}
	if err := writeAllAt(ctx, output, out, opts, p.Format()); err != nil {
		return 0, err
	}
	return int64(len(out)), nil
}

func readAllAt(ctx context.Context, r io.ReaderAt, size int64, progress func(int64) error) ([]byte, error) {
	if size < 0 || uint64(size) > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("input is too large for memory-backed operation: %d", size)
	}
	out := make([]byte, int(size))
	for off := int64(0); off < size; {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		n := int64(fileChunkSize)
		if size-off < n {
			n = size - off
		}
		got, err := r.ReadAt(out[off:off+n], off)
		if got < 0 || int64(got) > n {
			return nil, fmt.Errorf("invalid ReaderAt count %d", got)
		}
		off += int64(got)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if int64(got) != n {
			return nil, io.ErrUnexpectedEOF
		}
		if progress != nil {
			if err := progress(off); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func writeAllAt(ctx context.Context, w io.WriterAt, data []byte, opts ApplyOptions, format Format) error {
	for off := 0; off < len(data); {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n := fileChunkSize
		if len(data)-off < n {
			n = len(data) - off
		}
		wrote, err := w.WriteAt(data[off:off+n], int64(off))
		if wrote < 0 || wrote > n {
			return fmt.Errorf("invalid WriterAt count %d", wrote)
		}
		if err != nil {
			return err
		}
		if wrote != n {
			return io.ErrShortWrite
		}
		off += wrote
		if err := reportProgress(opts, Progress{Phase: "write-output", Format: format, Completed: int64(off), Total: int64(len(data))}); err != nil {
			return err
		}
	}
	return nil
}

func applyOverlayAt(source io.ReaderAt, sourceSize int64, output io.WriterAt, patch Patch, opts ApplyOptions) (int64, bool, error) {
	switch p := patch.(type) {
	case *APSN64Patch:
		return applyAPSN64At(source, sourceSize, nil, output, p, opts)
	case *APSGBAPatch:
		return applyAPSGBAAt(source, sourceSize, nil, output, p, opts)
	case *BDFPatch:
		return applyBDFAt(source, sourceSize, output, p, opts)
	case *UPSPatch:
		if !opts.Validate {
			return applyUPSAt(source, sourceSize, nil, output, p, opts)
		}
	case *RUPPatch:
		if !opts.Validate {
			return applyRUPAt(source, sourceSize, nil, output, p, opts)
		}
	}
	if readOutput, ok := output.(io.ReaderAt); ok {
		switch p := patch.(type) {
		case *BPSPatch:
			return applyBPSAt(source, sourceSize, readOutput, output, p, opts)
		case *UPSPatch:
			return applyUPSAt(source, sourceSize, readOutput, output, p, opts)
		case *RUPPatch:
			return applyRUPAt(source, sourceSize, readOutput, output, p, opts)
		case *VCDIFFPatch:
			return applyVCDIFFAt(source, sourceSize, readOutput, output, p, opts)
		}
	}
	targetSize := sourceSize
	switch p := patch.(type) {
	case *IPSPatch:
		if p.HasTruncate && p.Metadata == nil {
			targetSize = int64(p.Truncate)
		} else {
			targetSize = overlaySize(targetSize, p.Records)
		}
		if err := validateIPSRecords(p.Records, targetSize); err != nil {
			return 0, true, err
		}
	case *IPS32Patch:
		if p.HasTruncate {
			targetSize = int64(p.Truncate)
		} else {
			targetSize = overlaySize(targetSize, p.Records)
		}
		if err := validateIPSRecords(p.Records, targetSize); err != nil {
			return 0, true, err
		}
	case *PPFPatch:
		for _, r := range p.Records {
			if r.offset > uint64(^uint64(0)>>1) || uint64(len(r.data)) > uint64(^uint64(0)>>1)-r.offset {
				return 0, true, ErrInvalidPatch
			}
			end := int64(r.offset + uint64(len(r.data)))
			if end > targetSize {
				targetSize = end
			}
		}
		if opts.Validate {
			valid, err := validatePPFAt(source, sourceSize, p)
			if err != nil {
				return 0, true, err
			}
			if !valid {
				return 0, true, ErrSourceMismatch
			}
		}
	case *PMSRPatch:
		if opts.Validate {
			if sourceSize != 41943040 {
				return 0, true, ErrSourceMismatch
			}
			sum, err := crc32ReaderAt(opts, source, sourceSize, p.Format(), "validate-source")
			if err != nil {
				return 0, true, err
			}
			if sum != 0xa7f5cd7e {
				return 0, true, ErrSourceMismatch
			}
		}
		targetSize = int64(p.TargetSize)
		for _, r := range p.Records {
			if int64(r.offset) > targetSize-int64(len(r.data)) {
				return 0, true, fmt.Errorf("%w: PMSR record outside output", ErrInvalidPatch)
			}
		}
	default:
		return 0, false, nil
	}
	if targetSize < 0 {
		return 0, true, ErrInvalidPatch
	}
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, true, err
	}
	copySize := sourceSize
	if targetSize < copySize {
		copySize = targetSize
	}
	if err := copyReaderAt(opts, output, source, copySize, patch.Format()); err != nil {
		return 0, true, err
	}
	if targetSize > copySize {
		if err := zeroRange(opts, output, copySize, targetSize-copySize, patch.Format()); err != nil {
			return 0, true, err
		}
	}
	switch p := patch.(type) {
	case *IPSPatch:
		return targetSize, true, writeIPSRecords(output, p.Records, opts, p.Format())
	case *IPS32Patch:
		return targetSize, true, writeIPSRecords(output, p.Records, opts, p.Format())
	case *PPFPatch:
		undo, err := ppfUndoingAt(source, sourceSize, p)
		if err != nil {
			return 0, true, err
		}
		for i, r := range p.Records {
			data := r.data
			if undo {
				data = r.undo
			}
			if err := writeAtFull(output, data, int64(r.offset)); err != nil {
				return 0, true, err
			}
			if err := reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i + 1), Total: int64(len(p.Records))}); err != nil {
				return 0, true, err
			}
		}
	case *PMSRPatch:
		for i, r := range p.Records {
			if err := writeAtFull(output, r.data, int64(r.offset)); err != nil {
				return 0, true, err
			}
			if err := reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i + 1), Total: int64(len(p.Records))}); err != nil {
				return 0, true, err
			}
		}
	}
	return targetSize, true, nil
}

func applyBPSAt(source io.ReaderAt, sourceSize int64, readOutput io.ReaderAt, output io.WriterAt, p *BPSPatch, opts ApplyOptions) (int64, bool, error) {
	targetSize := int64(p.TargetSize)
	if targetSize < 0 || uint64(targetSize) != p.TargetSize {
		return 0, true, ErrInvalidPatch
	}
	if err := checkOutputSize64(p.TargetSize, uint64(sourceSize), opts); err != nil {
		return 0, true, err
	}
	if opts.Validate {
		if uint64(sourceSize) != p.SourceSize {
			return 0, true, ErrSourceMismatch
		}
		sum, err := crc32ReaderAt(opts, source, sourceSize, p.Format(), "validate-source")
		if err != nil {
			return 0, true, err
		}
		if sum != p.SourceCRC {
			return 0, true, ErrSourceMismatch
		}
	}
	pos := int64(0)
	var sourceRel, targetRel int64
	scratch := make([]byte, fileChunkSize)
	var targetPattern []byte
	for i, a := range p.Actions {
		ln := int64(a.length)
		if ln <= 0 || pos < 0 || pos > targetSize-ln {
			return 0, true, fmt.Errorf("%w: BPS action exceeds output", ErrInvalidPatch)
		}
		switch a.typ {
		case bpsSourceRead:
			if pos > sourceSize-ln {
				return 0, true, fmt.Errorf("%w: BPS source read exceeds input", ErrInvalidPatch)
			}
			if err := copyRange(opts, output, pos, source, pos, ln, p.Format(), scratch); err != nil {
				return 0, true, err
			}
		case bpsTargetRead:
			if len(a.data) != a.length {
				return 0, true, ErrInvalidPatch
			}
			if err := writeAtFull(output, a.data, pos); err != nil {
				return 0, true, err
			}
		case bpsSourceCopy:
			var ok bool
			sourceRel, ok = addInt64(sourceRel, a.relative)
			if !ok || sourceRel < 0 || sourceRel > sourceSize-ln {
				return 0, true, fmt.Errorf("%w: BPS source copy exceeds input", ErrInvalidPatch)
			}
			if err := copyRange(opts, output, pos, source, sourceRel, ln, p.Format(), scratch); err != nil {
				return 0, true, err
			}
			sourceRel += ln
		case bpsTargetCopy:
			var ok bool
			targetRel, ok = addInt64(targetRel, a.relative)
			if !ok || targetRel < 0 || targetRel >= pos {
				return 0, true, fmt.Errorf("%w: invalid BPS target copy", ErrInvalidPatch)
			}
			distance := pos - targetRel
			if distance <= 0 {
				return 0, true, fmt.Errorf("%w: invalid BPS target copy", ErrInvalidPatch)
			}
			if distance <= fileChunkSize {
				if cap(targetPattern) < int(distance) {
					targetPattern = make([]byte, int(distance))
				} else {
					targetPattern = targetPattern[:int(distance)]
				}
				if err := readAtFull(readOutput, targetPattern, targetRel); err != nil {
					return 0, true, err
				}
			}
			for copied := int64(0); copied < ln; {
				n := int64(fileChunkSize)
				if ln-copied < n {
					n = ln - copied
				}
				buf := scratch[:int(n)]
				if distance <= fileChunkSize {
					fillPattern(buf, targetPattern, int(copied%distance))
				} else {
					if err := readAtFull(readOutput, buf, targetRel+copied); err != nil {
						return 0, true, err
					}
				}
				if err := writeAtFull(output, buf, pos+copied); err != nil {
					return 0, true, err
				}
				copied += n
				if err := checkCanceled(opts); err != nil {
					return 0, true, err
				}
			}
			targetRel += ln
		default:
			return 0, true, ErrInvalidPatch
		}
		pos += ln
		if err := reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i + 1), Total: int64(len(p.Actions))}); err != nil {
			return 0, true, err
		}
	}
	if pos != targetSize {
		return 0, true, fmt.Errorf("%w: BPS output size", ErrInvalidPatch)
	}
	if opts.Validate {
		sum, err := crc32ReaderAt(opts, readOutput, targetSize, p.Format(), "validate-target")
		if err != nil {
			return 0, true, err
		}
		if sum != p.TargetCRC {
			return 0, true, ErrTargetMismatch
		}
	}
	return targetSize, true, nil
}

func applyUPSAt(source io.ReaderAt, sourceSize int64, readOutput io.ReaderAt, output io.WriterAt, p *UPSPatch, opts ApplyOptions) (int64, bool, error) {
	if err := p.validateRecords(); err != nil {
		return 0, true, err
	}
	actualSize := uint64(sourceSize)
	var sum uint32
	checked := false
	if opts.Validate || actualSize == p.TargetSize {
		var err error
		sum, err = crc32ReaderAt(opts, source, sourceSize, p.Format(), "validate-source")
		if err != nil {
			return 0, true, err
		}
		checked = true
	}
	undo := checked && p.reverseFor(actualSize, sum)
	if opts.Validate && !undo && !(actualSize == p.SourceSize && sum == p.SourceCRC) {
		return 0, true, ErrSourceMismatch
	}
	targetSize := p.TargetSize
	if undo {
		targetSize = p.SourceSize
	} else if !opts.Validate && p.SourceSize < actualSize && targetSize < actualSize {
		targetSize = actualSize
	}
	if targetSize > uint64(^uint64(0)>>1) {
		return 0, true, ErrInvalidPatch
	}
	if err := checkOutputSize64(targetSize, uint64(sourceSize), opts); err != nil {
		return 0, true, err
	}
	copySize := sourceSize
	if int64(targetSize) < copySize {
		copySize = int64(targetSize)
	}
	if err := copyReaderAt(opts, output, source, copySize, p.Format()); err != nil {
		return 0, true, err
	}
	if int64(targetSize) > copySize {
		if err := zeroRange(opts, output, copySize, int64(targetSize)-copySize, p.Format()); err != nil {
			return 0, true, err
		}
	}
	pos := uint64(0)
	scratch := make([]byte, fileChunkSize)
	for i, r := range p.Records {
		pos += r.offset
		for done := 0; done < len(r.xor); {
			n := len(scratch)
			if len(r.xor)-done < n {
				n = len(r.xor) - done
			}
			chunkPos := pos + uint64(done)
			if chunkPos >= targetSize {
				done += n
				continue
			}
			if targetSize-chunkPos < uint64(n) {
				n = int(targetSize - chunkPos)
			}
			buf := scratch[:n]
			clear(buf)
			if chunkPos < actualSize {
				readLen := n
				if actualSize-chunkPos < uint64(readLen) {
					readLen = int(actualSize - chunkPos)
				}
				if err := readAtFull(source, buf[:readLen], int64(chunkPos)); err != nil {
					return 0, true, err
				}
			}
			for j, x := range r.xor[done : done+n] {
				buf[j] ^= x
			}
			if err := writeAtFull(output, buf, int64(chunkPos)); err != nil {
				return 0, true, err
			}
			done += n
			if err := checkCanceled(opts); err != nil {
				return 0, true, err
			}
		}
		pos += uint64(len(r.xor))
		pos++
		if err := reportProgress(opts, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i + 1), Total: int64(len(p.Records))}); err != nil {
			return 0, true, err
		}
	}
	if opts.Validate {
		sum, err := crc32ReaderAt(opts, readOutput, int64(targetSize), p.Format(), "validate-target")
		if err != nil {
			return 0, true, err
		}
		want := p.TargetCRC
		if undo {
			want = p.SourceCRC
		}
		if sum != want {
			return 0, true, ErrTargetMismatch
		}
	}
	return int64(targetSize), true, nil
}

func crc32ReaderAt(opts ApplyOptions, r io.ReaderAt, size int64, format Format, phase string) (uint32, error) {
	h := crc32.NewIEEE()
	buf := make([]byte, fileChunkSize)
	for off := int64(0); off < size; {
		n := int64(len(buf))
		if size-off < n {
			n = size - off
		}
		if err := readAtFull(r, buf[:n], off); err != nil {
			return 0, err
		}
		_, _ = h.Write(buf[:n])
		off += n
		if err := reportProgress(opts, Progress{Phase: phase, Format: format, Completed: off, Total: size}); err != nil {
			return 0, err
		}
	}
	return h.Sum32(), nil
}

func copyRange(opts ApplyOptions, dst io.WriterAt, dstOff int64, src io.ReaderAt, srcOff, size int64, format Format, buf []byte) error {
	for done := int64(0); done < size; {
		n := int64(len(buf))
		if size-done < n {
			n = size - done
		}
		if err := readAtFull(src, buf[:n], srcOff+done); err != nil {
			return err
		}
		if err := writeAtFull(dst, buf[:n], dstOff+done); err != nil {
			return err
		}
		done += n
		if err := checkCanceled(opts); err != nil {
			return err
		}
	}
	return nil
}

func readAtFull(r io.ReaderAt, b []byte, off int64) error {
	for len(b) > 0 {
		n, err := r.ReadAt(b, off)
		if n < 0 || n > len(b) {
			return fmt.Errorf("invalid ReaderAt count %d", n)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		b, off = b[n:], off+int64(n)
	}
	return nil
}

func overlaySize(size int64, records []ipsRecord) int64 {
	for _, r := range records {
		end := int64(recordEnd(r))
		if end > size {
			size = end
		}
	}
	return size
}

func writeIPSRecords(output io.WriterAt, records []ipsRecord, opts ApplyOptions, format Format) error {
	var rleBuffer []byte
	for i, r := range records {
		if r.rleLen > 0 {
			if rleBuffer == nil {
				rleBuffer = make([]byte, fileChunkSize)
			}
			fillBytes(rleBuffer, r.rle)
			remaining, off := r.rleLen, int64(r.offset)
			for remaining > 0 {
				n := len(rleBuffer)
				if remaining < n {
					n = remaining
				}
				if err := writeAtFull(output, rleBuffer[:n], off); err != nil {
					return err
				}
				off, remaining = off+int64(n), remaining-n
			}
		} else if err := writeAtFull(output, r.data, int64(r.offset)); err != nil {
			return err
		}
		if err := reportProgress(opts, Progress{Phase: "apply", Format: format, Completed: int64(i + 1), Total: int64(len(records))}); err != nil {
			return err
		}
	}
	return nil
}

func copyReaderAt(opts ApplyOptions, dst io.WriterAt, src io.ReaderAt, size int64, format Format) error {
	buf := make([]byte, fileChunkSize)
	for off := int64(0); off < size; {
		n := int64(len(buf))
		if size-off < n {
			n = size - off
		}
		got, err := src.ReadAt(buf[:n], off)
		if got < 0 || int64(got) > n {
			return fmt.Errorf("invalid ReaderAt count %d", got)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if int64(got) != n {
			return io.ErrUnexpectedEOF
		}
		if err := writeAtFull(dst, buf[:n], off); err != nil {
			return err
		}
		off += n
		if err := reportProgress(opts, Progress{Phase: "copy-source", Format: format, Completed: off, Total: size}); err != nil {
			return err
		}
	}
	return nil
}

func zeroRange(opts ApplyOptions, dst io.WriterAt, offset, size int64, format Format) error {
	buf := make([]byte, fileChunkSize)
	for done := int64(0); done < size; {
		n := int64(len(buf))
		if size-done < n {
			n = size - done
		}
		if err := writeAtFull(dst, buf[:n], offset+done); err != nil {
			return err
		}
		done += n
		if err := reportProgress(opts, Progress{Phase: "initialize-output", Format: format, Completed: done, Total: size}); err != nil {
			return err
		}
	}
	return nil
}

func writeAtFull(w io.WriterAt, b []byte, off int64) error {
	for len(b) > 0 {
		n, err := w.WriteAt(b, off)
		if n < 0 || n > len(b) {
			return fmt.Errorf("invalid WriterAt count %d", n)
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b, off = b[n:], off+int64(n)
	}
	return nil
}

func ApplyFile(sourcePath, patchPath, outputPath string, opts ApplyOptions) error {
	return ApplyFileContext(contextOf(opts), sourcePath, patchPath, outputPath, opts)
}

func ApplyFileContext(ctx context.Context, sourcePath, patchPath, outputPath string, opts ApplyOptions) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer source.Close()
	patch, err := os.Open(patchPath)
	if err != nil {
		return fmt.Errorf("open patch: %w", err)
	}
	defer patch.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return err
	}
	patchInfo, err := patch.Stat()
	if err != nil {
		return err
	}
	if opts.SourceName == "" {
		opts.SourceName = sourcePath
	}
	if outputPath == "" {
		outputPath = DefaultPatchedPath(sourcePath)
	}
	return atomicOutput(outputPath, func(out *os.File) error {
		size, err := ApplyReaderAt(ctx, source, sourceInfo.Size(), patch, patchInfo.Size(), out, opts)
		if err != nil {
			return err
		}
		if err := out.Truncate(size); err != nil {
			return fmt.Errorf("truncate output: %w", err)
		}
		return nil
	})
}

func CreateFile(originalPath, modifiedPath, outputPath string, format Format, opts *CreateOptions) error {
	original, err := os.ReadFile(originalPath)
	if err != nil {
		return fmt.Errorf("read original: %w", err)
	}
	modified, err := os.ReadFile(modifiedPath)
	if err != nil {
		return fmt.Errorf("read modified: %w", err)
	}
	localOptions := CreateOptions{}
	if opts != nil {
		localOptions = *opts
	}
	if localOptions.SourceName == "" {
		localOptions.SourceName = originalPath
	}
	p, err := Create(original, modified, format, &localOptions)
	if err != nil {
		return err
	}
	data, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	if outputPath == "" {
		ext := filepath.Ext(modifiedPath)
		outputPath = modifiedPath[:len(modifiedPath)-len(ext)] + "." + string(format)
	}
	return atomicOutput(outputPath, func(out *os.File) error {
		if _, err := out.Write(data); err != nil {
			return fmt.Errorf("write patch: %w", err)
		}
		return nil
	})
}

func atomicOutput(path string, write func(*os.File) error) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rompatcher-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err = write(tmp); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err = commitTempNoReplace(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output already exists: %s", path)
		}
		return fmt.Errorf("commit output: %w", err)
	}
	return nil
}

// WriteFileAtomic writes data to a temporary file in the destination directory,
// flushes it, and atomically publishes it. Existing destinations are never
// clobbered.
func WriteFileAtomic(path string, data []byte) error {
	return atomicOutput(path, func(out *os.File) error {
		if _, err := out.Write(data); err != nil {
			return err
		}
		return nil
	})
}

func DefaultPatchedPath(sourcePath string) string {
	ext := filepath.Ext(sourcePath)
	return sourcePath[:len(sourcePath)-len(ext)] + " (patched)" + ext
}
