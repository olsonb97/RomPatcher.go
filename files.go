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

const (
	fileChunkSize     = 1 << 20
	checksumChunkSize = 128 << 10
)

// ApplyReaderAt normally applies a patch without loading either input into
// memory. Header conversion and checksum repair use the compatibility memory
// path. The returned size is the exact output length. Output must also
// implement io.ReaderAt for formats that copy from already-produced output;
// *os.File and the package's in-memory adapter both satisfy that requirement.
func ApplyReaderAt(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	if isNilInterface(source) || isNilInterface(patch) || isNilInterface(output) {
		return 0, fmt.Errorf("source, patch, and output must be non-nil")
	}
	if sourceSize < 0 || patchSize < 0 {
		return 0, fmt.Errorf("%w: negative input size", ErrInvalidPatch)
	}
	if opts.RemoveHeader && opts.AddHeader {
		return 0, fmt.Errorf("remove-header and add-header cannot be used together")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opts.Context = ctx
	if !opts.RemoveHeader && !opts.AddHeader && !opts.FixChecksum {
		size, err := applyPatchReaderAt(ctx, source, sourceSize, patch, patchSize, output, opts)
		if err != nil {
			return 0, err
		}
		if err := reportProgress(opts, Progress{Phase: "complete", Completed: size, Total: size}); err != nil {
			return 0, err
		}
		return size, nil
	}

	// Header conversion and platform checksum repair are compatibility features
	// that inherently operate on a complete ROM. Normal patching stays file-backed.
	patchData, err := readAllAt(ctx, patch, patchSize, nil)
	if err != nil {
		return 0, fmt.Errorf("read patch: %w", err)
	}
	sourceData, err := readAllAt(ctx, source, sourceSize, func(done int64) error {
		return reportProgress(opts, Progress{Phase: "read-source", Completed: done, Total: sourceSize})
	})
	if err != nil {
		return 0, fmt.Errorf("read source: %w", err)
	}
	applyOpts := withoutProgressPhase(opts, "complete")
	out, err := applyEncodedWithOptions(sourceData, patchData, applyOpts)
	if err != nil {
		return 0, err
	}
	if err := writeAllAt(ctx, output, out, opts); err != nil {
		return 0, err
	}
	if err := reportProgress(opts, Progress{Phase: "complete", Completed: int64(len(out)), Total: int64(len(out))}); err != nil {
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min64(fileChunkSize, size-off)
		if err := readAtFull(r, out[off:off+n], off); err != nil {
			return nil, err
		}
		off += n
		if progress != nil {
			if err := progress(off); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func writeAllAt(ctx context.Context, w io.WriterAt, data []byte, opts ApplyOptions) error {
	for off := 0; off < len(data); {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(fileChunkSize, len(data)-off)
		if err := writeAtFull(w, data[off:off+n], int64(off)); err != nil {
			return err
		}
		off += n
		if err := reportProgress(opts, Progress{Phase: "write-output", Completed: int64(off), Total: int64(len(data))}); err != nil {
			return err
		}
	}
	return nil
}

func crc32ReaderAt(opts ApplyOptions, r io.ReaderAt, size int64, format Format, phase string) (uint32, error) {
	h := crc32.NewIEEE()
	buf := make([]byte, checksumChunkSize)
	for off := int64(0); off < size; {
		n := min64(int64(len(buf)), size-off)
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
		n := min64(int64(len(buf)), size-done)
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

func readAtFull(r io.ReaderAt, data []byte, offset int64) error {
	for len(data) > 0 {
		n, err := r.ReadAt(data, offset)
		if n < 0 || n > len(data) {
			return fmt.Errorf("invalid ReaderAt count %d", n)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data, offset = data[n:], offset+int64(n)
	}
	return nil
}

func copyReaderAt(opts ApplyOptions, dst io.WriterAt, src io.ReaderAt, size int64, format Format) error {
	buf := make([]byte, fileChunkSize)
	for off := int64(0); off < size; {
		n := min64(int64(len(buf)), size-off)
		if err := readAtFull(src, buf[:n], off); err != nil {
			return err
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
		n := min64(int64(len(buf)), size-done)
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

func writeAtFull(w io.WriterAt, data []byte, offset int64) error {
	for len(data) > 0 {
		n, err := w.WriteAt(data, offset)
		if n < 0 || n > len(data) {
			return fmt.Errorf("invalid WriterAt count %d", n)
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data, offset = data[n:], offset+int64(n)
	}
	return nil
}

// ApplyFile applies one patch using file-backed I/O and atomic output.
func ApplyFile(sourcePath, patchPath, outputPath string, opts ApplyOptions) error {
	return ApplyFileContext(contextOf(opts), sourcePath, patchPath, outputPath, opts)
}

// ApplyFileContext is ApplyFile with explicit cancellation.
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
		return fmt.Errorf("stat source: %w", err)
	}
	patchInfo, err := patch.Stat()
	if err != nil {
		return fmt.Errorf("stat patch: %w", err)
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

// CreateFile creates a patch using file-backed I/O and atomic output.
func CreateFile(originalPath, modifiedPath, outputPath string, format Format, opts *CreateOptions) error {
	ctx := context.Background()
	if opts != nil && opts.Context != nil {
		ctx = opts.Context
	}
	return CreateFileContext(ctx, originalPath, modifiedPath, outputPath, format, opts)
}

// CreateFileContext creates a patch from two files and atomically publishes it.
// Inputs stay file-backed unless BPS delta matching is explicitly enabled.
func CreateFileContext(ctx context.Context, originalPath, modifiedPath, outputPath string, format Format, opts *CreateOptions) error {
	format = normalizeFormat(format)
	original, err := os.Open(originalPath)
	if err != nil {
		return fmt.Errorf("open original: %w", err)
	}
	defer original.Close()
	modified, err := os.Open(modifiedPath)
	if err != nil {
		return fmt.Errorf("open modified: %w", err)
	}
	defer modified.Close()
	originalInfo, err := original.Stat()
	if err != nil {
		return fmt.Errorf("stat original: %w", err)
	}
	modifiedInfo, err := modified.Stat()
	if err != nil {
		return fmt.Errorf("stat modified: %w", err)
	}
	local := CreateOptions{}
	if opts != nil {
		local = *opts
	}
	local.Context = ctx
	if local.SourceName == "" {
		local.SourceName = originalPath
	}
	if outputPath == "" {
		ext := filepath.Ext(modifiedPath)
		outputPath = modifiedPath[:len(modifiedPath)-len(ext)] + "." + string(format)
	}
	return atomicOutput(outputPath, func(out *os.File) error {
		_, err := CreateReaderAt(ctx, original, originalInfo.Size(), modified, modifiedInfo.Size(), out, format, &local)
		return err
	})
}

func atomicOutput(path string, write func(*os.File) error) (err error) {
	if err := ensureOutputAbsent(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rompatcher-*")
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
	return publishTemp(tmpName, path)
}

func ensureOutputAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("output already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output: %w", err)
	}
	return nil
}

func publishTemp(temporary, destination string) error {
	if err := commitTempNoReplace(temporary, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output already exists: %s", destination)
		}
		return fmt.Errorf("commit output: %w", err)
	}
	return nil
}

// WriteFileAtomic writes data atomically without replacing an existing file.
func WriteFileAtomic(path string, data []byte) error {
	return atomicOutput(path, func(out *os.File) error {
		_, err := out.Write(data)
		return err
	})
}

// DefaultPatchedPath inserts " (patched)" before a source file's extension.
func DefaultPatchedPath(sourcePath string) string {
	ext := filepath.Ext(sourcePath)
	return sourcePath[:len(sourcePath)-len(ext)] + " (patched)" + ext
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
