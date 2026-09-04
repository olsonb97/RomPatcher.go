package rompatcher

import (
	"context"
	"crypto/md5"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
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
