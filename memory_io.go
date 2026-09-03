package rompatcher

import (
	"bytes"
	"fmt"
	"io"
)

type memoryFile struct {
	data []byte
}

func (f *memoryFile) ReadAt(dst []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, io.EOF
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if offset >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(dst, f.data[offset:])
	if n != len(dst) {
		return n, io.EOF
	}
	return n, nil
}

func (f *memoryFile) WriteAt(src []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, ErrOutputTooLarge
	}
	if len(src) == 0 {
		return 0, nil
	}
	if uint64(offset) > uint64(int(^uint(0)>>1)) || uint64(len(src)) > uint64(int(^uint(0)>>1))-uint64(offset) {
		return 0, ErrOutputTooLarge
	}
	end := int(offset) + len(src)
	if end > len(f.data) {
		f.data = append(f.data, make([]byte, end-len(f.data))...)
	}
	return copy(f.data[int(offset):], src), nil
}

func applyMemoryRaw(source, patchData []byte, opts ApplyOptions) ([]byte, error) {
	// Most patches preserve or grow the source size. Reusing that size as
	// capacity avoids repeated reallocations without changing the exact result.
	output := &memoryFile{data: make([]byte, 0, len(source))}
	size, err := ApplyReaderAt(contextOf(opts), bytes.NewReader(source), int64(len(source)), bytes.NewReader(patchData), int64(len(patchData)), output, opts)
	if err != nil {
		return nil, err
	}
	if size < 0 || uint64(size) > uint64(len(output.data)) {
		return nil, fmt.Errorf("%w: invalid output size %d", ErrInvalidPatch, size)
	}
	return output.data[:int(size)], nil
}

func applyWithROMTransforms(source []byte, opts ApplyOptions, apply func([]byte, ApplyOptions) ([]byte, error)) ([]byte, error) {
	if opts.RemoveHeader && opts.AddHeader {
		return nil, fmt.Errorf("remove-header and add-header cannot be used together")
	}
	if err := reportProgress(opts, Progress{Phase: "prepare", Total: int64(len(source))}); err != nil {
		return nil, err
	}
	working := source
	var header []byte
	fake := 0
	if opts.RemoveHeader {
		h, rom, _ := RemoveHeader(source, opts.SourceName)
		if h != nil {
			header, working = h, rom
		}
	} else if opts.AddHeader {
		with, info := AddHeader(source, opts.SourceName)
		if info != nil {
			working, fake = with, info.Size
		}
	}
	applyOptions := withoutProgressPhase(opts, "complete")
	applyOptions.RemoveHeader = false
	applyOptions.AddHeader = false
	applyOptions.FixChecksum = false
	if fake > 0 && applyOptions.MaxOutputSize != 0 {
		if applyOptions.MaxOutputSize > ^uint64(0)-uint64(fake) {
			applyOptions.MaxOutputSize = ^uint64(0)
		} else {
			applyOptions.MaxOutputSize += uint64(fake)
		}
	}
	out, err := apply(working, applyOptions)
	if err != nil {
		return nil, err
	}
	if header != nil {
		if opts.FixChecksum {
			FixROMChecksum(out, opts.SourceName)
		}
		if len(out) > int(^uint(0)>>1)-len(header) {
			return nil, ErrOutputTooLarge
		}
		joined := make([]byte, len(header)+len(out))
		copy(joined, header)
		copy(joined[len(header):], out)
		out = joined
	} else if fake > 0 {
		if len(out) < fake {
			return nil, fmt.Errorf("%w: patched output is smaller than temporary header", ErrInvalidPatch)
		}
		out = append([]byte(nil), out[fake:]...)
		if opts.FixChecksum {
			FixROMChecksum(out, opts.SourceName)
		}
	} else if opts.FixChecksum {
		FixROMChecksum(out, opts.SourceName)
	}
	if err := checkOutputSize(uint64(len(out)), len(source), opts); err != nil {
		return nil, err
	}
	if err := reportProgress(opts, Progress{Phase: "complete", Completed: int64(len(out)), Total: int64(len(out))}); err != nil {
		return nil, err
	}
	return out, nil
}

func applyEncodedWithOptions(source, patchData []byte, opts ApplyOptions) ([]byte, error) {
	return applyWithROMTransforms(source, opts, func(working []byte, applyOptions ApplyOptions) ([]byte, error) {
		return applyMemoryRaw(working, patchData, applyOptions)
	})
}
