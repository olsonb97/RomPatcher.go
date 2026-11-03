package rompatcher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// HeaderInfo describes a recognized leading header layout.
type HeaderInfo struct {
	Name string
	Size int
}

var knownHeaders = []struct {
	extensions     []string
	size, multiple int
	name           string
}{{[]string{"nes"}, 16, 1024, "iNES"}, {[]string{"fds"}, 16, 65500, "fwNES"}, {[]string{"lnx"}, 64, 1024, "LNX"}, {[]string{"sfc", "smc", "swc", "fig"}, 512, 262144, "SNES copier"}}

func extension(name string) string {
	return strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
}

// CanAddHeader reports whether temporary header-sized compatibility data can
// be prepended to data. Use CanAddHeaderSize when the data is file-backed.
func CanAddHeader(data []byte, name string) *HeaderInfo {
	return CanAddHeaderSize(int64(len(data)), name)
}

// CanAddHeaderSize is CanAddHeader without requiring the file contents.
func CanAddHeaderSize(size int64, name string) *HeaderInfo {
	if size < 0 {
		return nil
	}
	ext := extension(name)
	for _, h := range knownHeaders {
		for _, x := range h.extensions {
			if ext == x && size%int64(h.multiple) == 0 {
				return &HeaderInfo{Name: h.name, Size: h.size}
			}
		}
	}
	return nil
}

// DetectHeader reports a recognized leading header already present in data.
// Detection is based on the filename and size convention; it does not validate
// every metadata field. Use DetectHeaderSize when the data is file-backed.
func DetectHeader(data []byte, name string) *HeaderInfo {
	return DetectHeaderSize(int64(len(data)), name)
}

// DetectHeaderSize is DetectHeader without requiring the file contents.
func DetectHeaderSize(size int64, name string) *HeaderInfo {
	if size < 0 {
		return nil
	}
	ext := extension(name)
	for _, h := range knownHeaders {
		for _, x := range h.extensions {
			if ext == x && size >= int64(h.size) && (size-int64(h.size))%int64(h.multiple) == 0 {
				return &HeaderInfo{Name: h.name, Size: h.size}
			}
		}
	}
	return nil
}

// RemoveHeader separates a recognized header from ROM data.
func RemoveHeader(data []byte, name string) (header, rom []byte, info *HeaderInfo) {
	header, rom, info, _ = removeHeaderContext(context.Background(), data, name)
	return
}

func removeHeaderContext(ctx context.Context, data []byte, name string) (header, rom []byte, info *HeaderInfo, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	info = DetectHeader(data, name)
	if info == nil {
		return nil, data, nil, nil
	}
	header = append([]byte(nil), data[:info.Size]...)
	rom = make([]byte, len(data)-info.Size)
	err = copyBytesContext(ctx, rom, data[info.Size:])
	return
}

// AddHeader prepends temporary header-sized data for patch offset
// compatibility. The generated prefix is removed after patching and is not
// guaranteed to contain complete iNES, LNX, or copier metadata. FDS magic and
// disk count fields are initialized because they can be derived safely.
func AddHeader(data []byte, name string) ([]byte, *HeaderInfo) {
	out, info, _ := addHeaderContext(context.Background(), data, name)
	return out, info
}

func addHeaderContext(ctx context.Context, data []byte, name string) ([]byte, *HeaderInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	info := CanAddHeader(data, name)
	if info == nil {
		return data, nil, nil
	}
	if len(data) > int(^uint(0)>>1)-info.Size {
		return nil, nil, ErrOutputTooLarge
	}
	out := make([]byte, info.Size+len(data))
	if err := copyBytesContext(ctx, out[info.Size:], data); err != nil {
		return nil, nil, err
	}
	if extension(name) == "fds" {
		copy(out, []byte{'F', 'D', 'S', 0x1a, byte(len(data) / 65500)})
	}
	return out, info, nil
}

var gameBoyLogo = []byte{0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x08, 0x11, 0x1f, 0x88, 0x89, 0x00, 0x0e, 0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99}

func romSystem(data []byte, name string) string {
	return romSystemHeader(data, int64(len(data)), name)
}

func romSystemHeader(data []byte, size int64, name string) string {
	ext := extension(name)
	if (ext == "gb" || ext == "gbc") && len(data) >= 0x124 && size%0x4000 == 0 && bytes.Equal(data[0x104:0x124], gameBoyLogo) {
		return "gb"
	}
	if (ext == "md" || ext == "bin") && len(data) >= 0x200 && (bytes.HasPrefix(data[0x100:], []byte("SEGA GENESIS")) || bytes.HasPrefix(data[0x100:], []byte("SEGA MEGA DR"))) {
		return "smd"
	}
	if ext == "z64" && size >= 0x400000 {
		return "n64"
	}
	if ext == "fds" && (size%65500 == 0 || (size >= 16 && (size-16)%65500 == 0)) {
		return "fds"
	}
	return ""
}

// FixROMChecksum repairs a recognized internal ROM checksum in place.
func FixROMChecksum(data []byte, name string) bool {
	fixed, _ := fixROMChecksumContext(context.Background(), data, name)
	return fixed
}

func fixROMChecksumContext(ctx context.Context, data []byte, name string) (bool, error) {
	rom := &memoryFile{data: data}
	return fixROMChecksumReaderAt(ctx, rom, rom, int64(len(data)), name)
}

func fixROMChecksumReaderAt(ctx context.Context, reader io.ReaderAt, writer io.WriterAt, size int64, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if size < 0 {
		return false, fmt.Errorf("invalid ROM size: %d", size)
	}
	switch extension(name) {
	case "gb", "gbc", "md", "bin":
	default:
		return false, nil
	}
	data := make([]byte, min64(size, 0x200))
	if err := readAtFull(reader, data, 0); err != nil {
		return false, fmt.Errorf("read ROM header: %w", err)
	}
	var offset int64
	var checksum []byte
	switch romSystemHeader(data, size, name) {
	case "gb":
		if len(data) < 0x14e {
			return false, nil
		}
		var sum byte
		for _, b := range data[0x134:0x14d] {
			sum = sum - b - 1
		}
		if data[0x14d] != sum {
			offset, checksum = 0x14d, []byte{sum}
		}
	case "smd":
		if len(data) < 0x200 {
			return false, nil
		}
		var sum uint16
		buf := make([]byte, checksumChunkSize)
		for off := int64(0x200); off+1 < size; {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			chunk := buf[:min64(int64(len(buf)), size-off)]
			if err := readAtFull(reader, chunk, off); err != nil {
				return false, fmt.Errorf("read ROM checksum data: %w", err)
			}
			for i := 0; i+1 < len(chunk); i += 2 {
				sum += uint16(chunk[i])<<8 | uint16(chunk[i+1])
			}
			off += int64(len(chunk))
		}
		current := uint16(data[0x18e])<<8 | uint16(data[0x18f])
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if current != sum {
			offset, checksum = 0x18e, []byte{byte(sum >> 8), byte(sum)}
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if len(checksum) == 0 {
		return false, nil
	}
	if err := writeAtFull(writer, checksum, offset); err != nil {
		return false, fmt.Errorf("write ROM checksum: %w", err)
	}
	return true, nil
}

// AdditionalChecksum returns format-specific source identification when available.
func AdditionalChecksum(data []byte, name string) string {
	if romSystem(data, name) == "n64" && len(data) >= 0x3f {
		return fmt.Sprintf("%s (%x)", data[0x3c:0x3f], data[0x10:0x18])
	}
	return ""
}

// ApplyWithOptions is an explicit-name alias for Apply.
func ApplyWithOptions(source, patchData []byte, opts ApplyOptions) ([]byte, error) {
	return Apply(source, patchData, opts)
}

// ApplyParsedWithOptions applies an already parsed patch in memory.
// Built-in serializers honor cancellation during processing. A caller-supplied
// Patch owns its MarshalBinary implementation; cancellation is checked before
// and after that method.
func ApplyParsedWithOptions(source []byte, p Patch, opts ApplyOptions) ([]byte, error) {
	if err := checkCanceled(opts); err != nil {
		return nil, err
	}
	if isNilInterface(p) {
		return nil, fmt.Errorf("%w: nil patch", ErrInvalidPatch)
	}
	if bdf, ok := p.(*BDFPatch); ok {
		if len(bdf.data) == 0 {
			return nil, ErrUnsupported
		}
		return applyEncodedWithOptions(source, bdf.data, opts)
	}
	var (
		data []byte
		err  error
	)
	switch patch := p.(type) {
	case *VCDIFFPatch:
		data = patch.data
	case *PMSRPatch:
		if patch.TargetSize < 0 {
			return nil, ErrInvalidPatch
		}
		if len(patch.data) == 0 {
			return nil, ErrUnsupported
		}
		data = patch.data
	default:
		data, err = marshalPatchContext(contextOf(opts), p)
	}
	if err != nil {
		return nil, err
	}
	return applyEncodedWithOptions(source, data, opts)
}
