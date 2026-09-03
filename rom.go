package rompatcher

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

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
func CanAddHeader(data []byte, name string) *HeaderInfo {
	if len(data) > 0x600000 {
		return nil
	}
	ext := extension(name)
	for _, h := range knownHeaders {
		for _, x := range h.extensions {
			if ext == x && len(data)%h.multiple == 0 {
				return &HeaderInfo{Name: h.name, Size: h.size}
			}
		}
	}
	return nil
}
func DetectHeader(data []byte, name string) *HeaderInfo {
	if len(data) > 0x600200 || len(data)%1024 == 0 {
		return nil
	}
	ext := extension(name)
	for _, h := range knownHeaders {
		for _, x := range h.extensions {
			if ext == x && (len(data)-h.size)%h.multiple == 0 {
				return &HeaderInfo{Name: h.name, Size: h.size}
			}
		}
	}
	return nil
}
func RemoveHeader(data []byte, name string) (header, rom []byte, info *HeaderInfo) {
	info = DetectHeader(data, name)
	if info == nil {
		return nil, data, nil
	}
	return append([]byte(nil), data[:info.Size]...), append([]byte(nil), data[info.Size:]...), info
}
func AddHeader(data []byte, name string) ([]byte, *HeaderInfo) {
	info := CanAddHeader(data, name)
	if info == nil {
		return data, nil
	}
	out := make([]byte, info.Size+len(data))
	copy(out[info.Size:], data)
	if extension(name) == "fds" {
		copy(out, []byte{'F', 'D', 'S', 0x1a, byte(len(data) / 65500)})
	}
	return out, info
}

var gameBoyLogo = []byte{0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b, 0x03, 0x73, 0x00, 0x83, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x08, 0x11, 0x1f, 0x88, 0x89, 0x00, 0x0e, 0xdc, 0xcc, 0x6e, 0xe6, 0xdd, 0xdd, 0xd9, 0x99}

func romSystem(data []byte, name string) string {
	ext := extension(name)
	if (ext == "gb" || ext == "gbc") && len(data) >= 0x124 && len(data)%0x4000 == 0 && bytes.Equal(data[0x104:0x124], gameBoyLogo) {
		return "gb"
	}
	if (ext == "md" || ext == "bin") && len(data) >= 0x200 && (bytes.HasPrefix(data[0x100:], []byte("SEGA GENESIS")) || bytes.HasPrefix(data[0x100:], []byte("SEGA MEGA DR"))) {
		return "smd"
	}
	if ext == "z64" && len(data) >= 0x400000 {
		return "n64"
	}
	if ext == "fds" && (len(data)%65500 == 0 || (len(data) >= 16 && (len(data)-16)%65500 == 0)) {
		return "fds"
	}
	return ""
}
func FixROMChecksum(data []byte, name string) bool {
	switch romSystem(data, name) {
	case "gb":
		if len(data) < 0x14e {
			return false
		}
		var sum byte
		for _, b := range data[0x134:0x14d] {
			sum = sum - b - 1
		}
		if data[0x14d] != sum {
			data[0x14d] = sum
			return true
		}
	case "smd":
		if len(data) < 0x200 {
			return false
		}
		var sum uint16
		for i := 0x200; i+1 < len(data); i += 2 {
			sum += uint16(data[i])<<8 | uint16(data[i+1])
		}
		current := uint16(data[0x18e])<<8 | uint16(data[0x18f])
		if current != sum {
			data[0x18e], data[0x18f] = byte(sum>>8), byte(sum)
			return true
		}
	}
	return false
}
func AdditionalChecksum(data []byte, name string) string {
	if romSystem(data, name) == "n64" && len(data) >= 0x3f {
		return fmt.Sprintf("%s (%x)", data[0x3c:0x3f], data[0x10:0x18])
	}
	return ""
}

func ApplyWithOptions(source, patchData []byte, opts ApplyOptions) ([]byte, error) {
	return Apply(source, patchData, opts)
}
func ApplyParsedWithOptions(source []byte, p Patch, opts ApplyOptions) ([]byte, error) {
	if opts.RemoveHeader && opts.AddHeader {
		return nil, errors.New("remove-header and add-header cannot be used together")
	}
	if err := reportProgress(opts, Progress{Phase: "prepare", Format: p.Format(), Total: int64(len(source))}); err != nil {
		return nil, err
	}
	working := source
	var header []byte
	fake := 0
	if opts.RemoveHeader {
		h, rom, _ := RemoveHeader(source, opts.SourceName)
		if h != nil {
			header = h
			working = rom
		}
	} else if opts.AddHeader {
		with, info := AddHeader(source, opts.SourceName)
		if info != nil {
			working = with
			fake = info.Size
		}
	}
	applyOptions := opts
	// MaxOutputSize describes the final output. A temporary compatibility
	// header is removed after patching, so allow that header only during the
	// intermediate apply step and enforce the caller's limit again below.
	if fake > 0 && applyOptions.MaxOutputSize != 0 {
		if applyOptions.MaxOutputSize > ^uint64(0)-uint64(fake) {
			applyOptions.MaxOutputSize = ^uint64(0)
		} else {
			applyOptions.MaxOutputSize += uint64(fake)
		}
	}
	out, e := p.Apply(working, applyOptions)
	if e != nil {
		return nil, e
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
	if e = reportProgress(opts, Progress{Phase: "complete", Format: p.Format(), Completed: int64(len(out)), Total: int64(len(out))}); e != nil {
		return nil, e
	}
	return out, nil
}
