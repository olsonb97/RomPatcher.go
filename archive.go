package rompatcher

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// InputKind controls which ZIP entries are considered candidates.
type InputKind string

const (
	// InputSource selects likely source-ROM entries.
	InputSource InputKind = "source"
	// InputPatch selects recognized patch entries.
	InputPatch InputKind = "patch"
	// InputAny permits any regular ZIP entry.
	InputAny InputKind = "file"
)

// ArchiveEntry describes a selectable file inside a ZIP archive.
type ArchiveEntry struct {
	Name            string `json:"name"`
	Size            uint64 `json:"size"`
	CompressedSize  uint64 `json:"compressedSize"`
	PatchCandidate  bool   `json:"patchCandidate"`
	SourceCandidate bool   `json:"sourceCandidate"`
}

var patchExtensions = map[string]bool{
	".ips": true, ".ips32": true, ".ebp": true, ".ups": true, ".bps": true,
	".aps": true, ".rup": true, ".ppf": true, ".bdf": true, ".bspatch": true,
	".mod": true, ".vcdiff": true, ".xdelta": true, ".xdelta3": true,
}

var sourceExtensions = map[string]bool{
	".bin": true, ".rom": true, ".nes": true, ".fds": true, ".sfc": true,
	".smc": true, ".swc": true, ".fig": true, ".gb": true, ".gbc": true,
	".gba": true, ".z64": true, ".n64": true, ".v64": true, ".nds": true,
	".iso": true, ".img": true, ".cue": true, ".md": true, ".gen": true,
}

// ListZIP lists regular entries and their candidate classifications.
func ListZIP(path string) ([]ArchiveEntry, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return describeZIP(r.File), nil
}

// ListZIPBytes lists entries in an in-memory ZIP archive.
func ListZIPBytes(data []byte) ([]ArchiveEntry, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	return describeZIP(r.File), nil
}

func describeZIP(files []*zip.File) []ArchiveEntry {
	entries := make([]ArchiveEntry, 0, len(files))
	for _, f := range files {
		if f.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		entries = append(entries, ArchiveEntry{
			Name: f.Name, Size: f.UncompressedSize64, CompressedSize: f.CompressedSize64,
			PatchCandidate: patchExtensions[ext], SourceCandidate: sourceExtensions[ext],
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries
}

// ReadZIP selects and reads one ZIP entry. A zero maxSize means unlimited.
func ReadZIP(path, entry string, kind InputKind, maxSize uint64) ([]byte, string, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, "", err
	}
	defer r.Close()
	return selectZIP(r.File, entry, kind, maxSize)
}

// ExtractZIP selects one ZIP entry and streams it to dst without buffering the
// entry in memory.
func ExtractZIP(path, entry string, kind InputKind, maxSize uint64, dst io.Writer) (string, error) {
	if isNilInterface(dst) {
		return "", fmt.Errorf("destination writer must be non-nil")
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer r.Close()
	f, err := findZIP(r.File, entry, kind, maxSize)
	if err != nil {
		return "", err
	}
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	reader := io.Reader(rc)
	if maxSize != 0 && maxSize < uint64(^uint64(0)>>1) {
		reader = io.LimitReader(rc, int64(maxSize)+1)
	}
	n, err := io.Copy(dst, reader)
	if err != nil {
		return "", err
	}
	if maxSize != 0 && uint64(n) > maxSize {
		return "", errors.New("archive entry expanded beyond size limit")
	}
	if uint64(n) != f.UncompressedSize64 {
		return "", fmt.Errorf("archive entry size mismatch: got %d, expected %d", n, f.UncompressedSize64)
	}
	return f.Name, nil
}

// ReadZIPBytes selects and reads one entry from an in-memory ZIP archive.
func ReadZIPBytes(data []byte, entry string, kind InputKind, maxSize uint64) ([]byte, string, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, "", err
	}
	return selectZIP(r.File, entry, kind, maxSize)
}

func selectZIP(files []*zip.File, entry string, kind InputKind, maxSize uint64) ([]byte, string, error) {
	f, err := findZIP(files, entry, kind, maxSize)
	if err != nil {
		return nil, "", err
	}
	if f.UncompressedSize64 > uint64(int(^uint(0)>>1)) {
		return nil, "", fmt.Errorf("%w: archive entry is too large for memory: %d bytes", ErrOutputTooLarge, f.UncompressedSize64)
	}
	r, err := f.Open()
	if err != nil {
		return nil, "", err
	}
	defer r.Close()
	var reader io.Reader = r
	if maxSize != 0 && maxSize < uint64(^uint64(0)>>1) {
		reader = io.LimitReader(r, int64(maxSize)+1)
	}
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, "", err
	}
	if maxSize != 0 && uint64(len(b)) > maxSize {
		return nil, "", errors.New("archive entry expanded beyond size limit")
	}
	if uint64(len(b)) != f.UncompressedSize64 {
		return nil, "", fmt.Errorf("archive entry size mismatch: got %d, expected %d", len(b), f.UncompressedSize64)
	}
	return b, f.Name, nil
}

func findZIP(files []*zip.File, entry string, kind InputKind, maxSize uint64) (*zip.File, error) {
	switch kind {
	case InputSource, InputPatch, InputAny:
	default:
		return nil, fmt.Errorf("%w: unknown archive input kind %q", ErrUnsupported, kind)
	}
	var candidates []*zip.File
	for _, f := range files {
		if f.FileInfo().IsDir() {
			continue
		}
		if entry != "" {
			if f.Name == entry {
				candidates = append(candidates, f)
			}
			continue
		}
		ext := strings.ToLower(filepath.Ext(f.Name))
		if kind == InputAny || kind == InputPatch && patchExtensions[ext] || kind == InputSource && sourceExtensions[ext] {
			candidates = append(candidates, f)
		}
	}
	if len(candidates) == 0 {
		if entry != "" {
			return nil, fmt.Errorf("archive entry not found: %q", entry)
		}
		return nil, fmt.Errorf("archive has no %s candidate", kind)
	}
	if len(candidates) != 1 {
		names := make([]string, len(candidates))
		for i, f := range candidates {
			names[i] = strconv.Quote(f.Name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w for %s: %s", ErrAmbiguousArchive, kind, strings.Join(names, ", "))
	}
	f := candidates[0]
	if maxSize != 0 && f.UncompressedSize64 > maxSize {
		return nil, fmt.Errorf("archive entry exceeds size limit: %d > %d", f.UncompressedSize64, maxSize)
	}
	return f, nil
}
