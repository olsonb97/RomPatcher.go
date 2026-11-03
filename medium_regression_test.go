package rompatcher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEBPMetadataLimit(t *testing.T) {
	metadata := []byte("PATCHEOF{\"x\":\"" + strings.Repeat("a", maxEBPMetadataSize) + "\"}")
	if _, err := Parse(metadata); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("Parse error = %v", err)
	}
	if _, err := Apply(nil, metadata, ApplyOptions{}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("Apply error = %v", err)
	}
	if _, err := Create([]byte("a"), []byte("b"), FormatEBP, &CreateOptions{Metadata: map[string]string{"x": strings.Repeat("a", maxEBPMetadataSize)}}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("Create error = %v", err)
	}
}

func TestPPF2UsesLittleEndianSourceSize(t *testing.T) {
	source := make([]byte, 40000)
	b := append([]byte("PPF20"), 1)
	b = append(b, make([]byte, 50)...)
	b = appendU32LE(b, uint32(len(source)))
	b = append(b, make([]byte, 1024)...)
	b = appendU32LE(b, 0)
	b = append(b, 1, 'x')
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.(*PPFPatch).InputSize != uint32(len(source)) {
		t.Fatalf("input size = %d", p.(*PPFPatch).InputSize)
	}
	if _, err = Apply(source, b, ApplyOptions{Validate: true}); err != nil {
		t.Fatal(err)
	}
}

func TestPPFUndoSkipsAmbiguousRecords(t *testing.T) {
	p := &PPFPatch{Version: 3, Undo: true, records: []ppfRecord{
		{offset: 0, data: []byte("a"), undo: []byte("a")},
		{offset: 1, data: []byte("X"), undo: []byte("b")},
	}}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply([]byte("abc"), b, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "aXc" {
		t.Fatalf("output = %q", got)
	}
	assertReaderAtApply(t, []byte("abc"), b, []byte("aXc"), false)
}

func TestPPF3AcceptsPaddedFileIDFooter(t *testing.T) {
	p := &PPFPatch{Version: 3, FileID: "description", records: []ppfRecord{{offset: 0, data: []byte("x")}}}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, 0, 0)
	if _, err := Parse(b); err != nil {
		t.Fatal(err)
	}
	assertReaderAtApply(t, []byte("a"), b, []byte("x"), false)
}

func TestBSDIFFAcceptsSeekOnlyTuple(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString("QlNESUZGNDAsAAAAAAAAACUAAAAAAAAAAQAAAAAAAABCWmg5MUFZJlNZ7YxfqgAAAOAAaAQIACAAIYNBmghK0gr4u5IpwoSHbGL9UEJaaDkxQVkmU1mx90BLAAAAQABAACAAIRhGgu5IpwoSFj7oCWBCWmg5F3JFOFCQAAAAAA==")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply([]byte("ab"), b, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "b" {
		t.Fatalf("output = %q", got)
	}
}

type cancelTargetWriter struct {
	memoryFile
	cancel context.CancelFunc
}

func (w *cancelTargetWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := w.memoryFile.WriteAt(p, off)
	if off == 1 {
		w.cancel()
	}
	return n, err
}

func TestBPSTargetCopyChecksCancellationPerChunk(t *testing.T) {
	p := &BPSPatch{TargetSize: 8 << 20, actions: []bpsAction{
		{typ: bpsTargetRead, length: 1, data: []byte("a")},
		{typ: bpsTargetCopy, length: (8 << 20) - 1},
	}}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &cancelTargetWriter{cancel: cancel}
	if _, err = ApplyReaderAt(ctx, bytes.NewReader(nil), 0, bytes.NewReader(b), int64(len(b)), out, ApplyOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
	if len(out.data) > 1+fileChunkSize {
		t.Fatalf("wrote %d bytes after cancellation", len(out.data))
	}
}

func TestVCDIFFLZMARejectsExtraDecodedData(t *testing.T) {
	section := append(appendBE7(nil, 1), xzSyncFlushFixture(t, []byte("abc"))...)
	if _, err := new(vcdLZMADecoder).decode(section, ApplyOptions{MaxOutputSize: 1 << 20}, 0, 1); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("error = %v", err)
	}
}

func TestVCDIFFLZMAAcceptsOptionalBlockSizes(t *testing.T) {
	compressed := xzSyncFlushFixture(t, []byte("a"))
	copy(compressed[12:20], []byte{2, 0x80, 1, 0x21, 1, 0, 0, 0})
	binary.LittleEndian.PutUint32(compressed[20:24], crc32.ChecksumIEEE(compressed[12:20]))
	out, err := new(vcdLZMADecoder).decode(append(appendBE7(nil, 1), compressed...), ApplyOptions{MaxOutputSize: 1 << 20}, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "a" {
		t.Fatalf("output = %q", out)
	}
}

func TestVCDIFFLZMAHandlesLargeChunkSize(t *testing.T) {
	raw := bytes.Repeat([]byte("0123456789abcdef"), 16<<10)
	section := appendBE7(nil, uint64(len(raw)))
	section = append(section, xzSyncFlushFixture(t, raw)...)
	out, err := new(vcdLZMADecoder).decode(section, ApplyOptions{MaxOutputSize: 1 << 20}, 0, uint64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("large LZMA2 chunk output mismatch")
	}
}

func TestVCDIFFLZMAContinuesAcrossSections(t *testing.T) {
	raw := bytes.Repeat([]byte("0123456789abcdef"), 192<<10)
	compressed := xzSyncFlushFixture(t, raw)
	off := 12 + (int(compressed[12])+1)*4
	control := compressed[off]
	if control < 0x80 {
		t.Fatalf("first LZMA2 chunk control = 0x%02x", control)
	}
	header := 5
	if control >= 0xc0 {
		header++
	}
	compressedSize := int(compressed[off+3])<<8 | int(compressed[off+4])
	firstEnd := off + header + compressedSize + 1
	if firstEnd >= len(compressed) {
		t.Fatal("fixture did not produce multiple LZMA2 chunks")
	}
	firstSize := int(control&0x1f)<<16 | int(compressed[off+1])<<8 | int(compressed[off+2])
	firstSize++
	d := new(vcdLZMADecoder)
	first := appendBE7(nil, uint64(firstSize))
	first = append(first, compressed[:firstEnd]...)
	firstOut, err := d.decode(first, ApplyOptions{MaxOutputSize: 8 << 20}, 0, uint64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	second := appendBE7(nil, uint64(len(raw)-firstSize))
	second = append(second, compressed[firstEnd:]...)
	secondOut, err := d.decode(second, ApplyOptions{MaxOutputSize: 8 << 20}, 0, uint64(len(raw)-firstSize))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(firstOut, secondOut...), raw) {
		t.Fatal("continued LZMA2 output mismatch")
	}
}

func TestAPSGBAApplyRejectsStructurallyInvalidRecord(t *testing.T) {
	b := appendU32LE([]byte("APS1"), 0)
	b = appendU32LE(b, apsGBABlockSize)
	b = appendU32LE(b, 0)
	b = appendU16LE(b, 0)
	b = appendU16LE(b, 0)
	b = append(b, make([]byte, apsGBABlockSize)...)
	if _, err := Parse(b); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("Parse error = %v", err)
	}
	if _, err := Apply(make([]byte, apsGBABlockSize), b, ApplyOptions{}); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("Apply error = %v", err)
	}
}

func TestRUPValidateSourceRequiresMatchingSize(t *testing.T) {
	p := &RUPPatch{files: []rupFile{{SourceSize: 2, TargetSize: 2, SourceMD5: MD5([]byte("x")), TargetMD5: MD5([]byte("yy"))}}}
	if p.ValidateSource([]byte("x")) {
		t.Fatal("accepted checksum with the wrong endpoint size")
	}
}

func TestIPSRejectsMetadataWithTruncation(t *testing.T) {
	p := &IPSPatch{HasTruncate: true, Truncate: 1, Metadata: map[string]string{"Title": "test"}}
	if _, err := p.MarshalBinary(); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("error = %v", err)
	}
}

func TestFileCompleteProgressFollowsPublication(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.bin")
	patchPath := filepath.Join(dir, "patch.ips")
	outputPath := filepath.Join(dir, "output.bin")
	if err := os.WriteFile(sourcePath, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchPath, []byte("PATCHEOF"), 0o600); err != nil {
		t.Fatal(err)
	}
	complete := false
	if err := ApplyFile(sourcePath, patchPath, outputPath, ApplyOptions{Progress: func(p Progress) {
		if p.Phase == "complete" {
			complete = true
			if got, err := os.ReadFile(outputPath); err != nil || string(got) != "abc" {
				t.Errorf("published output = %q, %v", got, err)
			}
		}
	}}); err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("missing complete progress")
	}
}

func TestCreateFileCompleteProgressFollowsPublication(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "original.bin")
	modifiedPath := filepath.Join(dir, "modified.bin")
	patchPath := filepath.Join(dir, "output.ips")
	if err := os.WriteFile(originalPath, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modifiedPath, []byte("axc"), 0o600); err != nil {
		t.Fatal(err)
	}
	complete := false
	err := CreateFile(originalPath, modifiedPath, patchPath, FormatIPS, &CreateOptions{Progress: func(p Progress) {
		if p.Phase == "complete" {
			complete = true
			if _, err := os.Stat(patchPath); err != nil {
				t.Errorf("published patch: %v", err)
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("missing complete progress")
	}
}

func TestFileChainCompleteProgressFollowsPublication(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.bin")
	patchPath := filepath.Join(dir, "patch.ips")
	outputPath := filepath.Join(dir, "output.bin")
	if err := os.WriteFile(sourcePath, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchPath, []byte("PATCHEOF"), 0o600); err != nil {
		t.Fatal(err)
	}
	complete := false
	_, err := ApplyFileChain(sourcePath, []string{patchPath}, outputPath, ApplyOptions{Progress: func(p Progress) {
		if p.Phase == "complete" {
			complete = true
			if _, err := os.Stat(outputPath); err != nil {
				t.Errorf("published chain output: %v", err)
			}
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("missing complete progress")
	}
}
