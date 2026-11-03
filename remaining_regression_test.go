package rompatcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ulikunitz/xz/lzma"
)

func TestVCDIFFLZMAValidatesEveryBlockDictionary(t *testing.T) {
	firstSection := xzSyncFlushFixture(t, []byte("a"))
	first := append([]byte(nil), firstSection...)
	first = append(first, 0)
	for (len(first)-12)%4 != 0 {
		first = append(first, 0)
	}
	second := xzSyncFlushFixture(t, []byte("b"))[12:]
	second[4] = lzma.EncodeDictCap(8 << 20)
	headerSize := (int(second[0]) + 1) * 4
	binary.LittleEndian.PutUint32(second[headerSize-4:headerSize], crc32.ChecksumIEEE(second[:headerSize-4]))
	section := appendBE7(nil, 2)
	section = append(section, first...)
	section = append(section, second...)
	out, err := new(vcdLZMADecoder).decode(section, ApplyOptions{MaxDictionarySize: 16 << 20}, 0, 2)
	if err != nil || string(out) != "ab" {
		t.Fatalf("valid multi-block output = %q, %v", out, err)
	}
	if _, err := new(vcdLZMADecoder).decode(section, ApplyOptions{MaxDictionarySize: 1 << 20}, 0, 2); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("error = %v", err)
	}
	d := new(vcdLZMADecoder)
	firstInput := appendBE7(nil, 1)
	firstInput = append(firstInput, firstSection...)
	if out, err := d.decode(firstInput, ApplyOptions{MaxDictionarySize: 16 << 20}, 0, 1); err != nil || string(out) != "a" {
		t.Fatalf("first window output = %q, %v", out, err)
	}
	secondInput := appendBE7(nil, 1)
	secondInput = append(secondInput, first[len(firstSection):]...)
	secondInput = append(secondInput, second...)
	if out, err := d.decode(secondInput, ApplyOptions{MaxDictionarySize: 16 << 20}, 0, 1); err != nil || string(out) != "b" {
		t.Fatalf("second window output = %q, %v", out, err)
	}
}

func TestVCDIFFLZMAAllocatesDeclaredDictionary(t *testing.T) {
	section := appendBE7(nil, 1)
	section = append(section, xzSyncFlushFixture(t, []byte("x"))...)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	d := new(vcdLZMADecoder)
	if _, err := d.decode(section, ApplyOptions{}, 8<<20, 1); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(d)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Fatalf("one-byte section allocated %d bytes", allocated)
	}
}

func TestBPSParseKeepsCompactEncodedActions(t *testing.T) {
	const count = 1 << 18
	b := appendBPSVLV([]byte("BPS1"), count)
	b = appendBPSVLV(b, count)
	b = appendBPSVLV(b, 0)
	b = append(b, bytes.Repeat([]byte{0x80}, count)...)
	b = append(b, make([]byte, 8)...)
	b = appendU32LE(b, CRC32(b))
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	bps := p.(*BPSPatch)
	if len(bps.actions) != 0 || bps.actionCount != count || len(bps.encodedActions) != count {
		t.Fatalf("actions=%d count=%d encoded=%d", len(bps.actions), bps.actionCount, len(bps.encodedActions))
	}
	encoded, err := bps.MarshalBinary()
	if err != nil || !bytes.Equal(encoded, b) {
		t.Fatalf("compact round trip: %v", err)
	}
}

func TestAPSN64RejectsUnsupportedHeaderValues(t *testing.T) {
	b := append([]byte("APS10"), 255, 255)
	b = append(b, make([]byte, 50)...)
	b = appendU32LE(b, 1)
	if _, err := Parse(b); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("Parse error = %v", err)
	}
	if _, err := Apply([]byte("a"), b, ApplyOptions{Validate: true}); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("Apply error = %v", err)
	}
	p := &APSN64Patch{HeaderType: 1, Encoding: 0, OriginalFormat: 2}
	if _, err := p.MarshalBinary(); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("Marshal error = %v", err)
	}
}

func TestEBPCreationPreservesDescription(t *testing.T) {
	p, err := Create([]byte("a"), []byte("b"), FormatEBP, &CreateOptions{Description: "requested description"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Description(), "Description: requested description") || strings.Contains(p.Description(), "No description") {
		t.Fatalf("description = %q", p.Description())
	}
}

func TestBPSVLVRejectsMultiplicationOverflow(t *testing.T) {
	encoded := append(make([]byte, 9), 0x82)
	if _, err := readBPSVLV(newDecoder(encoded)); !errors.Is(err, ErrInvalidPatch) || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("memory error = %v", err)
	}
	stream := newReaderDecoder(context.Background(), bytes.NewReader(encoded), int64(len(encoded)))
	if _, err := readBPSVLVReader(stream); !errors.Is(err, ErrInvalidPatch) || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("stream error = %v", err)
	}
}

func TestZIPContextAndExpansionLimit(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("game.gba")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("expanded")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "input.zip")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractZIPContext(context.Background(), path, "", InputSource, 3, io.Discard); err == nil {
		t.Fatal("oversized ZIP entry was extracted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	if _, err := ExtractZIPContext(ctx, path, "", InputSource, 1<<20, &output); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("wrote %d bytes after cancellation", output.Len())
	}
}
