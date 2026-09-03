package rompatcher

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ulikunitz/xz"
)

func xzSyncFlushFixture(t *testing.T, raw []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	w, err := (xz.WriterConfig{DictCap: 4096, NoCheckSum: true}).NewWriter(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	b := encoded.Bytes()
	off := 12 + (int(b[12])+1)*4
	for off < len(b) {
		control := b[off]
		if control == 0 {
			return append([]byte(nil), b[:off]...)
		}
		switch {
		case control == 1 || control == 2:
			if off+3 > len(b) {
				t.Fatal("short uncompressed LZMA2 chunk")
			}
			size := int(b[off+1])<<8 | int(b[off+2])
			off += 3 + size + 1
		case control >= 0x80:
			if off+5 > len(b) {
				t.Fatal("short compressed LZMA2 chunk")
			}
			size := int(b[off+3])<<8 | int(b[off+4])
			header := 5
			if control >= 0xc0 {
				header++
			}
			off += header + size + 1
		default:
			t.Fatalf("invalid LZMA2 control byte 0x%02x", control)
		}
	}
	t.Fatal("missing LZMA2 end marker")
	return nil
}

func TestVCDIFFLZMASecondary(t *testing.T) {
	data := []byte("XYZ")
	compressed := appendBE7(nil, uint64(len(data)))
	compressed = append(compressed, xzSyncFlushFixture(t, data)...)
	inst := []byte{4, 19, 3}
	addr := []byte{0}
	patch := []byte{0xd6, 0xc3, 0xc4, 0, vcdDecompress, vcdLZMASecondaryID, vcdSource}
	patch = appendBE7(patch, 6)
	patch = appendBE7(patch, 0)
	patch = appendVCDDelta(patch, 6, 0x01, compressed, inst, addr)

	p, err := Parse(patch)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Apply([]byte("abcdef"), ApplyOptions{Validate: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "XYZabc" {
		t.Fatalf("got %q", got)
	}
	assertReaderAtApply(t, []byte("abcdef"), patch, []byte("XYZabc"), true)
	if _, err := p.Apply([]byte("abcdef"), ApplyOptions{MaxOutputSize: 1024}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("dictionary limit error = %v", err)
	}
}
