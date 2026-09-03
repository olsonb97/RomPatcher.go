package rompatcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var testOriginal = []byte{98, 91, 64, 8, 35, 53, 122, 167, 52, 253, 222, 156, 247, 82, 227, 213, 22, 221, 17, 247, 107, 102, 164, 254, 221, 102, 207, 63, 117, 164, 223, 10, 223, 200, 150, 4, 77, 250, 111, 64, 233, 118, 1, 36, 1, 60, 208, 245, 136, 126, 29, 231, 168, 18, 125, 172, 11, 184, 81, 20, 16, 30, 154, 16, 236, 21, 5, 74, 255, 112, 171, 198, 185, 89, 2, 98, 45, 164, 214, 55, 103, 15, 217, 95, 212, 133, 184, 21, 67, 144, 198, 163, 76, 35, 248, 229, 163, 37, 103, 33, 193, 160, 161, 245, 125, 144, 193, 178, 31, 253, 119, 168, 169, 187, 195, 165, 205, 140, 222, 134, 249, 68, 224, 248, 144, 207, 18, 126}
var testModified = []byte{98, 91, 64, 8, 35, 53, 122, 167, 52, 253, 222, 156, 247, 82, 227, 213, 22, 221, 17, 247, 107, 102, 164, 254, 221, 8, 207, 63, 117, 164, 223, 10, 1, 77, 87, 123, 48, 9, 111, 64, 233, 118, 1, 36, 1, 60, 208, 245, 136, 126, 29, 231, 168, 18, 125, 172, 11, 184, 81, 20, 16, 30, 154, 16, 236, 21, 5, 74, 255, 112, 171, 198, 185, 89, 2, 98, 45, 164, 214, 55, 103, 15, 217, 95, 212, 133, 184, 21, 67, 144, 198, 163, 76, 35, 248, 229, 163, 37, 103, 33, 193, 96, 77, 255, 117, 89, 193, 61, 64, 253, 119, 82, 49, 187, 195, 165, 205, 140, 222, 134, 249, 68, 224, 248, 144, 207, 18, 126}

func TestHashes(t *testing.T) {
	if got := CRC32(testOriginal); got != 0x903a031b {
		t.Fatalf("CRC32=%08x", got)
	}
	if got := MD5(testOriginal); got != "55c76e7e683fd7cd63c673c5df3efa6e" {
		t.Fatalf("MD5=%s", got)
	}
	if got := Adler32(testOriginal); got != 0xef984205 {
		t.Fatalf("Adler32=%08x", got)
	}
	if got := CRC16(testOriginal); got != 0x96e4 {
		t.Fatalf("CRC16=%04x", got)
	}
}

func TestCreateMarshalParseApply(t *testing.T) {
	formats := []Format{FormatIPS, FormatEBP, FormatUPS, FormatBPS, FormatAPSN64, FormatPPF, FormatRUP}
	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			opts := &CreateOptions{Metadata: map[string]string{"Author": "test"}, Description: "test"}
			p, e := Create(testOriginal, testModified, format, opts)
			if e != nil {
				t.Fatal(e)
			}
			encoded, e := p.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			parsed, e := Parse(encoded)
			if e != nil {
				t.Fatal(e)
			}
			got, e := parsed.Apply(testOriginal, ApplyOptions{Validate: true})
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, testModified) {
				t.Fatalf("output mismatch")
			}
			if parsed.Format() != format {
				t.Fatalf("format=%s", parsed.Format())
			}
		})
	}
}

func TestRandomizedCreateApplyRoundTrips(t *testing.T) {
	rng := rand.New(rand.NewSource(0x524f4d))
	formats := []Format{FormatIPS, FormatIPS32, FormatEBP, FormatUPS, FormatBPS, FormatAPSN64, FormatRUP, FormatPPF}
	for iteration := 0; iteration < 100; iteration++ {
		original := make([]byte, rng.Intn(2048))
		modified := make([]byte, rng.Intn(2048))
		_, _ = rng.Read(original)
		_, _ = rng.Read(modified)
		copy(modified, original)
		for changes := 0; changes < 20 && len(modified) > 0; changes++ {
			modified[rng.Intn(len(modified))] = byte(rng.Intn(256))
		}
		for _, format := range formats {
			if len(modified) < len(original) && (format == FormatEBP || format == FormatPPF) {
				continue
			}
			patch, err := Create(original, modified, format, nil)
			if err != nil {
				t.Fatalf("iteration %d %s create: %v", iteration, format, err)
			}
			encoded, err := patch.MarshalBinary()
			if err != nil {
				t.Fatalf("iteration %d %s marshal: %v", iteration, format, err)
			}
			got, err := Apply(original, encoded, ApplyOptions{Validate: true})
			if err != nil {
				t.Fatalf("iteration %d %s apply: %v", iteration, format, err)
			}
			if !bytes.Equal(got, modified) {
				t.Fatalf("iteration %d %s output mismatch: got %d bytes, want %d", iteration, format, len(got), len(modified))
			}
		}
	}
}

func TestBPSReferenceChecksum(t *testing.T) {
	p, e := Create(testOriginal, testModified, FormatBPS, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, e := p.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	if got := CRC32(b); got != 0x2144df1c {
		t.Fatalf("BPS CRC32=%08x, want 2144df1c", got)
	}
}

func TestBPSLargeOverlappingTargetCopy(t *testing.T) {
	const size = 2<<20 + 17
	p := &BPSPatch{TargetSize: size, Actions: []bpsAction{
		{typ: bpsTargetRead, length: 1, data: []byte{'A'}},
		{typ: bpsTargetCopy, length: size - 1},
	}}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte{'A'}, size)
	got, err := Apply(nil, b, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("overlapping BPS target copy mismatch")
	}
	assertReaderAtApply(t, nil, b, want, false)
}

func TestResizeRoundTrips(t *testing.T) {
	cases := [][]byte{append(append([]byte{}, testModified...), 1, 2, 3, 0), append([]byte{}, testModified[:80]...), {}}
	for _, target := range cases {
		for _, format := range []Format{FormatIPS, FormatUPS, FormatBPS, FormatAPSN64, FormatRUP} {
			p, e := Create(testOriginal, target, format, nil)
			if e != nil {
				t.Fatalf("%s: %v", format, e)
			}
			b, e := p.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			got, e := Apply(testOriginal, b, ApplyOptions{Validate: true})
			if e != nil {
				t.Fatalf("%s: %v", format, e)
			}
			if !bytes.Equal(got, target) {
				t.Fatalf("%s resized output mismatch", format)
			}
		}
	}
}

func TestCreateRejectsUnrepresentableShrink(t *testing.T) {
	for _, format := range []Format{FormatEBP, FormatPPF} {
		if _, err := Create([]byte{1, 2}, []byte{1}, format, nil); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s shrink error = %v", format, err)
		}
	}
}

func TestRUPUndo(t *testing.T) {
	p := createRUP(testOriginal, testModified, "")
	patched, err := p.Apply(testOriginal, ApplyOptions{Validate: true})
	if err != nil {
		t.Fatal(err)
	}
	unpatched, err := p.Apply(patched, ApplyOptions{Validate: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpatched, testOriginal) {
		t.Fatal("RUP undo mismatch")
	}
}

func TestRUPSelectsMatchingFileWithoutValidation(t *testing.T) {
	first := createRUP([]byte("first source"), []byte("first target"), "")
	secondSource, secondTarget := []byte("second source"), []byte("second target")
	second := createRUP(secondSource, secondTarget, "")
	patch := &RUPPatch{Files: []rupFile{first.Files[0], second.Files[0]}}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(secondSource, encoded, ApplyOptions{})
	if err != nil || !bytes.Equal(got, secondTarget) {
		t.Fatalf("multi-file RUP selection: %v, %q", err, got)
	}
	assertReaderAtApply(t, secondSource, encoded, secondTarget, false)
	got, err = Apply(secondTarget, encoded, ApplyOptions{})
	if err != nil || !bytes.Equal(got, secondSource) {
		t.Fatalf("multi-file RUP reverse selection: %v, %q", err, got)
	}
}

func TestUPSUndo(t *testing.T) {
	for _, target := range [][]byte{testModified, append(append([]byte(nil), testModified...), 1, 2, 3)} {
		patch := createUPS(testOriginal, target)
		encoded, err := patch.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, err := Apply(target, encoded, ApplyOptions{Validate: true})
		if err != nil || !bytes.Equal(got, testOriginal) {
			t.Fatalf("UPS undo: %v", err)
		}
		assertReaderAtApply(t, target, encoded, testOriginal, true)
		if !patch.ValidateSource(target) || !InspectParsed(patch).Reversible {
			t.Fatal("UPS target was not recognized as a reversible input")
		}
	}
}

func TestAPSGBA(t *testing.T) {
	source := make([]byte, apsGBABlockSize)
	for i := range source {
		source[i] = byte(i * 31)
	}
	target := append([]byte(nil), source...)
	target[4] ^= 0x55
	target[60000] ^= 0xaa
	xor := make([]byte, len(source))
	for i := range xor {
		xor[i] = source[i] ^ target[i]
	}
	p := &APSGBAPatch{SourceSize: uint32(len(source)), TargetSize: uint32(len(target)), Records: []apsGBARecord{{sourceCRC: CRC16(source), targetCRC: CRC16(target), xor: xor}}}
	b, e := p.MarshalBinary()
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	got, e := parsed.Apply(source, ApplyOptions{Validate: true})
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, target) {
		t.Fatal("APS GBA output mismatch")
	}
	assertReaderAtApply(t, source, b, target, true)
	empty := append([]byte("APS1"), make([]byte, 8)...)
	parsed, e = Parse(empty)
	if e != nil {
		t.Fatal(e)
	}
	got, e = parsed.Apply(nil, ApplyOptions{Validate: true})
	if e != nil || len(got) != 0 {
		t.Fatalf("empty APS GBA patch: %v", e)
	}
}

func TestPMSR(t *testing.T) {
	patch := append([]byte{}, "PMSR"...)
	patch = appendU32BE(patch, 1)
	patch = appendU32BE(patch, 2)
	patch = appendU32BE(patch, 3)
	patch = append(patch, 'x', 'y', 'z')
	p, e := Parse(patch)
	if e != nil {
		t.Fatal(e)
	}
	got, e := p.Apply([]byte("abcdef"), ApplyOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if string(got[:6]) != "abxyzf" {
		t.Fatalf("got %q", got[:6])
	}
}

func TestBSDIFF(t *testing.T) {
	const fixture = "QlNESUZGNDAoAAAAAAAAACUAAAAAAAAABgAAAAAAAABCWmg5MUFZJlNZj3vkXQAABEAASAggADDMCTIiao4u5IpwoSEe98i6QlpoOTFBWSZTWUxan0gAAABAAGAAIAAhAIKMXckU4UJBMWp9IEJaaDkxQVkmU1lzpAd3AAAAAgAAcCAAIZgZhGF3JFOFCQc6QHdw"
	b, e := base64.StdEncoding.DecodeString(fixture)
	if e != nil {
		t.Fatal(e)
	}
	p, e := Parse(b)
	if e != nil {
		t.Fatal(e)
	}
	got, e := p.Apply([]byte("abc"), ApplyOptions{Validate: true})
	if e != nil {
		t.Fatal(e)
	}
	if string(got) != "abdXYZ" {
		t.Fatalf("got %q", got)
	}
	assertReaderAtApply(t, []byte("abc"), b, []byte("abdXYZ"), true)
	if _, err := p.Apply([]byte("abc"), ApplyOptions{MaxOutputSize: 5}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("BSDIFF limit error = %v", err)
	}
}

func appendBE7(dst []byte, v uint64) []byte {
	var buf [10]byte
	i := len(buf)
	buf[i-1] = byte(v & 0x7f)
	i--
	for v >>= 7; v > 0; v >>= 7 {
		i--
		buf[i] = byte(v&0x7f) | 0x80
	}
	return append(dst, buf[i:]...)
}

func appendVCDDelta(dst []byte, targetLength uint64, indicator byte, data, instructions, addresses []byte) []byte {
	delta := appendBE7(nil, targetLength)
	delta = append(delta, indicator)
	delta = appendBE7(delta, uint64(len(data)))
	delta = appendBE7(delta, uint64(len(instructions)))
	delta = appendBE7(delta, uint64(len(addresses)))
	delta = append(delta, data...)
	delta = append(delta, instructions...)
	delta = append(delta, addresses...)
	dst = appendBE7(dst, uint64(len(delta)))
	return append(dst, delta...)
}

func TestVCDIFF(t *testing.T) {
	data := []byte("XYZ")
	inst := []byte{4, 19, 3}
	addr := []byte{0}
	patch := []byte{0xd6, 0xc3, 0xc4, 0, 0}
	patch = append(patch, vcdSource)
	patch = appendBE7(patch, 6)
	patch = appendBE7(patch, 0)
	patch = appendVCDDelta(patch, 6, 0, data, inst, addr)
	p, e := Parse(patch)
	if e != nil {
		t.Fatal(e)
	}
	got, e := p.Apply([]byte("abcdef"), ApplyOptions{Validate: true})
	if e != nil {
		t.Fatal(e)
	}
	if string(got) != "XYZabc" {
		t.Fatalf("got %q", got)
	}
	assertReaderAtApply(t, []byte("abcdef"), patch, []byte("XYZabc"), true)
	badLength := append([]byte(nil), patch...)
	d := newDecoder(badLength)
	_ = d.seek(6)
	_, _ = readBE7(d)
	_, _ = readBE7(d)
	badLength[d.off]++
	badPatch, err := Parse(badLength)
	if err == nil {
		_, err = badPatch.Apply([]byte("abcdef"), ApplyOptions{})
	}
	if !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("VCDIFF delta length error = %v", err)
	}

	// Declaring a secondary compressor is valid when no section uses it.
	declared := append([]byte(nil), patch[:4]...)
	declared = append(declared, vcdDecompress, 2)
	declared = append(declared, patch[5:]...)
	p, e = Parse(declared)
	if e != nil {
		t.Fatal(e)
	}
	got, e = p.Apply([]byte("abcdef"), ApplyOptions{})
	if e != nil || string(got) != "XYZabc" {
		t.Fatalf("declared secondary compressor: %q, %v", got, e)
	}
	declared[11] = 1 // Mark the data section as LZMA-compressed.
	p, e = Parse(declared)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Apply([]byte("abcdef"), ApplyOptions{}); !errors.Is(e, ErrInvalidPatch) {
		t.Fatalf("compressed section error = %v", e)
	}
}

func TestVCDIFFCustomCodeTable(t *testing.T) {
	rawTable := encodeVCDTable(vcdTable)
	nestedInst := []byte{1}
	nestedInst = appendBE7(nestedInst, uint64(len(rawTable)))
	nested := []byte{0xd6, 0xc3, 0xc4, 0, 0, 0}
	nested = appendVCDDelta(nested, uint64(len(rawTable)), 0, rawTable, nestedInst, nil)

	patch := []byte{0xd6, 0xc3, 0xc4, 0, vcdCodeTable}
	patch = appendBE7(patch, uint64(len(nested)+2))
	patch = append(patch, 4, 3)
	patch = append(patch, nested...)
	data := []byte("custom")
	inst := []byte{1}
	inst = appendBE7(inst, uint64(len(data)))
	patch = append(patch, 0)
	patch = appendVCDDelta(patch, uint64(len(data)), 0, data, inst, nil)

	p, err := Parse(patch)
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Apply(nil, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "custom" {
		t.Fatalf("got %q", out)
	}
}

func TestHeaderAndChecksum(t *testing.T) {
	rom := make([]byte, 0x8000)
	copy(rom[0x104:], gameBoyLogo)
	rom[0x134] = 1
	if CanAddHeader(rom, "game.nes") == nil {
		t.Fatal("expected iNES header support")
	}
	headered, _ := AddHeader(rom, "game.nes")
	if DetectHeader(headered, "game.nes") == nil {
		t.Fatal("header not detected")
	}
	if !FixROMChecksum(rom, "game.gb") {
		t.Fatal("checksum was not fixed")
	}
}

func TestTemporaryHeaders(t *testing.T) {
	plain := make([]byte, 1024)
	modified := append([]byte(nil), plain...)
	modified[10] = 7
	patch, err := Create(plain, modified, FormatIPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	patchBytes, _ := patch.MarshalBinary()
	headered, _ := AddHeader(plain, "game.nes")
	headered[0] = 0x4e
	got, err := Apply(headered, patchBytes, ApplyOptions{RemoveHeader: true, SourceName: "game.nes"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x4e || !bytes.Equal(got[16:], modified) {
		t.Fatal("temporary header removal mismatch")
	}

	fakeOriginal, _ := AddHeader(plain, "game.nes")
	fakeModified := append([]byte(nil), fakeOriginal...)
	fakeModified[16+20] = 9
	patch, err = Create(fakeOriginal, fakeModified, FormatIPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	patchBytes, _ = patch.MarshalBinary()
	got, err = Apply(plain, patchBytes, ApplyOptions{AddHeader: true, SourceName: "game.nes"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(plain) || got[20] != 9 {
		t.Fatal("temporary header addition mismatch")
	}
}

func TestBadChecksums(t *testing.T) {
	p := createUPS(testOriginal, testModified)
	b, _ := p.MarshalBinary()
	b[len(b)-1] ^= 1
	if _, e := Parse(b); !errors.Is(e, ErrPatchMismatch) {
		t.Fatalf("got %v", e)
	}
}

func TestOutputLimit(t *testing.T) {
	p := &BPSPatch{TargetSize: 1024}
	if _, err := p.Apply(nil, ApplyOptions{MaxOutputSize: 100}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestMalformedArithmeticAndMetadata(t *testing.T) {
	ups := &UPSPatch{TargetSize: 1, Records: []upsRecord{{offset: ^uint64(0), xor: []byte{1, 2}}}}
	if _, err := ups.Apply(nil, ApplyOptions{}); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("UPS overflow error = %v", err)
	}
	ebp := &IPSPatch{Metadata: map[string]string{"": "ignored", "title": "safe"}}
	if got := ebp.Description(); got != "Title: safe" {
		t.Fatalf("EBP description = %q", got)
	}
}

func TestIPS32FinalProgressCancellation(t *testing.T) {
	p, err := Create(testOriginal, testModified, FormatIPS32, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err = p.Apply(testOriginal, ApplyOptions{Context: ctx, Progress: func(progress Progress) {
		if progress.Total > 0 && progress.Completed == progress.Total {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("final progress cancellation = %v", err)
	}
}

func TestHashReader(t *testing.T) {
	want := HashBytes(testOriginal)
	//lint:ignore SA1012 HashReader intentionally documents and supports a nil context.
	got, err := HashReader(nil, bytes.NewReader(testOriginal))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("stream hashes = %+v, want %+v", got, want)
	}
}

func TestAtomicConcurrentNoClobber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "winner.bin")
	inputs := [][]byte{[]byte("first"), []byte("second")}
	errs := make([]error, len(inputs))
	var wg sync.WaitGroup
	for i := range inputs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = WriteFileAtomic(path, inputs[i])
		}(i)
	}
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("atomic successes = %d; errors = %v", successes, errs)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, inputs[0]) && !bytes.Equal(got, inputs[1]) {
		t.Fatalf("partial atomic output %q", got)
	}
}

func TestFileAPI(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "original.bin")
	modifiedPath := filepath.Join(dir, "modified.bin")
	patchPath := filepath.Join(dir, "change.bps")
	outputPath := filepath.Join(dir, "output.bin")
	if err := os.WriteFile(originalPath, testOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modifiedPath, testModified, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateFile(originalPath, modifiedPath, patchPath, FormatBPS, nil); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFile(originalPath, patchPath, outputPath, ApplyOptions{Validate: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, testModified) {
		t.Fatal("file API output mismatch")
	}
}

func TestIPS32RoundTrip(t *testing.T) {
	p, err := Create(testOriginal, testModified, FormatIPS32, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("IPS32")) || !bytes.Contains(b, []byte("EEOF")) {
		t.Fatal("invalid IPS32 framing")
	}
	got, err := Apply(testOriginal, b, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, testModified) {
		t.Fatal("IPS32 output mismatch")
	}
}

func TestContextAndProgress(t *testing.T) {
	p, err := Create(testOriginal, testModified, FormatBPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.MarshalBinary()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Apply(testOriginal, b, ApplyOptions{Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	updates := 0
	if _, err := Apply(testOriginal, b, ApplyOptions{Progress: func(Progress) { updates++ }}); err != nil {
		t.Fatal(err)
	}
	if updates < 2 {
		t.Fatalf("only %d progress updates", updates)
	}
}

func TestReaderAtReportsCompletion(t *testing.T) {
	patch, err := Create(testOriginal, testModified, FormatBPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(filepath.Join(t.TempDir(), "output.bin"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	last := Progress{}
	size, err := ApplyReaderAt(context.Background(), bytes.NewReader(testOriginal), int64(len(testOriginal)), bytes.NewReader(encoded), int64(len(encoded)), out, ApplyOptions{Progress: func(progress Progress) { last = progress }})
	if err != nil {
		t.Fatal(err)
	}
	if last.Phase != "complete" || last.Completed != size || last.Total != size {
		t.Fatalf("last ReaderAt progress = %+v, output size %d", last, size)
	}
}

func TestInspectDryRunAndChain(t *testing.T) {
	p1, _ := Create(testOriginal, testModified, FormatUPS, nil)
	b1, _ := p1.MarshalBinary()
	i, err := Inspect(b1)
	if err != nil {
		t.Fatal(err)
	}
	if i.Format != FormatUPS || i.Source.Size == nil || *i.Source.Size != uint64(len(testOriginal)) || i.Target.Hashes["crc32"] == "" {
		t.Fatalf("incomplete inspection: %+v", i)
	}
	dry, err := DryRun(testOriginal, b1, ApplyOptions{Validate: true})
	if err != nil || dry.Output.Size == nil || *dry.Output.Size != uint64(len(testModified)) {
		t.Fatalf("dry run: %+v, %v", dry, err)
	}
	final := append([]byte(nil), testModified...)
	final[0] ^= 0xff
	p2, _ := Create(testModified, final, FormatBPS, nil)
	b2, _ := p2.MarshalBinary()
	chain, err := ApplyChain(testOriginal, [][]byte{b1, b2}, ApplyOptions{Validate: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(chain.Output, final) || len(chain.Steps) != 2 {
		t.Fatal("chain output mismatch")
	}
}

func TestChainRepairsChecksumOnlyAfterFinalPatch(t *testing.T) {
	original := make([]byte, 0x8000)
	copy(original[0x104:], gameBoyLogo)
	FixROMChecksum(original, "game.gb")
	intermediate := append([]byte(nil), original...)
	intermediate[0x134] = 1
	target := append([]byte(nil), intermediate...)
	target[0x200] = 2
	first, err := Create(original, intermediate, FormatIPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(intermediate, target, FormatBPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstData, _ := first.MarshalBinary()
	secondData, _ := second.MarshalBinary()
	result, err := ApplyChain(original, [][]byte{firstData, secondData}, ApplyOptions{Validate: true, FixChecksum: true, SourceName: "game.gb"})
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), target...)
	FixROMChecksum(want, "game.gb")
	if !bytes.Equal(result.Output, want) {
		t.Fatal("chain checksum repair did not run exclusively on final output")
	}
}

func TestZIPSelection(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range map[string][]byte{"a/game.gba": testOriginal, "b/game.gba": testModified, "patches/change.bps": []byte("BPS1")} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadZIPBytes(buf.Bytes(), "", InputSource, 0); !errors.Is(err, ErrAmbiguousArchive) {
		t.Fatalf("got %v", err)
	}
	got, name, err := ReadZIPBytes(buf.Bytes(), "b/game.gba", InputSource, 0)
	if err != nil || name != "b/game.gba" || !bytes.Equal(got, testModified) {
		t.Fatalf("selected %q: %v", name, err)
	}
	patch, name, err := ReadZIPBytes(buf.Bytes(), "", InputPatch, 0)
	if err != nil || name != "patches/change.bps" || string(patch) != "BPS1" {
		t.Fatalf("patch selection %q: %v", name, err)
	}
	zipPath := filepath.Join(t.TempDir(), "inputs.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var extracted bytes.Buffer
	name, err = ExtractZIP(zipPath, "a/game.gba", InputSource, 1<<20, &extracted)
	if err != nil || name != "a/game.gba" || !bytes.Equal(extracted.Bytes(), testOriginal) {
		t.Fatalf("stream extraction %q: %v", name, err)
	}

	var duplicate bytes.Buffer
	dzw := zip.NewWriter(&duplicate)
	for attempt := 0; attempt < 2; attempt++ {
		w, err := dzw.Create("same/game.gba")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(testOriginal)
	}
	if err := dzw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadZIPBytes(duplicate.Bytes(), "same/game.gba", InputSource, 0); !errors.Is(err, ErrAmbiguousArchive) {
		t.Fatalf("duplicate named ZIP entry error = %v", err)
	}
}

func TestReaderAtAndAtomicOutput(t *testing.T) {
	dir := t.TempDir()
	for _, format := range []Format{FormatIPS, FormatIPS32, FormatBPS, FormatUPS, FormatAPSN64, FormatPPF, FormatRUP} {
		p, _ := Create(testOriginal, testModified, format, nil)
		b, _ := p.MarshalBinary()
		outPath := filepath.Join(dir, "output."+string(format))
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		size, err := ApplyReaderAt(context.Background(), bytes.NewReader(testOriginal), int64(len(testOriginal)), bytes.NewReader(b), int64(len(b)), out, ApplyOptions{Validate: true})
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		got, _ := os.ReadFile(outPath)
		if size != int64(len(testModified)) || !bytes.Equal(got, testModified) {
			t.Fatalf("%s ReaderAt output mismatch", format)
		}
	}
	outPath := filepath.Join(dir, "output.ips")
	if err := WriteFileAtomic(outPath, []byte("replacement")); err == nil {
		t.Fatal("atomic output overwrote an existing file")
	}
	got, _ := os.ReadFile(outPath)
	if !bytes.Equal(got, testModified) {
		t.Fatal("existing output changed")
	}
}

func assertReaderAtApply(t *testing.T, source, patch, expected []byte, validate bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "output.bin")
	out, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	size, err := ApplyReaderAt(context.Background(), bytes.NewReader(source), int64(len(source)), bytes.NewReader(patch), int64(len(patch)), out, ApplyOptions{Validate: validate})
	if err == nil {
		err = out.Truncate(size)
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatalf("ReaderAt output mismatch: got %d bytes, want %d", len(got), len(expected))
	}
}

func assertReaderAtError(t *testing.T, source, patch []byte, validate bool) error {
	t.Helper()
	out, err := os.OpenFile(filepath.Join(t.TempDir(), "output.bin"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	//lint:ignore SA1012 ApplyReaderAt intentionally documents and supports a nil context.
	_, err = ApplyReaderAt(nil, bytes.NewReader(source), int64(len(source)), bytes.NewReader(patch), int64(len(patch)), out, ApplyOptions{Validate: validate})
	return err
}

func TestTruncatedIPSRejectsOutOfRangeRecords(t *testing.T) {
	cases := []Patch{
		&IPSPatch{Records: []ipsRecord{{offset: 2, data: []byte{1}}}, Truncate: 1, HasTruncate: true},
		&IPS32Patch{Records: []ipsRecord{{offset: 2, data: []byte{1}}}, Truncate: 1, HasTruncate: true},
	}
	for _, patch := range cases {
		t.Run(string(patch.Format()), func(t *testing.T) {
			encoded, err := patch.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Apply([]byte("source"), encoded, ApplyOptions{}); !errors.Is(err, ErrInvalidPatch) {
				t.Fatalf("memory error = %v", err)
			}
			if err = assertReaderAtError(t, []byte("source"), encoded, false); !errors.Is(err, ErrInvalidPatch) {
				t.Fatalf("ReaderAt error = %v", err)
			}
		})
	}
}

func TestIPSReservedEOFOffsetRoundTrip(t *testing.T) {
	const reserved = 0x454f46
	source := make([]byte, reserved+1)
	target := append([]byte(nil), source...)
	target[reserved] = 1
	patch, err := Create(source, target, FormatIPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(source, encoded, ApplyOptions{})
	if err != nil || !bytes.Equal(got, target) {
		t.Fatalf("reserved IPS offset round trip: %v", err)
	}
}

func TestEBPMetadataMustBeObject(t *testing.T) {
	if _, err := Parse([]byte("PATCHEOFnull")); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("null EBP metadata error = %v", err)
	}
	patch := &IPSPatch{Metadata: map[string]string{"éclair": "safe"}}
	if got := patch.Description(); got != "Éclair: safe" {
		t.Fatalf("Unicode EBP description = %q", got)
	}
}

func TestMalformedPositionArithmetic(t *testing.T) {
	bps := &BPSPatch{TargetSize: 10, Actions: []bpsAction{{typ: bpsSourceCopy, length: 10, relative: int64(^uint64(0)>>1) - 1}}}
	encoded, err := bps.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply([]byte("small"), encoded, ApplyOptions{}); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("BPS overflow error = %v", err)
	}

	bdf := &BDFPatch{TargetSize: 1, Records: []bdfRecord{{diff: []byte{0}, skip: int64(^uint64(0) >> 1)}}}
	if _, err = bdf.Apply(nil, ApplyOptions{}); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("BSDIFF overflow error = %v", err)
	}
	out, openErr := os.OpenFile(filepath.Join(t.TempDir(), "bdf.bin"), os.O_CREATE|os.O_RDWR, 0o600)
	if openErr != nil {
		t.Fatal(openErr)
	}
	_, _, err = applyBDFAt(bytes.NewReader(nil), 0, out, bdf, ApplyOptions{})
	_ = out.Close()
	if !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("BSDIFF ReaderAt overflow error = %v", err)
	}
}

func TestPPFValidationAndFileID(t *testing.T) {
	source := make([]byte, 0x9320+1024)
	patch := &PPFPatch{
		Version: 3, BlockCheck: append([]byte(nil), source[0x9320:]...), FileID: "metadata",
		Records: []ppfRecord{{offset: 0, data: []byte{'X'}}},
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), source...)
	want[0] = 'X'
	got, err := parsed.Apply(source, ApplyOptions{Validate: true})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("validated PPF apply: %v", err)
	}
	assertReaderAtApply(t, source, encoded, want, true)
	badSource := append([]byte(nil), source...)
	badSource[0x9320] = 1
	if _, err = parsed.Apply(badSource, ApplyOptions{Validate: true}); !errors.Is(err, ErrSourceMismatch) {
		t.Fatalf("PPF block validation error = %v", err)
	}
	badFooter := append([]byte(nil), encoded...)
	badFooter[len(badFooter)-2]++
	if _, err = Parse(badFooter); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("PPF footer error = %v", err)
	}
}

func TestStrictRUPAndVCDIFFStructure(t *testing.T) {
	rup := createRUP(testOriginal, testModified, "")
	encoded, err := rup.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(append(encoded, 1)); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("RUP trailing data error = %v", err)
	}
	rup.Files[0].Overflow = []byte{1}
	if _, err = rup.MarshalBinary(); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("RUP overflow structure error = %v", err)
	}

	vcd := []byte{0xd6, 0xc3, 0xc4, 0, 0, 0}
	vcd = appendVCDDelta(vcd, 1, 1, []byte{1}, []byte{2}, nil)
	if _, err = Parse(vcd); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("VCDIFF secondary declaration error = %v", err)
	}
	if _, err = Parse([]byte{0xd6, 0xc3, 0xc4, 0, vcdCodeTable, 0}); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("VCDIFF empty code table error = %v", err)
	}
}

func TestRUPAllowsResizedTailRecords(t *testing.T) {
	source, target := []byte{1, 2}, []byte{1, 2, 3, 4}
	patch := &RUPPatch{Files: []rupFile{{
		SourceSize: uint64(len(source)), TargetSize: uint64(len(target)),
		SourceMD5: MD5(source), TargetMD5: MD5(target), OverflowMode: 'A',
		Records: []rupRecord{{offset: 2, xor: []byte{3, 4}}},
	}}}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsed.Apply(source, ApplyOptions{Validate: true})
	if err != nil || !bytes.Equal(got, target) {
		t.Fatalf("forward resized-tail RUP: %v, %v", err, got)
	}
	got, err = parsed.Apply(target, ApplyOptions{Validate: true})
	if err != nil || !bytes.Equal(got, source) {
		t.Fatalf("reverse resized-tail RUP: %v, %v", err, got)
	}
	assertReaderAtApply(t, source, encoded, target, true)
	assertReaderAtApply(t, target, encoded, source, true)
}

func TestArchiveAnyAndLargeLimit(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("hello"))
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	got, name, err := ReadZIPBytes(archive.Bytes(), "", InputAny, ^uint64(0))
	if err != nil || name != "notes.txt" || string(got) != "hello" {
		t.Fatalf("generic archive selection %q: %q, %v", name, got, err)
	}
}

func TestUPSValidationIncludesSize(t *testing.T) {
	patch := &UPSPatch{SourceSize: uint64(len(testOriginal) + 1), TargetSize: uint64(len(testOriginal) + 2), SourceCRC: CRC32(testOriginal), TargetCRC: CRC32(testOriginal)}
	if patch.ValidateSource(testOriginal) {
		t.Fatal("UPS accepted the correct CRC with the wrong source size")
	}
	if _, err := patch.Apply(testOriginal, ApplyOptions{Validate: true}); !errors.Is(err, ErrSourceMismatch) {
		t.Fatalf("UPS source size error = %v", err)
	}
}

func TestMarshalRejectsLossyOrImpossibleValues(t *testing.T) {
	cases := []Patch{
		&IPSPatch{Truncate: -1, HasTruncate: true},
		&BPSPatch{Actions: []bpsAction{{typ: 9, length: 1}}},
		&PPFPatch{Version: 1, BlockCheck: make([]byte, 1024)},
		&PPFPatch{Version: 2, BlockCheck: make([]byte, 1024), Undo: true},
		&RUPPatch{},
	}
	if uint64(^uint(0)>>1) > uint64(^uint32(0)) {
		cases = append(cases, &APSN64Patch{Records: []apsRecord{{offset: int(uint64(^uint32(0)) + 1), data: []byte{1}}}})
	}
	for _, patch := range cases {
		if _, err := patch.MarshalBinary(); !errors.Is(err, ErrInvalidPatch) {
			t.Errorf("%T marshal error = %v", patch, err)
		}
	}
	if _, err := (&PMSRPatch{TargetSize: -1}).Apply(nil, ApplyOptions{}); !errors.Is(err, ErrInvalidPatch) {
		t.Fatalf("negative PMSR target error = %v", err)
	}
}

func TestTemporaryHeaderUsesFinalOutputLimit(t *testing.T) {
	source := make([]byte, 1024)
	patch := &IPSPatch{}
	out, err := ApplyParsedWithOptions(source, patch, ApplyOptions{AddHeader: true, SourceName: "game.nes", MaxOutputSize: uint64(len(source))})
	if err != nil || !bytes.Equal(out, source) {
		t.Fatalf("temporary header apply: %v", err)
	}
	if _, err := ApplyParsedWithOptions(source, patch, ApplyOptions{AddHeader: true, RemoveHeader: true}); err == nil {
		t.Fatal("conflicting header options were accepted")
	}
}

func TestBPSDeltaHandlesHighlyRepetitiveInput(t *testing.T) {
	source := bytes.Repeat([]byte{1, 2}, 32<<10)
	target := append(append([]byte(nil), source[1:]...), source[0])
	patch := createBPS(source, target, true)
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(source, encoded, ApplyOptions{Validate: true})
	if err != nil || !bytes.Equal(got, target) {
		t.Fatalf("repetitive BPS delta: %v", err)
	}
}

func FuzzParseNoPanic(f *testing.F) {
	f.Add([]byte("PATCHXYZ"))
	f.Add([]byte{0xd6, 0xc3, 0xc4, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := Parse(b)
		if e == nil && p != nil {
			_, _ = p.Apply([]byte("source"), ApplyOptions{MaxOutputSize: 1 << 20})
		}
	})
}
