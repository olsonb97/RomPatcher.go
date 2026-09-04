package rompatcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

type limitedReadAt struct {
	data []byte
	max  int
}

type writerAtOnly struct{ data []byte }

type countingReaderAt struct{ reads int }

type zeroReaderAt struct{}

func (zeroReaderAt) ReadAt(p []byte, _ int64) (int, error) {
	clear(p)
	return len(p), nil
}

func (r *countingReaderAt) ReadAt([]byte, int64) (int, error) {
	r.reads++
	return 0, errors.New("unexpected read")
}

func (w *writerAtOnly) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(w.data) {
		w.data = append(w.data, make([]byte, end-len(w.data))...)
	}
	return copy(w.data[int(off):], p), nil
}

func (r *limitedReadAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > r.max {
		return 0, errors.New("oversized read")
	}
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestCreateReaderAtRoundTrips(t *testing.T) {
	formats := []Format{FormatIPS, FormatIPS32, FormatEBP, FormatUPS, FormatBPS, FormatAPSN64, FormatRUP, FormatPPF}
	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			var encoded bytes.Buffer
			opts := &CreateOptions{Metadata: map[string]string{"Author": "test"}, Description: "test"}
			size, err := CreateReaderAt(context.Background(), bytes.NewReader(testOriginal), int64(len(testOriginal)), bytes.NewReader(testModified), int64(len(testModified)), &encoded, format, opts)
			if err != nil {
				t.Fatal(err)
			}
			if size != int64(encoded.Len()) {
				t.Fatalf("size = %d, encoded = %d", size, encoded.Len())
			}
			parsed, err := Parse(encoded.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Format() != format {
				t.Fatalf("format = %s", parsed.Format())
			}
			switch format {
			case FormatEBP, FormatBPS, FormatAPSN64, FormatRUP, FormatPPF:
				if parsed.Description() == "" {
					t.Fatal("creation discarded the description")
				}
			}
			assertReaderAtApply(t, testOriginal, encoded.Bytes(), testModified, true)
		})
	}
}

func TestRandomizedCreateReaderAtRoundTrips(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5354524d))
	formats := []Format{FormatIPS, FormatIPS32, FormatEBP, FormatUPS, FormatBPS, FormatAPSN64, FormatRUP, FormatPPF}
	for iteration := 0; iteration < 40; iteration++ {
		original := make([]byte, rng.Intn(4096))
		modified := make([]byte, rng.Intn(4096))
		_, _ = rng.Read(original)
		_, _ = rng.Read(modified)
		copy(modified, original)
		for changes := 0; changes < 30 && len(modified) > 0; changes++ {
			modified[rng.Intn(len(modified))] = byte(rng.Intn(256))
		}
		for _, format := range formats {
			if len(modified) < len(original) && (format == FormatEBP || format == FormatPPF) {
				continue
			}
			var encoded bytes.Buffer
			if _, err := CreateReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), bytes.NewReader(modified), int64(len(modified)), &encoded, format, nil); err != nil {
				t.Fatalf("iteration %d %s create: %v", iteration, format, err)
			}
			got, err := Apply(original, encoded.Bytes(), ApplyOptions{Validate: true})
			if err != nil {
				t.Fatalf("iteration %d %s apply: %v", iteration, format, err)
			}
			if !bytes.Equal(got, modified) {
				t.Fatalf("iteration %d %s output mismatch", iteration, format)
			}
		}
	}
}

func TestCreateReaderAtUsesBoundedReads(t *testing.T) {
	original := make([]byte, 3<<20)
	modified := bytes.Repeat([]byte{0x5a}, len(original))
	var patch bytes.Buffer
	_, err := CreateReaderAt(context.Background(), &limitedReadAt{data: original, max: fileChunkSize}, int64(len(original)), &limitedReadAt{data: modified, max: fileChunkSize}, int64(len(modified)), &patch, FormatBPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Apply(original, patch.Bytes(), ApplyOptions{Validate: true})
	if err != nil || !bytes.Equal(got, modified) {
		t.Fatalf("bounded-reader BPS round trip: %v", err)
	}
}

func TestLargeBPSCreationCompressesRepeatedOutput(t *testing.T) {
	target := make([]byte, 5<<20)
	patch, err := Create(nil, target, FormatBPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 128 {
		t.Fatalf("repeated output produced a %d-byte patch", len(encoded))
	}
	got, err := Apply(nil, encoded, ApplyOptions{Validate: true})
	if err != nil || !bytes.Equal(got, target) {
		t.Fatalf("repeated BPS round trip: %v", err)
	}
}

func TestCreateReaderAtOptionalBPSDeltaMatching(t *testing.T) {
	target := make([]byte, 5<<20)
	for i := range target {
		target[i] = byte(i)
	}
	var linear, delta bytes.Buffer
	if _, err := CreateReaderAt(context.Background(), bytes.NewReader(nil), 0, bytes.NewReader(target), int64(len(target)), &linear, FormatBPS, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateReaderAt(context.Background(), bytes.NewReader(nil), 0, bytes.NewReader(target), int64(len(target)), &delta, FormatBPS, &CreateOptions{BPSDelta: true}); err != nil {
		t.Fatal(err)
	}
	if delta.Len() >= linear.Len()/100 {
		t.Fatalf("delta patch was not substantially smaller: delta=%d linear=%d", delta.Len(), linear.Len())
	}
	got, err := Apply(nil, delta.Bytes(), ApplyOptions{Validate: true})
	if err != nil || !bytes.Equal(got, target) {
		t.Fatalf("file-backed delta BPS round trip: %v", err)
	}
}

func TestCreateFileLimitDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "original.bin")
	modifiedPath := filepath.Join(dir, "modified.bin")
	patchPath := filepath.Join(dir, "change.ips")
	if err := os.WriteFile(originalPath, testOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modifiedPath, testModified, 0o600); err != nil {
		t.Fatal(err)
	}
	err := CreateFile(originalPath, modifiedPath, patchPath, FormatIPS, &CreateOptions{MaxPatchSize: 4})
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("limit error = %v", err)
	}
	if _, err := os.Stat(patchPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed patch was published: %v", err)
	}
}

func TestIPSRejectsUnrepresentableTruncateSize(t *testing.T) {
	_, err := CreateReaderAt(context.Background(), zeroReaderAt{}, ipsMaxSize+1, zeroReaderAt{}, ipsMaxSize, io.Discard, FormatIPS, nil)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestIPSGrowthSentinelAvoidsReservedOffset(t *testing.T) {
	const targetSize = int64(0x454f46 + 1)
	var encoded bytes.Buffer
	if _, err := CreateReaderAt(context.Background(), zeroReaderAt{}, targetSize-1, zeroReaderAt{}, targetSize, &encoded, FormatIPS, nil); err != nil {
		t.Fatal(err)
	}
	patch, err := Parse(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ips := patch.(*IPSPatch)
	if len(ips.records) != 1 || int64(ips.records[0].offset) != targetSize-2 || len(ips.records[0].data) != 2 {
		t.Fatalf("sentinel record = %+v", ips.records)
	}
}

func TestCreateFileNormalizesDefaultExtension(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "original.bin")
	modifiedPath := filepath.Join(dir, "modified.bin")
	if err := os.WriteFile(originalPath, testOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modifiedPath, testModified, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateFile(originalPath, modifiedPath, "", Format(" BPS "), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "modified.bps")); err != nil {
		t.Fatalf("normalized output was not created: %v", err)
	}
}

func TestUPSCreationPreservesShrunkTailForUndo(t *testing.T) {
	original := []byte("prefix and original tail")
	modified := []byte("prefix")
	for _, streamed := range []bool{false, true} {
		var encoded []byte
		if streamed {
			var output bytes.Buffer
			if _, err := CreateReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), bytes.NewReader(modified), int64(len(modified)), &output, FormatUPS, nil); err != nil {
				t.Fatal(err)
			}
			encoded = output.Bytes()
		} else {
			patch, err := Create(original, modified, FormatUPS, nil)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ = patch.MarshalBinary()
		}
		got, err := Apply(modified, encoded, ApplyOptions{Validate: true})
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("streamed=%v: %v, %q", streamed, err, got)
		}
	}
}

func TestApplyReaderAtStreamsLargePatch(t *testing.T) {
	original := make([]byte, 2<<20)
	modified := make([]byte, len(original))
	for i := range modified {
		modified[i] = byte(i*31 + 7)
	}
	var encoded bytes.Buffer
	if _, err := CreateReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), bytes.NewReader(modified), int64(len(modified)), &encoded, FormatIPS, nil); err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(filepath.Join(t.TempDir(), "output.bin"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	patch := &limitedReadAt{data: encoded.Bytes(), max: 128 << 10}
	size, err := ApplyReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), patch, int64(encoded.Len()), out, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(modified)) {
		t.Fatalf("size = %d", size)
	}
	if err := out.Truncate(size); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, size)
	if err := readAtFull(out, got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, modified) {
		t.Fatal("streamed output mismatch")
	}
}

func TestApplyReaderAtReportsReadableOutputRequirement(t *testing.T) {
	patch, err := Create(testOriginal, testModified, FormatBPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ApplyReaderAt(context.Background(), bytes.NewReader(testOriginal), int64(len(testOriginal)), bytes.NewReader(encoded), int64(len(encoded)), &writerAtOnly{}, ApplyOptions{})
	if !errors.Is(err, ErrUnsupported) || !bytes.Contains([]byte(err.Error()), []byte("output must implement io.ReaderAt")) {
		t.Fatalf("error = %v", err)
	}
}

func TestApplyReaderAtRejectsConflictingHeaderOptionsBeforeReading(t *testing.T) {
	source, patch := &countingReaderAt{}, &countingReaderAt{}
	_, err := ApplyReaderAt(context.Background(), source, 1, patch, 1, &writerAtOnly{}, ApplyOptions{RemoveHeader: true, AddHeader: true})
	if err == nil || source.reads != 0 || patch.reads != 0 {
		t.Fatalf("error = %v, source reads = %d, patch reads = %d", err, source.reads, patch.reads)
	}
}

func TestApplyReaderAtHeaderTransformCompletesAfterWriting(t *testing.T) {
	source := make([]byte, 1024)
	headered := make([]byte, 16+len(source))
	target := append([]byte(nil), headered...)
	target[16] = 0x7f
	patch, err := Create(headered, target, FormatIPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var phases []string
	output := &writerAtOnly{}
	size, err := ApplyReaderAt(context.Background(), bytes.NewReader(source), int64(len(source)), bytes.NewReader(encoded), int64(len(encoded)), output, ApplyOptions{
		AddHeader:  true,
		SourceName: "game.nes",
		Progress: func(progress Progress) {
			phases = append(phases, progress.Phase)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(source)) || len(output.data) != len(source) || output.data[0] != 0x7f {
		t.Fatal("header-transformed output mismatch")
	}
	if len(phases) == 0 {
		t.Fatal("no progress reported")
	}
	if phases[len(phases)-1] != "complete" {
		t.Fatalf("progress phases = %v", phases)
	}
	for _, phase := range phases[:len(phases)-1] {
		if phase == "complete" {
			t.Fatalf("completion reported before output write: %v", phases)
		}
	}
}

func TestAtomicOutputSkipsWorkWhenDestinationExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.bin")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := atomicOutput(path, func(*os.File) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatalf("error = %v, writer called = %v", err, called)
	}
}

func TestApplyFileChain(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "original.bin")
	firstPath := filepath.Join(dir, "first.bps")
	secondPath := filepath.Join(dir, "second.ips")
	outputPath := filepath.Join(dir, "output.bin")
	final := append([]byte(nil), testModified...)
	final[0] ^= 0xff
	if err := os.WriteFile(originalPath, testOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	first, _ := Create(testOriginal, testModified, FormatBPS, nil)
	second, _ := Create(testModified, final, FormatIPS, nil)
	firstData, _ := first.MarshalBinary()
	secondData, _ := second.MarshalBinary()
	if err := os.WriteFile(firstPath, firstData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, secondData, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ApplyFileChainContext(context.Background(), originalPath, []string{firstPath, secondPath}, outputPath, ApplyOptions{Validate: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, final) || result.Output != nil || len(result.Steps) != 2 {
		t.Fatal("file chain result mismatch")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".rompatcher-chain-*")); len(matches) != 0 {
		t.Fatalf("intermediate files remain: %v", matches)
	}
}

func TestApplyFileChainCancellationDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.bin")
	patchPath := filepath.Join(dir, "change.bps")
	outputPath := filepath.Join(dir, "output.bin")
	if err := os.WriteFile(sourcePath, testOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	patch, _ := Create(testOriginal, testModified, FormatBPS, nil)
	encoded, _ := patch.MarshalBinary()
	if err := os.WriteFile(patchPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := ApplyFileChainContext(ctx, sourcePath, []string{patchPath}, outputPath, ApplyOptions{Progress: func(progress Progress) {
		if progress.Phase == "chain" && progress.Completed == progress.Total {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if _, err := os.Stat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled output exists: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".rompatcher-chain-*")); len(matches) != 0 {
		t.Fatalf("canceled intermediate files remain: %v", matches)
	}
}

func FuzzApplyReaderAtNoPanic(f *testing.F) {
	for _, format := range []Format{FormatIPS, FormatIPS32, FormatEBP, FormatUPS, FormatBPS, FormatAPSN64, FormatRUP, FormatPPF} {
		patch, err := Create(testOriginal, testModified, format, nil)
		if err != nil {
			f.Fatal(err)
		}
		encoded, err := patch.MarshalBinary()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(testOriginal, encoded)
	}
	f.Fuzz(func(t *testing.T, source, patch []byte) {
		output := make(benchmarkReadWriterAt, 1<<20)
		_, _ = ApplyReaderAt(context.Background(), bytes.NewReader(source), int64(len(source)), bytes.NewReader(patch), int64(len(patch)), output, ApplyOptions{MaxOutputSize: 1 << 20})
	})
}

func FuzzCreateReaderAtRoundTrip(f *testing.F) {
	f.Add([]byte("original"), []byte("modified"), uint8(0))
	f.Add([]byte{}, []byte{}, uint8(4))
	formats := []Format{FormatIPS, FormatIPS32, FormatEBP, FormatUPS, FormatBPS, FormatAPSN64, FormatRUP, FormatPPF}
	f.Fuzz(func(t *testing.T, original, modified []byte, formatIndex uint8) {
		if len(original) > 1024 || len(modified) > 1024 {
			t.Skip()
		}
		format := formats[int(formatIndex)%len(formats)]
		var encoded bytes.Buffer
		_, err := CreateReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), bytes.NewReader(modified), int64(len(modified)), &encoded, format, &CreateOptions{MaxPatchSize: 1 << 20})
		if err != nil {
			if errors.Is(err, ErrUnsupported) && len(modified) < len(original) && (format == FormatEBP || format == FormatPPF) {
				return
			}
			t.Fatal(err)
		}
		output := new(memoryFile)
		size, err := ApplyReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), bytes.NewReader(encoded.Bytes()), int64(encoded.Len()), output, ApplyOptions{Validate: true, MaxOutputSize: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if size != int64(len(modified)) || !bytes.Equal(output.data[:size], modified) {
			t.Fatalf("%s round trip produced %d bytes, expected %d", format, size, len(modified))
		}
	})
}
