package rompatcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

type checksumTestFile struct {
	memoryFile
	maxRead  int
	readErr  error
	writeErr error
	cancel   context.CancelFunc
}

func (f *checksumTestFile) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > f.maxRead {
		f.maxRead = len(p)
	}
	if f.readErr != nil {
		return 0, f.readErr
	}
	n, err := f.memoryFile.ReadAt(p, off)
	if f.cancel != nil {
		f.cancel()
	}
	return n, err
}

func (f *checksumTestFile) WriteAt(p []byte, off int64) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.memoryFile.WriteAt(p, off)
}

func TestApplyReaderAtRepairsChecksumWithoutWholeOutputRead(t *testing.T) {
	for _, name := range []string{"game.gb", "game.md"} {
		t.Run(name, func(t *testing.T) {
			source := make([]byte, 4*checksumChunkSize)
			if name == "game.gb" {
				copy(source[0x104:], gameBoyLogo)
			} else {
				copy(source[0x100:], "SEGA GENESIS")
			}
			target := append([]byte(nil), source...)
			target[0x134], target[0x201] = 7, 9
			patch, err := Create(source, target, FormatBPS, &CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := patch.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			out := &checksumTestFile{}
			completed := false
			options := ApplyOptions{Validate: true, FixChecksum: true, SourceName: name,
				Progress: func(p Progress) {
					if p.Phase == "complete" {
						completed = true
					}
				},
			}
			size, err := ApplyReaderAt(context.Background(), bytes.NewReader(source), int64(len(source)), bytes.NewReader(encoded), int64(len(encoded)), out, options)
			if err != nil {
				t.Fatal(err)
			}
			if size != int64(len(target)) || !completed {
				t.Fatalf("size=%d completed=%v", size, completed)
			}
			if out.maxRead > checksumChunkSize {
				t.Fatalf("output read requested %d bytes", out.maxRead)
			}
			if name == "game.gb" {
				var sum byte
				for _, b := range target[0x134:0x14d] {
					sum -= b + 1
				}
				target[0x14d] = sum
			} else {
				target[0x18f] = 9
			}
			if !bytes.Equal(out.data, target) {
				t.Fatal("incorrect repaired output")
			}
			inMemory, err := Apply(source, encoded, options)
			if err != nil || !bytes.Equal(inMemory, target) {
				t.Fatalf("memory/file parity: %v", err)
			}
		})
	}
}

func TestChecksumRepairFailureDoesNotWriteChecksum(t *testing.T) {
	for _, mode := range []string{"cancel", "read", "write"} {
		t.Run(mode, func(t *testing.T) {
			data := make([]byte, 0x4000)
			copy(data[0x104:], gameBoyLogo)
			before := append([]byte(nil), data...)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			file := &checksumTestFile{memoryFile: memoryFile{data: data}}
			want := io.ErrClosedPipe
			switch mode {
			case "cancel":
				file.cancel, want = cancel, context.Canceled
			case "read":
				file.readErr = want
			case "write":
				file.writeErr = want
			}
			fixed, err := fixROMChecksumReaderAt(ctx, file, file, int64(len(data)), "game.gb")
			if fixed || !errors.Is(err, want) {
				t.Fatalf("fixed=%v err=%v", fixed, err)
			}
			if !bytes.Equal(file.data, before) {
				t.Fatal("failed repair altered checksum")
			}
		})
	}
}

func TestChecksumRepairSkipsUnrecognizedROM(t *testing.T) {
	file := &checksumTestFile{readErr: io.ErrClosedPipe}
	fixed, err := fixROMChecksumReaderAt(context.Background(), file, file, 8<<30, "disc.iso")
	if fixed || err != nil || file.maxRead != 0 {
		t.Fatalf("fixed=%v err=%v maxRead=%d", fixed, err, file.maxRead)
	}
}

type checksumWriteOnly struct{ file *memoryFile }

func (w checksumWriteOnly) WriteAt(p []byte, off int64) (int, error) {
	return w.file.WriteAt(p, off)
}

func TestChecksumRepairPreservesWriteOnlyOutputSupport(t *testing.T) {
	source := make([]byte, 0x4000)
	copy(source[0x104:], gameBoyLogo)
	patch := []byte("PATCHEOF")
	file := &memoryFile{}
	_, err := ApplyReaderAt(context.Background(), bytes.NewReader(source), int64(len(source)), bytes.NewReader(patch), int64(len(patch)), checksumWriteOnly{file}, ApplyOptions{FixChecksum: true, SourceName: "game.gb"})
	if err != nil {
		t.Fatal(err)
	}
	if file.data[0x14d] != 0xe7 {
		t.Fatalf("checksum=%02x, want e7", file.data[0x14d])
	}
}

func BenchmarkChecksumRepairReaderAt(b *testing.B) {
	file := &memoryFile{data: make([]byte, 8<<20)}
	copy(file.data[0x100:], "SEGA GENESIS")
	file.data[0x201] = 1
	b.SetBytes(int64(len(file.data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		file.data[0x18f] = 0
		if _, err := fixROMChecksumReaderAt(context.Background(), file, file, int64(len(file.data)), "game.md"); err != nil {
			b.Fatal(err)
		}
	}
}
