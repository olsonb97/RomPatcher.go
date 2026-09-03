package rompatcher

import (
	"bytes"
	"context"
	"io"
	"testing"
)

type benchmarkReadWriterAt []byte

func (b benchmarkReadWriterAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (b benchmarkReadWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(b))-int64(len(p)) {
		return 0, io.ErrShortWrite
	}
	return copy(b[off:], p), nil
}

func benchmarkData(b *testing.B) ([]byte, []byte, []byte) {
	b.Helper()
	original := make([]byte, 1<<20)
	for i := range original {
		original[i] = byte(i * 31)
	}
	modified := append([]byte(nil), original...)
	for i := 0; i < len(modified); i += 4093 {
		modified[i] ^= 0x5a
	}
	patch, err := Create(original, modified, FormatBPS, nil)
	if err != nil {
		b.Fatal(err)
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}
	return original, modified, encoded
}

func BenchmarkApplyBPS(b *testing.B) {
	original, _, patch := benchmarkData(b)
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(original)))
	for i := 0; i < b.N; i++ {
		if _, err := Apply(original, patch, ApplyOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplyReaderAtBPS(b *testing.B) {
	original, modified, patch := benchmarkData(b)
	output := make(benchmarkReadWriterAt, len(modified))
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(original)))
	for i := 0; i < b.N; i++ {
		if _, err := ApplyReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), bytes.NewReader(patch), int64(len(patch)), output, ApplyOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateBPS(b *testing.B) {
	original, modified, _ := benchmarkData(b)
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(original) + len(modified)))
	for i := 0; i < b.N; i++ {
		if _, err := Create(original, modified, FormatBPS, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCreateReaderAtBPS(b *testing.B) {
	original, modified, _ := benchmarkData(b)
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(original) + len(modified)))
	for i := 0; i < b.N; i++ {
		var output bytes.Buffer
		if _, err := CreateReaderAt(context.Background(), bytes.NewReader(original), int64(len(original)), bytes.NewReader(modified), int64(len(modified)), &output, FormatBPS, nil); err != nil {
			b.Fatal(err)
		}
	}
}
