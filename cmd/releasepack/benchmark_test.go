package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkReleaseZIP(b *testing.B) {
	for _, size := range []int{8 << 20, 32 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			data := make([]byte, size)
			_, _ = rand.New(rand.NewSource(1)).Read(data)
			input := filepath.Join(b.TempDir(), "binary")
			if err := os.WriteFile(input, data, 0o600); err != nil {
				b.Fatal(err)
			}
			f, err := os.Open(input)
			if err != nil {
				b.Fatal(err)
			}
			defer f.Close()
			files := []archiveFile{{name: "rompatcher", source: f, size: int64(size), mode: 0o755}}
			path := filepath.Join(b.TempDir(), "release.zip")
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := writeArchive(path, files); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if err := os.Remove(path); err != nil {
					b.Fatal(err)
				}
				if _, err := f.Seek(0, 0); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}
