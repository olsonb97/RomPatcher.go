package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func releaseTestFiles() []archiveFile {
	return []archiveFile{
		{name: "rompatcher", source: bytes.NewReader([]byte("binary")), size: 6, mode: 0o755},
		{name: "LICENSE", source: bytes.NewReader([]byte("MIT")), size: 3, mode: 0o644},
		{name: "THIRD_PARTY_NOTICES.md", source: bytes.NewReader([]byte("BSD")), size: 3, mode: 0o644},
	}
}

func TestReleaseArchivesDoNotReplaceExistingFiles(t *testing.T) {
	for _, suffix := range []string{".zip", ".tar.gz"} {
		path := filepath.Join(t.TempDir(), "release"+suffix)
		if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := writeArchive(path, releaseTestFiles())
		if err == nil {
			t.Fatalf("%s replaced an existing archive", suffix)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != "existing" {
			t.Fatalf("existing %s = %q, %v", suffix, got, readErr)
		}
	}
}

func TestReleasePreflightChecksArchiveAndChecksum(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "release.zip")
	checksum := archive + ".sha256"
	if err := os.WriteFile(checksum, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireAbsent(archive, checksum); err == nil {
		t.Fatal("existing checksum was accepted")
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("archive was created: %v", err)
	}
}

type archiveEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func readArchive(t *testing.T, encoded []byte, suffix string) (entries []archiveEntry) {
	t.Helper()
	read := func(name string, mode os.FileMode, r io.Reader) {
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, archiveEntry{name, data, mode.Perm()})
	}
	if suffix == ".zip" {
		zr, err := zip.NewReader(bytes.NewReader(encoded), int64(len(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range zr.File {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			read(f.Name, f.Mode(), r)
		}
	} else {
		gz, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			read(h.Name, h.FileInfo().Mode(), tr)
		}
	}
	return entries
}

func TestStreamedArchives(t *testing.T) {
	want := []archiveEntry{{"rompatcher", bytes.Repeat([]byte("streaming payload"), 10000), 0o755}, {"LICENSE", []byte("MIT"), 0o644}, {"THIRD_PARTY_NOTICES.md", []byte("BSD"), 0o644}}
	for _, suffix := range []string{".zip", ".tar.gz"} {
		dir := t.TempDir()
		var first []byte
		for i := 0; i < 2; i++ {
			var files []archiveFile
			for _, entry := range want {
				files = append(files, archiveFile{entry.name, bytes.NewReader(entry.data), int64(len(entry.data)), entry.mode})
			}
			path := filepath.Join(dir, fmt.Sprintf("release%d%s", i, suffix))
			sum, err := writeArchive(path, files)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if sum != fmt.Sprintf("%x", sha256.Sum256(encoded)) {
				t.Fatal("incorrect archive checksum")
			}
			if i == 0 {
				first = encoded
			} else if !bytes.Equal(first, encoded) {
				t.Fatal("archive is not deterministic")
			}
			if got := readArchive(t, encoded, suffix); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s contents, order or permissions differ", suffix)
			}
		}
	}
}

func TestArchiveReadFailureDoesNotPublish(t *testing.T) {
	for _, suffix := range []string{".zip", ".tar.gz"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "release"+suffix)
		files := []archiveFile{{name: "short", source: bytes.NewReader([]byte("abc")), size: 10}}
		if _, err := writeArchive(path, files); !errors.Is(err, io.EOF) {
			t.Fatalf("read error = %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("partial output left behind: %v, %v", entries, err)
		}
	}
}
