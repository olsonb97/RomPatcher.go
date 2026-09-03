package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

var releaseTestFiles = []archiveFile{
	{name: "rompatcher", data: []byte("binary"), mode: 0o755},
	{name: "LICENSE", data: []byte("MIT"), mode: 0o644},
	{name: "THIRD_PARTY_NOTICES.md", data: []byte("BSD"), mode: 0o644},
}

func TestReleaseArchivesContainLicenses(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")
	if err := writeZIP(zipPath, releaseTestFiles); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(releaseTestFiles) || zr.File[1].Name != "LICENSE" || zr.File[2].Name != "THIRD_PARTY_NOTICES.md" {
		t.Fatalf("ZIP entries = %+v", zr.File)
	}
	_ = zr.Close()

	tarPath := filepath.Join(dir, "release.tar.gz")
	if err := writeTGZ(tarPath, releaseTestFiles); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	_ = gz.Close()
	_ = f.Close()
	if len(names) != len(releaseTestFiles) || names[1] != "LICENSE" || names[2] != "THIRD_PARTY_NOTICES.md" {
		t.Fatalf("tar entries = %v", names)
	}
}

func TestSPDXIncludesXZDependency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.spdx.json")
	if err := writeSPDX(path, "rompatcher", "v1", "linux", "amd64", [32]byte{}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Packages []struct {
			Name    string `json:"name"`
			License string `json:"licenseDeclared"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(b, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Packages) != 3 || document.Packages[1].Name != "github.com/ulikunitz/xz" || document.Packages[1].License != "BSD-3-Clause" || document.Packages[2].Name != "Go standard library" || document.Packages[2].License != "BSD-3-Clause" {
		t.Fatalf("SPDX packages = %+v", document.Packages)
	}
}
