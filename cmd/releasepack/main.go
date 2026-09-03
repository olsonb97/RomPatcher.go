// Command releasepack creates a deterministic release archive and SHA-256
// checksum for one binary.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	binary := flag.String("binary", "", "binary to package")
	output := flag.String("output", "", "archive output path (.zip or .tar.gz)")
	flag.Parse()
	if *binary == "" || *output == "" {
		fatal(fmt.Errorf("binary and output are required"))
	}
	data, err := os.ReadFile(*binary)
	if err != nil {
		fatal(err)
	}
	mode := os.FileMode(0o755)
	name := filepath.Base(*binary)
	license, err := os.ReadFile("LICENSE")
	if err != nil {
		fatal(err)
	}
	notices, err := os.ReadFile("THIRD_PARTY_NOTICES.md")
	if err != nil {
		fatal(err)
	}
	files := []archiveFile{{name: name, data: data, mode: mode}, {name: "LICENSE", data: license, mode: 0o644}, {name: "THIRD_PARTY_NOTICES.md", data: notices, mode: 0o644}}
	if strings.HasSuffix(*output, ".zip") {
		err = writeZIP(*output, files)
	} else {
		err = writeTGZ(*output, files)
	}
	if err != nil {
		fatal(err)
	}
	archive, err := os.ReadFile(*output)
	if err != nil {
		fatal(err)
	}
	archiveSum := sha256.Sum256(archive)
	if err := os.WriteFile(*output+".sha256", []byte(hex.EncodeToString(archiveSum[:])+"  "+filepath.Base(*output)+"\n"), 0o644); err != nil {
		fatal(err)
	}
}

type archiveFile struct {
	name string
	data []byte
	mode os.FileMode
}

func writeZIP(path string, files []archiveFile) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	for _, file := range files {
		h := &zip.FileHeader{Name: file.name, Method: zip.Deflate, Modified: time.Unix(0, 0).UTC()}
		h.SetMode(file.mode)
		w, createErr := zw.CreateHeader(h)
		if createErr != nil {
			err = createErr
			break
		}
		if _, err = w.Write(file.data); err != nil {
			break
		}
	}
	if closeErr := zw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func writeTGZ(path string, files []archiveFile) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	for _, file := range files {
		err = tw.WriteHeader(&tar.Header{Name: file.name, Size: int64(len(file.data)), Mode: int64(file.mode), ModTime: time.Unix(0, 0).UTC()})
		if err != nil {
			break
		}
		if _, err = tw.Write(file.data); err != nil {
			break
		}
	}
	if closeErr := tw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := gz.Close(); err == nil {
		err = closeErr
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func fatal(err error) { _, _ = io.WriteString(os.Stderr, "releasepack: "+err.Error()+"\n"); os.Exit(1) }
