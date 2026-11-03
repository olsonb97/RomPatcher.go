// Command releasepack creates a deterministic release archive and SHA-256
// checksum for one binary.
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
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

	rompatcher "github.com/olsonb97/RomPatcher.go"
)

func main() {
	binary := flag.String("binary", "", "binary to package")
	output := flag.String("output", "", "archive output path (.zip or .tar.gz)")
	flag.Parse()
	if *binary == "" || *output == "" {
		fatal(fmt.Errorf("binary and output are required"))
	}
	if err := requireAbsent(*output, *output+".sha256"); err != nil {
		fatal(err)
	}
	var files []archiveFile
	for _, path := range []string{*binary, "LICENSE", "THIRD_PARTY_NOTICES.md"} {
		f, err := os.Open(path)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			fatal(err)
		}
		if !info.Mode().IsRegular() {
			fatal(fmt.Errorf("archive input is not a regular file: %s", path))
		}
		mode := os.FileMode(0o644)
		if len(files) == 0 {
			mode = 0o755
		}
		files = append(files, archiveFile{name: filepath.Base(path), source: f, size: info.Size(), mode: mode})
	}
	sum, err := writeArchive(*output, files)
	if err != nil {
		fatal(err)
	}
	if err := rompatcher.WriteFileAtomic(*output+".sha256", []byte(sum+"  "+filepath.Base(*output)+"\n")); err != nil {
		fatal(err)
	}
}

type archiveFile struct {
	name   string
	source io.Reader
	size   int64
	mode   os.FileMode
}

// Hash the exact archive bytes during publication; neither inputs nor the
// archive need to be buffered in memory or reread for the checksum.
func writeArchive(path string, files []archiveFile) (string, error) {
	h := sha256.New()
	err := rompatcher.WriteFileAtomicFunc(path, func(out io.Writer) error {
		w := bufio.NewWriter(io.MultiWriter(out, h))
		var err error
		if strings.HasSuffix(path, ".zip") {
			err = writeZIP(w, files)
		} else {
			err = writeTGZ(w, files)
		}
		if err != nil {
			return err
		}
		return w.Flush()
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeZIP(out io.Writer, files []archiveFile) (err error) {
	zw := zip.NewWriter(out)
	defer closeArchive(&err, zw)
	for _, file := range files {
		h := &zip.FileHeader{Name: file.name, Method: zip.Deflate, Modified: time.Unix(0, 0).UTC()}
		h.SetMode(file.mode)
		w, createErr := zw.CreateHeader(h)
		if createErr != nil {
			return createErr
		}
		if _, err = io.CopyN(w, file.source, file.size); err != nil {
			return err
		}
	}
	return err
}

func writeTGZ(out io.Writer, files []archiveFile) (err error) {
	gz := gzip.NewWriter(out)
	defer closeArchive(&err, gz)
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gz)
	defer closeArchive(&err, tw)
	for _, file := range files {
		err = tw.WriteHeader(&tar.Header{Name: file.name, Size: file.size, Mode: int64(file.mode), ModTime: time.Unix(0, 0).UTC()})
		if err != nil {
			return err
		}
		if _, err = io.CopyN(tw, file.source, file.size); err != nil {
			return err
		}
	}
	return err
}

// Always finish each layer, preserving the first write or close failure.
func closeArchive(err *error, w io.Closer) {
	if closeErr := w.Close(); *err == nil {
		*err = closeErr
	}
}

func requireAbsent(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("output already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect output: %w", err)
		}
	}
	return nil
}

func fatal(err error) { _, _ = io.WriteString(os.Stderr, "releasepack: "+err.Error()+"\n"); os.Exit(1) }
