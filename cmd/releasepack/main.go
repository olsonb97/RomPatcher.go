// Command releasepack creates deterministic release archives, SHA-256
// checksums, and an SPDX 2.3 SBOM for one binary.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	binary := flag.String("binary", "", "binary to package")
	output := flag.String("output", "", "archive output path (.zip or .tar.gz)")
	version := flag.String("version", "dev", "release version")
	goos := flag.String("os", "", "target operating system")
	goarch := flag.String("arch", "", "target architecture")
	flag.Parse()
	if *binary == "" || *output == "" || *goos == "" || *goarch == "" {
		fatal(fmt.Errorf("binary, output, os, and arch are required"))
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
	archiveSum, binarySum := sha256.Sum256(archive), sha256.Sum256(data)
	if err := os.WriteFile(*output+".sha256", []byte(hex.EncodeToString(archiveSum[:])+"  "+filepath.Base(*output)+"\n"), 0o644); err != nil {
		fatal(err)
	}
	if err := writeSPDX(*output+".spdx.json", name, *version, *goos, *goarch, binarySum); err != nil {
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

func writeSPDX(path, name, version, goos, goarch string, sum [32]byte) error {
	namespace := fmt.Sprintf("https://github.com/olsonb97/RomPatcher.go/releases/%s/%s-%s", version, goos, goarch)
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
		"name": "RomPatcher.go " + version + " " + goos + "/" + goarch, "documentNamespace": namespace,
		"creationInfo": map[string]any{"created": time.Now().UTC().Format(time.RFC3339), "creators": []string{"Tool: RomPatcher.go-releasepack"}},
		"packages": []any{
			map[string]any{"name": name, "SPDXID": "SPDXRef-Package", "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "licenseConcluded": "MIT", "licenseDeclared": "MIT", "checksums": []any{map[string]string{"algorithm": "SHA256", "checksumValue": hex.EncodeToString(sum[:])}}, "externalRefs": []any{map[string]string{"referenceCategory": "OTHER", "referenceType": "go-platform", "referenceLocator": goos + "/" + goarch}}},
			map[string]any{"name": "github.com/ulikunitz/xz", "SPDXID": "SPDXRef-Package-xz", "versionInfo": "v0.5.16", "downloadLocation": "https://github.com/ulikunitz/xz", "filesAnalyzed": false, "licenseConcluded": "BSD-3-Clause", "licenseDeclared": "BSD-3-Clause", "externalRefs": []any{map[string]string{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/github.com/ulikunitz/xz@v0.5.16"}}},
			map[string]any{"name": "Go standard library", "SPDXID": "SPDXRef-Package-go-stdlib", "versionInfo": runtime.Version(), "downloadLocation": "https://go.dev/", "filesAnalyzed": false, "licenseConcluded": "BSD-3-Clause", "licenseDeclared": "BSD-3-Clause"},
		},
		"relationships": []any{
			map[string]string{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package"},
			map[string]string{"spdxElementId": "SPDXRef-Package", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-xz"},
			map[string]string{"spdxElementId": "SPDXRef-Package", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-go-stdlib"},
		},
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(doc)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func fatal(err error) { _, _ = io.WriteString(os.Stderr, "releasepack: "+err.Error()+"\n"); os.Exit(1) }
