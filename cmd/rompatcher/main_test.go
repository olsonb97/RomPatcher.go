package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	rompatcher "github.com/olsonb97/RomPatcher.go"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	b, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(b), runErr
}

func TestApplyFlagsAreInterspersedAndConsistent(t *testing.T) {
	f := flag.NewFlagSet("apply", flag.ContinueOnError)
	o := addApplyFlags(f)
	args := []string{"game.sfc", "base.bps", "-v", "fix.ips", "--patch-entry", "base/in.zip", "-e", "fix/in.zip", "-o", "final.sfc", "-j"}
	if err := parseInterspersed(f, args); err != nil {
		t.Fatal(err)
	}
	if !o.validate || !o.jsonOutput || o.output != "final.sfc" {
		t.Fatalf("flags not parsed: %+v", o)
	}
	if !reflect.DeepEqual(f.Args(), []string{"game.sfc", "base.bps", "fix.ips"}) {
		t.Fatalf("positionals: %v", f.Args())
	}
	if !reflect.DeepEqual([]string(o.patchEntries), []string{"base/in.zip", "fix/in.zip"}) {
		t.Fatalf("entries: %v", o.patchEntries)
	}
}

func TestDefaultOutputNames(t *testing.T) {
	if got := defaultOutputPath("games.zip", "region/game.sfc"); got != "game (patched).sfc" {
		t.Fatalf("ZIP output: %q", got)
	}
	if got := defaultOutputPath(filepath.Join("roms", "game.sfc"), filepath.Join("roms", "game.sfc")); got != filepath.Join("roms", "game (patched).sfc") {
		t.Fatalf("file output: %q", got)
	}
	if !requestedJSON([]string{"file", "-j"}) {
		t.Fatal("-j was not recognized")
	}
	if requestedJSON([]string{"file", "--json=false"}) {
		t.Fatal("--json=false was treated as enabled")
	}
	if !requestedJSON([]string{"file", "-json=true"}) {
		t.Fatal("-json=true was not recognized")
	}
}

func TestPatchEntriesFollowArchivePatches(t *testing.T) {
	got, err := assignPatchEntries([]string{"base.bps", "fixes.zip", "more.ips", "extras.ZIP"}, []string{"fix.ips", "extra.bps"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", "fix.ips", "", "extra.bps"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("patch entries = %v, want %v", got, want)
	}
	if _, err := assignPatchEntries([]string{"base.bps"}, []string{"unused"}); err == nil {
		t.Fatal("entry for a raw patch was accepted")
	}
}

func TestRawInputSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patch.bps")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readInput(path, "", rompatcher.InputPatch, 3); err == nil {
		t.Fatal("readInput ignored the raw-file size limit")
	}
	if _, _, _, err := materializeInput(path, "", rompatcher.InputPatch, 3); err == nil {
		t.Fatal("materializeInput ignored the raw-file size limit")
	}
}

func TestBatchDryRunDoesNotRequireOutput(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.bin")
	patchPath := filepath.Join(dir, "empty.ips")
	manifestPath := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchPath, []byte("PATCHEOF"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(batchManifest{Jobs: []batchJob{{Source: source, Patches: []batchPatch{{Path: patchPath}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return batch(context.Background(), []string{manifestPath, "-n", "-j"}) }); err != nil {
		t.Fatal(err)
	}
}

func TestCLIWorkflow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	original := filepath.Join(dir, "original.bin")
	modified := filepath.Join(dir, "modified.bin")
	patch := filepath.Join(dir, "change.ips")
	output := filepath.Join(dir, "patched.bin")
	if err := os.WriteFile(original, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modified, []byte("abdXYZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	text, err := captureStdout(t, func() error {
		return create(ctx, []string{original, modified, "-f", "ips", "-o", patch, "-j"})
	})
	if err != nil || !bytes.Contains([]byte(text), []byte(`"status": "ok"`)) {
		t.Fatalf("create: %v, %s", err, text)
	}
	text, err = captureStdout(t, func() error { return inspect([]string{patch, "-j"}) })
	if err != nil || !bytes.Contains([]byte(text), []byte(`"format": "ips"`)) {
		t.Fatalf("inspect: %v, %s", err, text)
	}
	text, err = captureStdout(t, func() error {
		return apply(ctx, []string{original, patch, "-o", output, "-j"})
	})
	if err != nil || !bytes.Contains([]byte(text), []byte(`"status": "ok"`)) {
		t.Fatalf("apply: %v, %s", err, text)
	}
	text, err = captureStdout(t, func() error { return hashFile(ctx, []string{output, "-j"}) })
	if err != nil || !bytes.Contains([]byte(text), []byte(`"crc32"`)) {
		t.Fatalf("hash: %v, %s", err, text)
	}

	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	w, err := zw.Create("game.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("abc"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(dir, "games.zip")
	if err := os.WriteFile(zipPath, zipped.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	text, err = captureStdout(t, func() error { return archive([]string{zipPath, "-j"}) })
	if err != nil || !bytes.Contains([]byte(text), []byte(`"name": "game.bin"`)) {
		t.Fatalf("archive: %v, %s", err, text)
	}

	batchOutput := filepath.Join(dir, "batch.bin")
	manifestPath := filepath.Join(dir, "batch.json")
	manifest, _ := json.Marshal(batchManifest{Jobs: []batchJob{{Source: original, Patches: []batchPatch{{Path: patch}}, Output: batchOutput}}})
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	text, err = captureStdout(t, func() error { return batch(ctx, []string{manifestPath, "-j"}) })
	if err != nil || !bytes.Contains([]byte(text), []byte(`"status": "ok"`)) {
		t.Fatalf("batch: %v, %s", err, text)
	}
	got, err := os.ReadFile(batchOutput)
	if err != nil || string(got) != "abdXYZ" {
		t.Fatalf("batch output: %v, %q", err, got)
	}
}
