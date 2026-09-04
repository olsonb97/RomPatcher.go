package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	args := []string{"game.sfc", "base.bps", "-v", "fix.ips", "--patch-entry", "base/in.zip", "-e", "fix/in.zip", "-o", "final.sfc", "-j", "-d", "reverse"}
	if err := parseInterspersed(f, args); err != nil {
		t.Fatal(err)
	}
	if !o.validate || !o.jsonOutput || o.output != "final.sfc" || o.directionName != "reverse" {
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

func TestConflictingAndFormatSpecificFlagsFailEarly(t *testing.T) {
	ctx := context.Background()
	if err := apply(ctx, []string{"missing.rom", "missing.ips", "--add-header", "--remove-header"}); err == nil {
		t.Fatal("conflicting header flags were accepted")
	}
	if err := apply(ctx, []string{"missing.rom", "missing.ups", "--direction", "backward"}); err == nil || !strings.Contains(err.Error(), "auto, forward, or reverse") {
		t.Fatalf("invalid direction error = %v", err)
	}
	if err := apply(ctx, []string{"missing.rom", "one.ups", "two.ups", "--direction", "reverse"}); err == nil || !strings.Contains(err.Error(), "exactly one patch") {
		t.Fatalf("multi-patch direction error = %v", err)
	}
	if err := create(ctx, []string{"missing.rom", "missing-modified.rom", "--format", "ips", "--title", "unused"}); err == nil {
		t.Fatal("EBP-only metadata flag was accepted for IPS")
	}
}

func TestCLIReversibleDirection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	originalData := []byte("short original")
	modifiedData := []byte("a longer modified endpoint")
	modifiedPath := filepath.Join(dir, "modified.bin")
	if err := os.WriteFile(modifiedPath, modifiedData, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, format := range []rompatcher.Format{rompatcher.FormatUPS, rompatcher.FormatRUP} {
		patch, err := rompatcher.Create(originalData, modifiedData, format, nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := patch.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		patchPath := filepath.Join(dir, "change."+string(format))
		if err := os.WriteFile(patchPath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		outputPath := filepath.Join(dir, "restored-"+string(format)+".bin")
		if err := apply(ctx, []string{modifiedPath, patchPath, "-d", "reverse", "-o", outputPath}); err != nil {
			t.Fatalf("%s reverse: %v", format, err)
		}
		got, err := os.ReadFile(outputPath)
		if err != nil || !bytes.Equal(got, originalData) {
			t.Fatalf("%s reverse output: %v, %q", format, err, got)
		}
		if _, err := captureStdout(t, func() error {
			return apply(ctx, []string{modifiedPath, patchPath, "-d", "reverse", "-n", "-j"})
		}); err != nil {
			t.Fatalf("%s reverse dry run: %v", format, err)
		}
	}
}

func TestBatchReversibleDirection(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	originalData, modifiedData := []byte("original"), []byte("modified endpoint")
	patch, err := rompatcher.Create(originalData, modifiedData, rompatcher.FormatUPS, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := patch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "modified.bin")
	patchPath := filepath.Join(dir, "change.ups")
	outputPath := filepath.Join(dir, "original.bin")
	manifestPath := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(sourcePath, modifiedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(patchPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(batchManifest{Jobs: []batchJob{{
		Source: sourcePath, Patches: []batchPatch{{Path: patchPath}}, Output: outputPath,
		Direction: rompatcher.ApplyDirectionReverse,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := batch(ctx, []string{manifestPath}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(got, originalData) {
		t.Fatalf("batch reverse output: %v, %q", err, got)
	}
}

func TestFlagDiagnosticsStayMachineReadable(t *testing.T) {
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	var output bytes.Buffer
	f.SetOutput(&output)
	f.Usage = func() { fmt.Fprintln(f.Output(), "usage: test") }
	if err := parseInterspersed(f, []string{"--unknown", "-j"}); err == nil {
		t.Fatal("unknown flag was accepted")
	}
	if output.Len() != 0 {
		t.Fatalf("parse diagnostics leaked before JSON error: %q", output.String())
	}

	help := flag.NewFlagSet("test", flag.ContinueOnError)
	output.Reset()
	help.SetOutput(&output)
	help.Usage = func() { fmt.Fprintln(help.Output(), "usage: test") }
	if err := parseInterspersed(help, []string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("help error = %v", err)
	}
	if output.String() != "usage: test\n" {
		t.Fatalf("help output = %q", output.String())
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
