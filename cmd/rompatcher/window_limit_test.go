package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	rompatcher "github.com/olsonb97/RomPatcher.go"
)

func TestCLIWindowLimit(t *testing.T) {
	// One VCDIFF ADD window with four output bytes and five section bytes.
	patch := []byte{0xd6, 0xc3, 0xc4, 0, 0, 0, 10, 4, 0, 4, 1, 0, 'a', 'b', 'c', 'd', 5}
	for _, mode := range []string{"apply", "dry-run", "batch", "batch-dry-run"} {
		t.Run(mode, func(t *testing.T) {
			for _, limit := range []uint64{4, 5} {
				dir := t.TempDir()
				source, patchPath, output := filepath.Join(dir, "source.bin"), filepath.Join(dir, "patch.xdelta"), filepath.Join(dir, "output.bin")
				for path, data := range map[string][]byte{source: {}, patchPath: patch} {
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if mode == "apply" || mode == "dry-run" {
					args := []string{source, patchPath, "--max-window", strconv.FormatUint(limit, 10), "-o", output}
					if mode == "dry-run" {
						args = append(args, "--dry-run")
					}
					err = apply(context.Background(), args)
				} else {
					manifest, marshalErr := json.Marshal(batchManifest{Jobs: []batchJob{{Source: source, Patches: []batchPatch{{Path: patchPath}}, Output: output, MaxWindow: limit}}})
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					path := filepath.Join(dir, "batch.json")
					if err := os.WriteFile(path, manifest, 0o600); err != nil {
						t.Fatal(err)
					}
					args := []string{path}
					if mode == "batch-dry-run" {
						args = append(args, "--dry-run")
					}
					err = batch(context.Background(), args)
				}
				if limit == 4 {
					if !errors.Is(err, rompatcher.ErrOutputTooLarge) {
						t.Fatalf("limit 4: %v", err)
					}
					if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("rejected output exists: %v", statErr)
					}
				} else if err != nil {
					t.Fatalf("limit 5: %v", err)
				} else if mode == "apply" || mode == "batch" {
					data, err := os.ReadFile(output)
					if err != nil || string(data) != "abcd" {
						t.Fatalf("output=%q err=%v", data, err)
					}
				}
			}
		})
	}
}
