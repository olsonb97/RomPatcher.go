package rompatcher

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
)

func TestVCDIFFWindowLimitAllowsLargerCumulativeOutput(t *testing.T) {
	patch := []byte{0xd6, 0xc3, 0xc4, 0, 0}
	for _, data := range []string{"abcd", "efgh"} {
		patch = appendVCDDelta(append(patch, 0), 4, 0, []byte(data), []byte{5}, nil)
	}
	for _, limit := range []uint64{3, 4, 5} {
		opts := ApplyOptions{MaxOutputSize: 64 << 30, MaxWindowSize: limit}
		out, err := Apply(nil, patch, opts)
		var file memoryFile
		_, fileErr := ApplyReaderAt(context.Background(), bytes.NewReader(nil), 0, bytes.NewReader(patch), int64(len(patch)), &file, opts)
		if limit == 5 {
			if err != nil || fileErr != nil || string(out) != "abcdefgh" || !bytes.Equal(out, file.data) {
				t.Fatalf("cumulative output: memory=%q (%v), file=%q (%v)", out, err, file.data, fileErr)
			}
		} else if !errors.Is(err, ErrOutputTooLarge) || !errors.Is(fileErr, ErrOutputTooLarge) || len(file.data) != 0 {
			t.Fatalf("limit %d: memory=%v, file=%v, bytes written=%d", limit, err, fileErr, len(file.data))
		}
	}
}

func TestVCDIFFWindowLimitBoundsExpandedSections(t *testing.T) {
	// Encoded data fits within the limit, but its expansion plus instructions
	// does not. Keep the fixture small enough to exercise normal LZMA input.
	raw := bytes.Repeat([]byte("a"), 256)
	data := append(appendBE7(nil, uint64(len(raw))), xzSyncFlushFixture(t, raw)...)
	patch := []byte{0xd6, 0xc3, 0xc4, 0, vcdDecompress, vcdLZMASecondaryID, 0}
	patch = appendVCDDelta(patch, uint64(len(raw)), 1, data, appendBE7([]byte{1}, uint64(len(raw))), nil)
	opts := ApplyOptions{MaxOutputSize: 1024, MaxDictionarySize: 4096, MaxWindowSize: 256}
	if _, err := Apply(nil, patch, opts); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("expanded sections bypassed window limit: %v", err)
	}
	opts.MaxWindowSize = 259
	if out, err := Apply(nil, patch, opts); err != nil || !bytes.Equal(out, raw) {
		t.Fatalf("valid expanded sections: %q, %v", out, err)
	}
}

func TestVCDIFFSectionLengthOverflow(t *testing.T) {
	// The three lengths wrapped to one when added before validating them.
	maximum := uint64(^uint(0) >> 1)
	body := []byte{0, 0} // Target length and delta flags.
	body = appendBE7(body, maximum)
	body = appendBE7(body, maximum)
	body = appendBE7(body, 3)
	patch := appendBE7([]byte{0xd6, 0xc3, 0xc4, 0, 0, 0}, uint64(len(body)+1))
	patch = append(patch, body...)
	patch = append(patch, 0)
	if _, err := Parse(patch); !errors.Is(err, ErrUnexpectedEnd) {
		t.Fatalf("invalid section lengths: %v", err)
	}
	var out memoryFile
	if _, err := ApplyReaderAt(context.Background(), bytes.NewReader(nil), 0, bytes.NewReader(patch), int64(len(patch)), &out, ApplyOptions{}); !errors.Is(err, ErrUnexpectedEnd) {
		t.Fatalf("file-backed section lengths: %v", err)
	}
}

func TestVCDIFFSourceRangeReportsSourceMismatch(t *testing.T) {
	for _, indicator := range []byte{vcdSource, vcdTarget} {
		patch := []byte{0xd6, 0xc3, 0xc4, 0, 0, indicator, 4, 0}
		patch = appendVCDDelta(patch, 4, 0, nil, []byte{20}, []byte{0})
		want := ErrSourceMismatch
		if indicator == vcdTarget {
			want = ErrInvalidPatch
		}
		if _, err := Apply([]byte("abc"), patch, ApplyOptions{}); !errors.Is(err, want) {
			t.Fatalf("indicator %d: %v, want %v", indicator, err, want)
		}
		var out memoryFile
		if _, err := ApplyReaderAt(context.Background(), bytes.NewReader([]byte("abc")), 3, bytes.NewReader(patch), int64(len(patch)), &out, ApplyOptions{}); !errors.Is(err, want) {
			t.Fatalf("file-backed indicator %d: %v, want %v", indicator, err, want)
		}
	}
}

func TestApplyChainHonorsDictionaryLimitDuringInspection(t *testing.T) {
	patch, _, _ := nestedDictionaryFixture(t, 8<<20)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := ApplyChain(nil, [][]byte{patch}, ApplyOptions{MaxDictionarySize: 4096})
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("chain inspection dictionary limit: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("chain allocated %d bytes before applying its 4 KiB dictionary limit", allocated)
	}
	patch, _, _ = nestedDictionaryFixture(t, 4096)
	result, err := ApplyChain(nil, [][]byte{patch}, ApplyOptions{MaxDictionarySize: 4096})
	if err != nil || string(result.Output) != "x" || len(result.Steps) != 1 {
		t.Fatalf("valid chain: %+v, %v", result, err)
	}
	if _, err := ApplyChain(nil, [][]byte{patch}, ApplyOptions{MaxWindowSize: 1024}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("custom table bypassed chain window limit: %v", err)
	}
}

func TestVCDIFFInspectionUsesHeaderAdjustedOptions(t *testing.T) {
	_, nested, _ := nestedDictionaryFixture(t, 4096)
	patch := appendBE7([]byte{0xd6, 0xc3, 0xc4, 0, vcdCodeTable}, uint64(len(nested)+2))
	patch = append(patch, 4, 3)
	patch = append(patch, nested...)
	patch = appendVCDDelta(append(patch, 0), 17, 0, bytes.Repeat([]byte("x"), 17), []byte{18}, nil)
	source := make([]byte, 16<<10)
	// Adding the temporary iNES header raises the output allowance from 4080
	// to 4096, permitting this ordinary 4 KiB dictionary during application.
	opts := ApplyOptions{AddHeader: true, SourceName: "game.nes", MaxOutputSize: 4080}
	want, err := Apply(source, patch, opts)
	if err != nil || string(want) != "x" {
		t.Fatalf("direct application: %q, %v", want, err)
	}
	chain, err := ApplyChain(source, [][]byte{patch}, opts)
	if err != nil || !bytes.Equal(chain.Output, want) {
		t.Fatalf("chain application: %q, %v", chain.Output, err)
	}
	dry, err := DryRun(source, patch, opts)
	if err != nil || dry.Output.Size == nil || *dry.Output.Size != uint64(len(want)) {
		t.Fatalf("dry run: %+v, %v", dry, err)
	}
}
