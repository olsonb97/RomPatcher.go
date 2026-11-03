package rompatcher

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/ulikunitz/xz/lzma"
)

type eofCancelReader struct {
	data   string
	cancel context.CancelFunc
}

func (r eofCancelReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	if r.cancel != nil {
		r.cancel()
	}
	return n, io.EOF
}

func TestHashReaderFinalReadCancellation(t *testing.T) {
	for _, data := range []string{"", "abc"} {
		got, err := HashReader(context.Background(), eofCancelReader{data: data})
		if err != nil || got != HashBytes([]byte(data)) {
			t.Fatalf("final data with EOF: %+v, %v", got, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		got, err = HashReader(ctx, eofCancelReader{data: data, cancel: cancel})
		cancel()
		if !errors.Is(err, context.Canceled) || got != (HashInfo{}) {
			t.Fatalf("canceled final read: %+v, %v", got, err)
		}
	}
}

func nestedDictionaryFixture(t testing.TB, dictionary int64) (patch, nested, data []byte) {
	t.Helper()
	raw := encodeVCDTable(vcdTable)
	compressed := xzSyncFlushFixture(t, raw)
	compressed[16] = lzma.EncodeDictCap(dictionary)
	headerEnd := 12 + (int(compressed[12])+1)*4
	binary.LittleEndian.PutUint32(compressed[headerEnd-4:headerEnd], crc32.ChecksumIEEE(compressed[12:headerEnd-4]))
	data = append(appendBE7(nil, uint64(len(raw))), compressed...)
	inst := appendBE7([]byte{1}, uint64(len(raw)))
	nested = []byte{0xd6, 0xc3, 0xc4, 0, vcdDecompress, 2, 0}
	nested = appendVCDDelta(nested, uint64(len(raw)), 1, data, inst, nil)
	patch = []byte{0xd6, 0xc3, 0xc4, 0, vcdCodeTable}
	patch = appendBE7(patch, uint64(len(nested)+2))
	patch = append(patch, 4, 3)
	patch = append(patch, nested...)
	patch = append(patch, 0)
	patch = appendVCDDelta(patch, 1, 0, []byte("x"), []byte{2}, nil)
	return
}

func TestFollowupNestedDictionaryLimit(t *testing.T) {
	patch, nested, data := nestedDictionaryFixture(t, 8<<20)
	opts := ApplyOptions{MaxDictionarySize: 1 << 20}
	if _, err := new(vcdLZMADecoder).decode(data, opts, 0, 256*6); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("control: %v", err)
	}
	var out memoryFile
	n, err := ApplyReaderAt(context.Background(), bytes.NewReader(nil), 0, bytes.NewReader(patch), int64(len(patch)), &out, opts)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("8 MiB dictionary bypassed 1 MiB cap through custom table: n=%d error=%v", n, err)
	}
	if _, err := DryRun(nil, patch, opts); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("dry-run dictionary error = %v", err)
	}
	allowed := ApplyOptions{MaxDictionarySize: 16 << 20, MaxOutputSize: 2}
	if got, err := Apply(nil, patch, allowed); err != nil || string(got) != "x" {
		t.Fatalf("allowed dictionary with small final-output limit: %q, %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := decodeVCDCodeTable(ctx, nested, 1, allowed); !errors.Is(err, context.Canceled) {
		t.Fatalf("nested cancellation = %v", err)
	}
	if _, err := decodeVCDCodeTable(followupCancelAfter(t, 16), nested, 1, allowed); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during nested decoding = %v", err)
	}
}

func TestFollowupDryRunDirection(t *testing.T) {
	for _, format := range []Format{FormatUPS, FormatRUP} {
		t.Run(string(format), func(t *testing.T) {
			p, err := Create([]byte("a"), []byte("b"), format, nil)
			if err != nil {
				t.Fatal(err)
			}
			patch, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			result, err := DryRun([]byte("b"), patch, ApplyOptions{Direction: ApplyDirectionForward, Validate: true})
			if !errors.Is(err, ErrSourceMismatch) {
				t.Fatalf("expected source mismatch: %v", err)
			}
			if result.SourceValid == nil || *result.SourceValid {
				t.Errorf("SourceValid=%v despite wrong forward endpoint (%v)", result.SourceValid, err)
			}
			for _, tc := range []struct {
				source    string
				direction ApplyDirection
				valid     bool
			}{
				{"a", ApplyDirectionForward, true},
				{"b", ApplyDirectionReverse, true},
				{"a", ApplyDirectionReverse, false},
				{"b", ApplyDirectionForward, false},
				{"a", ApplyDirectionAuto, true},
				{"b", ApplyDirectionAuto, true},
			} {
				for _, validate := range []bool{false, true} {
					result, err := DryRun([]byte(tc.source), patch, ApplyOptions{Direction: tc.direction, Validate: validate})
					if result.SourceValid == nil || *result.SourceValid != tc.valid {
						t.Errorf("source=%q direction=%s validate=%v: SourceValid=%v", tc.source, tc.direction, validate, result.SourceValid)
					}
					if (tc.valid || !validate) && err != nil {
						t.Errorf("source=%q direction=%s: %v", tc.source, tc.direction, err)
					}
				}
			}
		})
	}
}

// Trigger cancellation after multiple checkpoints without depending on timing.
type followupCountingContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *followupCountingContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}
func followupCancelAfter(t *testing.T, checks int) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &followupCountingContext{Context: ctx, cancel: cancel, remaining: checks}
}

func TestSerializationCancelsDuringRecordProcessing(t *testing.T) {
	const count = 128
	ips := &IPSPatch{}
	ips32 := &IPS32Patch{}
	aps := &APSN64Patch{TargetSize: 1}
	gba := &APSGBAPatch{SourceSize: apsGBABlockSize, TargetSize: apsGBABlockSize}
	bps := &BPSPatch{SourceSize: count, TargetSize: count}
	ups := &UPSPatch{SourceSize: count * 2, TargetSize: count * 2}
	ppf := &PPFPatch{Version: 1}
	rup := &RUPPatch{files: []rupFile{{SourceSize: 1, TargetSize: 1, SourceMD5: MD5([]byte("a")), TargetMD5: MD5([]byte("b"))}}}
	block := make([]byte, apsGBABlockSize)
	for i := 0; i < count; i++ {
		ips.records = append(ips.records, ipsRecord{data: []byte("x")})
		ips32.records = append(ips32.records, ipsRecord{data: []byte("x")})
		aps.records = append(aps.records, apsRecord{data: []byte("x")})
		gba.records = append(gba.records, apsGBARecord{xor: block})
		bps.actions = append(bps.actions, bpsAction{typ: bpsSourceRead, length: 1})
		ups.records = append(ups.records, upsRecord{xor: []byte{1}})
		ppf.records = append(ppf.records, ppfRecord{data: []byte("x")})
		rup.files[0].records = append(rup.files[0].records, rupRecord{xor: []byte{1}})
	}
	for _, p := range []Patch{ips, ips32, aps, gba, bps, ups, ppf, rup} {
		t.Run(string(p.Format()), func(t *testing.T) {
			if _, err := p.MarshalBinary(); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			if _, err := marshalPatchContext(followupCancelAfter(t, 8), p); !errors.Is(err, context.Canceled) {
				t.Fatalf("serialization cancellation=%v", err)
			}
		})
	}
}

func TestCancellationDuringLargeMemoryOperations(t *testing.T) {
	data := make([]byte, 8<<20)
	t.Run("literal", func(t *testing.T) {
		p := &BPSPatch{TargetSize: uint64(len(data)), actions: []bpsAction{{typ: bpsTargetRead, length: len(data), data: data}}}
		if _, err := marshalPatchContext(followupCancelAfter(t, 6), p); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("hash", func(t *testing.T) {
		if _, err := crc32BytesContext(followupCancelAfter(t, 3), data); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("add-header", func(t *testing.T) {
		if _, _, err := addHeaderContext(followupCancelAfter(t, 4), data, "game.sfc"); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("remove-header", func(t *testing.T) {
		headered := make([]byte, len(data)+512)
		if _, _, _, err := removeHeaderContext(followupCancelAfter(t, 4), headered, "game.sfc"); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("checksum", func(t *testing.T) {
		copy(data[0x100:], "SEGA GENESIS")
		data[0x18e], data[0x18f] = 1, 2
		if _, err := fixROMChecksumContext(followupCancelAfter(t, 4), data, "game.md"); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if data[0x18e] != 1 || data[0x18f] != 2 {
			t.Fatal("checksum changed after cancellation")
		}
	})
}

func TestAppendContextBytesAndStrings(t *testing.T) {
	for _, size := range []int{0, 1, fileChunkSize - 1, fileChunkSize, fileChunkSize + 1} {
		data := bytes.Repeat([]byte("x"), size)
		for _, appendData := range []func(context.Context, []byte) ([]byte, error){
			func(ctx context.Context, dst []byte) ([]byte, error) { return appendContext(ctx, dst, data) },
			func(ctx context.Context, dst []byte) ([]byte, error) { return appendContext(ctx, dst, string(data)) },
		} {
			ctx, cancel := context.WithCancel(context.Background())
			for _, active := range []context.Context{context.Background(), ctx} {
				got, err := appendData(active, []byte("prefix"))
				if err != nil || !bytes.Equal(got, append([]byte("prefix"), data...)) {
					t.Fatalf("append size=%d: %v", size, err)
				}
			}
			cancel()
			if _, err := appendData(ctx, nil); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled append size=%d: %v", size, err)
			}
			if size > fileChunkSize {
				if _, err := appendData(followupCancelAfter(t, 3), nil); !errors.Is(err, context.Canceled) {
					t.Fatalf("mid-append cancellation: %v", err)
				}
			}
		}
	}
}

func TestCustomTableRejectsOversizedOutputBeforeReadingSections(t *testing.T) {
	nested := []byte{0xd6, 0xc3, 0xc4, 0, 0, 0}
	nested = appendVCDDelta(nested, 256*6+1, 0, nil, nil, nil)
	if _, err := decodeVCDCodeTable(context.Background(), nested, 1, ApplyOptions{}); !errors.Is(err, ErrInvalidPatch) || !strings.Contains(err.Error(), "exceeds 1536") {
		t.Fatalf("table output bound=%v", err)
	}
}

func TestNestedCodeTableDepthLimit(t *testing.T) {
	_, encoded, _ := nestedDictionaryFixture(t, 4096)
	raw := encodeVCDTable(vcdTable)
	for depth := 1; depth <= 5; depth++ {
		_, err := decodeVCDCodeTable(context.Background(), encoded, 1, ApplyOptions{})
		if depth <= 4 && err != nil {
			t.Fatalf("valid depth %d: %v", depth, err)
		}
		if depth == 5 && (!errors.Is(err, ErrInvalidPatch) || !strings.Contains(err.Error(), "nested VCDIFF")) {
			t.Fatalf("excess depth: %v", err)
		}
		wrapper := appendBE7([]byte{0xd6, 0xc3, 0xc4, 0, vcdCodeTable}, uint64(len(encoded)+2))
		wrapper = append(wrapper, 4, 3)
		wrapper = append(wrapper, encoded...)
		wrapper = append(wrapper, 0)
		encoded = appendVCDDelta(wrapper, uint64(len(raw)), 0, raw, appendBE7([]byte{1}, uint64(len(raw))), nil)
	}
}

func TestChecksumChunksPreserveWordAndOddByteBoundaries(t *testing.T) {
	for _, payloadSize := range []int{checksumChunkSize - 1, checksumChunkSize, checksumChunkSize + 1, 2*checksumChunkSize + 3} {
		data := make([]byte, 0x200+payloadSize)
		copy(data[0x100:], "SEGA GENESIS")
		for i := 0x200; i < len(data); i++ {
			data[i] = 1
		}
		want := uint16(uint64(payloadSize/2) * 0x0101)
		if _, err := fixROMChecksumContext(context.Background(), data, "game.md"); err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint16(data[0x18e:0x190]); got != want {
			t.Fatalf("payload=%d checksum=%04x, want %04x", payloadSize, got, want)
		}
	}
}

type followupMarshalProbe struct {
	basePatch
	called bool
}

func (*followupMarshalProbe) Format() Format                             { return FormatIPS }
func (*followupMarshalProbe) Apply([]byte, ApplyOptions) ([]byte, error) { return nil, ErrUnsupported }
func (p *followupMarshalProbe) MarshalBinary() ([]byte, error) {
	p.called = true
	return []byte("PATCHEOF"), nil
}
func TestFollowupCanceledParsedApply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := &followupMarshalProbe{}
	_, err := ApplyParsedWithOptions(nil, p, ApplyOptions{Context: ctx})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if p.called {
		t.Error("MarshalBinary called despite cancellation before operation")
	}
}

type followupMetadataReader struct {
	*bytes.Reader
	cancel   context.CancelFunc
	canceled bool
	after    int
}

func (r *followupMetadataReader) ReadAt(b []byte, off int64) (int, error) {
	if r.canceled {
		r.after++
	}
	n, err := r.Reader.ReadAt(b, off)
	if off == 9 && !r.canceled {
		r.cancel()
		r.canceled = true
	}
	return n, err
}
func TestFollowupMetadataCancellationBelowCap(t *testing.T) {
	data := []byte("PATCHEOF{\"x\":\"" + strings.Repeat("a", 128<<10) + "\"}")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &followupMetadataReader{Reader: bytes.NewReader(data), cancel: cancel}
	_, err := scanIPSStream(ctx, r, int64(len(data)), 0, false)
	if !errors.Is(err, context.Canceled) || r.after != 0 {
		t.Fatalf("error=%v reads-after-cancel=%d", err, r.after)
	}
}
