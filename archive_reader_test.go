package rompatcher

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
)

func archiveReaderFixture(t *testing.T, names ...string) ([]byte, *zip.Reader) {
	t.Helper()
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	for _, name := range names {
		entry, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, "contents of "+name); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(data.Bytes()), int64(data.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return data.Bytes(), r
}

func TestZIPReaderListAndExtractReuseArchive(t *testing.T) {
	data, r := archiveReaderFixture(t, "game.gba", "fix.ips")
	listed := ListZIPReader(r)
	want, err := ListZIPBytes(data)
	if err != nil || !reflect.DeepEqual(listed, want) {
		t.Fatalf("list = %v, %v; want %v", listed, err, want)
	}
	listed[0].Name = "changed by caller"
	if got := ListZIPReader(r); !reflect.DeepEqual(got, want) {
		t.Fatalf("caller changed archive metadata: %v", got)
	}
	for _, tc := range []struct {
		kind InputKind
		name string
	}{{InputSource, "game.gba"}, {InputPatch, "fix.ips"}, {InputSource, "game.gba"}} {
		var out bytes.Buffer
		name, err := ExtractZIPReader(r, "", tc.kind, 100, &out)
		if err != nil || name != tc.name || out.String() != "contents of "+tc.name {
			t.Fatalf("extract %s = %q, %q, %v", tc.kind, name, out.String(), err)
		}
	}
}

func TestZIPReaderSelectionAndLimits(t *testing.T) {
	_, r := archiveReaderFixture(t, "first.gba", "second.gba")
	var out bytes.Buffer
	if _, err := ExtractZIPReader(r, "", InputSource, 0, &out); !errors.Is(err, ErrAmbiguousArchive) {
		t.Fatalf("ambiguous selection error = %v", err)
	}
	if _, err := ExtractZIPReader(r, "first.gba", InputSource, 1, &out); err == nil {
		t.Fatal("size limit was ignored")
	}
	if out.Len() != 0 {
		t.Fatalf("selection failure wrote %d bytes", out.Len())
	}
	name, err := ExtractZIPReader(r, "second.gba", InputSource, 0, &out)
	if err != nil || name != "second.gba" || out.String() != "contents of second.gba" {
		t.Fatalf("explicit selection = %q, %q, %v", name, out.String(), err)
	}
	_, duplicate := archiveReaderFixture(t, "same.gba", "same.gba")
	if _, err := ExtractZIPReader(duplicate, "same.gba", InputSource, 0, io.Discard); !errors.Is(err, ErrAmbiguousArchive) {
		t.Fatalf("duplicate name error = %v", err)
	}
}

type archiveWriterFunc func([]byte) (int, error)

func (f archiveWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestZIPReaderCancellationAndWriterErrors(t *testing.T) {
	_, r := archiveReaderFixture(t, "game.gba")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if _, err := ExtractZIPReaderContext(ctx, r, "", InputSource, 0, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatalf("pre-cancelled extraction = %d bytes, %v", out.Len(), err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	writer := archiveWriterFunc(func(p []byte) (int, error) {
		cancel()
		return len(p), nil
	})
	if _, err := ExtractZIPReaderContext(ctx, r, "", InputSource, 0, writer); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel during write error = %v", err)
	}
	short := archiveWriterFunc(func(p []byte) (int, error) { return len(p) - 1, nil })
	if _, err := ExtractZIPReader(r, "", InputSource, 0, short); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v", err)
	}
	want := errors.New("destination failed")
	failure := archiveWriterFunc(func([]byte) (int, error) { return 0, want })
	if _, err := ExtractZIPReader(r, "", InputSource, 0, failure); !errors.Is(err, want) {
		t.Fatalf("write failure = %v", err)
	}
	if _, err := ExtractZIPReaderContext(nil, r, "", InputSource, 0, io.Discard); err != nil {
		t.Fatalf("archive unusable after failed extraction: %v", err)
	}
}

func TestZIPReaderRejectsCorruptionAndNilArguments(t *testing.T) {
	data, r := archiveReaderFixture(t, "game.gba")
	offset, err := r.File[0].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	data[offset] ^= 1
	if _, err := ExtractZIPReader(r, "", InputSource, 0, io.Discard); !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("corrupt entry error = %v", err)
	}
	if got := ListZIPReader(nil); got != nil {
		t.Fatalf("nil archive list = %v", got)
	}
	if _, err := ExtractZIPReader(nil, "", InputAny, 0, io.Discard); err == nil {
		t.Fatal("nil reader was accepted")
	}
	var nilBuffer *bytes.Buffer
	if _, err := ExtractZIPReader(r, "", InputAny, 0, nilBuffer); err == nil {
		t.Fatal("nil destination was accepted")
	}
}
