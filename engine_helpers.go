package rompatcher

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func sourceSizeMismatch(format Format, actual int64, opts ApplyOptions, expected ...uint64) error {
	values := make([]string, 0, len(expected))
	seen := make(map[uint64]struct{}, len(expected))
	for _, size := range expected {
		if _, exists := seen[size]; exists {
			continue
		}
		seen[size] = struct{}{}
		values = append(values, strconv.FormatUint(size, 10))
	}
	detail := fmt.Sprintf("%s source is %d bytes", strings.ToUpper(string(format)), actual)
	if len(values) == 1 {
		detail += "; patch expects " + values[0] + " bytes"
	} else if len(values) > 1 {
		detail += "; patch accepts " + strings.Join(values, " or ") + " bytes"
	}
	if actual >= 0 {
		if header := canAddHeaderSize(actual, opts.SourceName); header != nil {
			for size := range seen {
				if size == uint64(actual)+uint64(header.Size) {
					return fmt.Errorf("%w: %s (a recognized %d-byte file header); try --add-header", ErrSourceMismatch, detail, header.Size)
				}
			}
		}
	}
	return fmt.Errorf("%w: %s", ErrSourceMismatch, detail)
}

func checksumMismatch(kind error, format Format, algorithm, expected, actual string) error {
	return fmt.Errorf("%w: %s %s expected %s, got %s", kind, strings.ToUpper(string(format)), algorithm, expected, actual)
}

func checksum32Mismatch(kind error, format Format, algorithm string, expected, actual uint32) error {
	return checksumMismatch(kind, format, algorithm, fmt.Sprintf("%08x", expected), fmt.Sprintf("%08x", actual))
}

func initializeOutput(source io.ReaderAt, sourceSize, targetSize int64, output io.WriterAt, opts ApplyOptions, format Format) error {
	copySize := sourceSize
	if targetSize < copySize {
		copySize = targetSize
	}
	if err := copyReaderAt(opts, output, source, copySize, format); err != nil {
		return err
	}
	if targetSize > copySize {
		return zeroRange(opts, output, copySize, targetSize-copySize, format)
	}
	return nil
}

func ppfBytesEqualAt(source io.ReaderAt, sourceSize int64, offset uint64, expected, scratch []byte) (bool, error) {
	if offset > uint64(sourceSize) || uint64(len(expected)) > uint64(sourceSize)-offset {
		return false, nil
	}
	if len(scratch) < len(expected) {
		return false, fmt.Errorf("%w: PPF comparison buffer", ErrInvalidPatch)
	}
	buf := scratch[:len(expected)]
	if err := readAtFull(source, buf, int64(offset)); err != nil {
		return false, err
	}
	return bytes.Equal(buf, expected), nil
}

func md5ReaderAt(opts ApplyOptions, r io.ReaderAt, size int64, format Format, phase string) (string, error) {
	h := md5.New()
	buf := make([]byte, checksumChunkSize)
	for off := int64(0); off < size; {
		n := min64(int64(len(buf)), size-off)
		if err := readAtFull(r, buf[:n], off); err != nil {
			return "", err
		}
		_, _ = h.Write(buf[:n])
		off += n
		if err := reportProgress(opts, Progress{Phase: phase, Format: format, Completed: off, Total: size}); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
