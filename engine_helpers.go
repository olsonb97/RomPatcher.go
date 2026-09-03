package rompatcher

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
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
