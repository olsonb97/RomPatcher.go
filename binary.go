package rompatcher

import (
	"encoding/binary"
	"fmt"
)

type decoder struct {
	b   []byte
	off int
}

func newDecoder(b []byte) *decoder { return &decoder{b: b} }
func (d *decoder) remaining() int  { return len(d.b) - d.off }
func (d *decoder) eof() bool       { return d.off >= len(d.b) }

func (d *decoder) seek(off int) error {
	if off < 0 || off > len(d.b) {
		return fmt.Errorf("%w: offset %d", ErrUnexpectedEnd, off)
	}
	d.off = off
	return nil
}

func (d *decoder) skip(n int) error {
	if n < 0 || n > d.remaining() {
		return fmt.Errorf("%w at patch offset %d: cannot skip %d bytes with %d remaining", ErrUnexpectedEnd, d.off, n, d.remaining())
	}
	d.off += n
	return nil
}

func addInt64(a, b int64) (int64, bool) {
	const max = int64(^uint64(0) >> 1)
	const min = -max - 1
	if b > 0 && a > max-b || b < 0 && a < min-b {
		return 0, false
	}
	return a + b, true
}

func (d *decoder) u8() (byte, error) {
	if d.remaining() < 1 {
		return 0, fmt.Errorf("%w at patch offset %d: need 1 byte, have %d", ErrUnexpectedEnd, d.off, d.remaining())
	}
	v := d.b[d.off]
	d.off++
	return v, nil
}

func (d *decoder) bytes(n int) ([]byte, error) {
	if n < 0 || d.remaining() < n {
		return nil, fmt.Errorf("%w at patch offset %d: need %d bytes, have %d", ErrUnexpectedEnd, d.off, n, d.remaining())
	}
	v := d.b[d.off : d.off+n]
	d.off += n
	return v, nil
}

func (d *decoder) string(n int) (string, error) {
	b, err := d.bytes(n)
	return string(b), err
}

func (d *decoder) u16be() (uint16, error) {
	b, err := d.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (d *decoder) u16le() (uint16, error) {
	b, err := d.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (d *decoder) u24be() (uint32, error) {
	b, err := d.bytes(3)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}

func (d *decoder) u32be() (uint32, error) {
	b, err := d.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (d *decoder) u32le() (uint32, error) {
	b, err := d.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (d *decoder) u64le() (uint64, error) {
	b, err := d.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func appendU16BE(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func appendU16LE(dst []byte, v uint16) []byte {
	return append(dst, byte(v), byte(v>>8))
}

func appendU24BE(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>16), byte(v>>8), byte(v))
}

func appendU32BE(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendU32LE(dst []byte, v uint32) []byte {
	return append(dst, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func checkedInt(v uint64) (int, error) {
	n := int(v)
	if n < 0 || uint64(n) != v {
		return 0, fmt.Errorf("%w: size %d is too large", ErrInvalidPatch, v)
	}
	return n, nil
}

func fillBytes(dst []byte, value byte) {
	if len(dst) == 0 {
		return
	}
	dst[0] = value
	for filled := 1; filled < len(dst); {
		filled += copy(dst[filled:], dst[:filled])
	}
}

// copyOverlapping copies forward from already-produced bytes, expanding the
// copied prefix exponentially when source and destination overlap.
func copyOverlapping(dst []byte, destination, source, length int) bool {
	if length < 0 || source < 0 || source >= destination || destination < 0 || destination > len(dst)-length {
		return false
	}
	first := destination - source
	if length < first {
		first = length
	}
	copy(dst[destination:destination+first], dst[source:source+first])
	for written := first; written < length; {
		n := written
		if length-written < n {
			n = length - written
		}
		copy(dst[destination+written:destination+written+n], dst[destination:destination+n])
		written += n
	}
	return true
}

func fillPattern(dst, pattern []byte, phase int) {
	if len(dst) == 0 || len(pattern) == 0 {
		return
	}
	phase %= len(pattern)
	filled := copy(dst, pattern[phase:])
	if filled < len(dst) && phase != 0 {
		filled += copy(dst[filled:], pattern[:phase])
	}
	for filled < len(dst) {
		filled += copy(dst[filled:], dst[:filled])
	}
}

func fixedString(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}
