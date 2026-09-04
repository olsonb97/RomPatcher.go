package rompatcher

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

type readerDecoder struct {
	ctx        context.Context
	r          io.ReaderAt
	size       int64
	off        int64
	cache      []byte
	cacheStart int64
}

func newReaderDecoder(ctx context.Context, r io.ReaderAt, size int64) *readerDecoder {
	if ctx == nil {
		ctx = context.Background()
	}
	return &readerDecoder{ctx: ctx, r: r, size: size}
}

func (d *readerDecoder) remaining() int64 { return d.size - d.off }
func (d *readerDecoder) eof() bool        { return d.off == d.size }

func (d *readerDecoder) seek(offset int64) error {
	if offset < 0 || offset > d.size {
		return fmt.Errorf("%w: offset %d", ErrUnexpectedEnd, offset)
	}
	d.off = offset
	return nil
}

func (d *readerDecoder) skip(length int64) error {
	if length < 0 || length > d.remaining() {
		return fmt.Errorf("%w at patch offset %d: cannot skip %d bytes with %d remaining", ErrUnexpectedEnd, d.off, length, d.remaining())
	}
	d.off += length
	return d.ctx.Err()
}

func (d *readerDecoder) read(dst []byte) error {
	if int64(len(dst)) > d.remaining() {
		return fmt.Errorf("%w at patch offset %d: need %d bytes, have %d", ErrUnexpectedEnd, d.off, len(dst), d.remaining())
	}
	if err := d.ctx.Err(); err != nil {
		return err
	}
	for len(dst) > 0 {
		if err := d.ctx.Err(); err != nil {
			return err
		}
		cacheOffset := d.off - d.cacheStart
		if cacheOffset < 0 || cacheOffset >= int64(len(d.cache)) {
			length := int64(64 << 10)
			if d.size-d.off < length {
				length = d.size - d.off
			}
			if cap(d.cache) < int(length) {
				d.cache = make([]byte, int(length))
			} else {
				d.cache = d.cache[:int(length)]
			}
			d.cacheStart = d.off
			if err := readAtFull(d.r, d.cache, d.off); err != nil {
				return err
			}
			cacheOffset = 0
		}
		n := copy(dst, d.cache[int(cacheOffset):])
		d.off += int64(n)
		dst = dst[n:]
	}
	return nil
}

func (d *readerDecoder) bytes(length int64) ([]byte, error) {
	if length < 0 || uint64(length) > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("%w: byte field length %d cannot be represented", ErrInvalidPatch, length)
	}
	out := make([]byte, int(length))
	if err := d.read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *readerDecoder) u8() (byte, error) {
	var data [1]byte
	if err := d.read(data[:]); err != nil {
		return 0, err
	}
	return data[0], nil
}

func (d *readerDecoder) u16be() (uint16, error) {
	var data [2]byte
	if err := d.read(data[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(data[:]), nil
}

func (d *readerDecoder) u16le() (uint16, error) {
	var data [2]byte
	if err := d.read(data[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(data[:]), nil
}

func (d *readerDecoder) u24be() (uint32, error) {
	var data [3]byte
	if err := d.read(data[:]); err != nil {
		return 0, err
	}
	return uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]), nil
}

func (d *readerDecoder) u32be() (uint32, error) {
	var data [4]byte
	if err := d.read(data[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data[:]), nil
}

func (d *readerDecoder) u32le() (uint32, error) {
	var data [4]byte
	if err := d.read(data[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data[:]), nil
}

func (d *readerDecoder) u64le() (uint64, error) {
	var data [8]byte
	if err := d.read(data[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

func readBPSVLVReader(d *readerDecoder) (uint64, error) {
	var value, shift uint64 = 0, 1
	for i := 0; i < 10; i++ {
		x, err := d.u8()
		if err != nil {
			return 0, err
		}
		add := uint64(x&0x7f) * shift
		if value > ^uint64(0)-add {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		value += add
		if x&0x80 != 0 {
			return value, nil
		}
		if shift > ^uint64(0)>>7 {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		shift <<= 7
		if value > ^uint64(0)-shift {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		value += shift
	}
	return 0, fmt.Errorf("%w: variable integer too long", ErrInvalidPatch)
}

func readBE7Reader(d *readerDecoder) (uint64, error) {
	var value uint64
	for i := 0; i < 10; i++ {
		x, err := d.u8()
		if err != nil {
			return 0, err
		}
		if value > ^uint64(0)>>7 {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		value = value<<7 | uint64(x&0x7f)
		if x&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("%w: variable integer too long", ErrInvalidPatch)
}

func readRUPVLVReader(d *readerDecoder) (uint64, error) {
	n, err := d.u8()
	if err != nil {
		return 0, err
	}
	if n > 8 {
		return 0, fmt.Errorf("%w: RUP integer too long", ErrInvalidPatch)
	}
	var value uint64
	for i := 0; i < int(n); i++ {
		b, err := d.u8()
		if err != nil {
			return 0, err
		}
		value |= uint64(b) << (8 * i)
	}
	return value, nil
}

func sectionReader(r io.ReaderAt, offset, length int64) *io.SectionReader {
	return io.NewSectionReader(r, offset, length)
}
