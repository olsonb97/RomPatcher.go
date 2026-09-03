package rompatcher

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

const vcdLZMASecondaryID = 2

type vcdSectionFeed struct {
	ctx  context.Context
	data []byte
	off  int
}

func (f *vcdSectionFeed) Read(p []byte) (int, error) {
	select {
	case <-f.ctx.Done():
		return 0, f.ctx.Err()
	default:
	}
	if f.off == len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

type vcdLZMADecoder struct {
	feed   vcdSectionFeed
	reader *xz.Reader
}

func readXZVLI(data []byte, off *int) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 63 && *off < len(data); shift += 7 {
		b := data[*off]
		(*off)++
		if shift == 56 && b > 0x7f {
			return 0, ErrInvalidPatch
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, nil
		}
	}
	return 0, ErrUnexpectedEnd
}

func validateXZDictionary(data []byte, limit uint64) error {
	if len(data) < 16 || !bytes.Equal(data[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0}) {
		return fmt.Errorf("%w: VCDIFF LZMA XZ header", ErrInvalidPatch)
	}
	headerEnd := 12 + (int(data[12])+1)*4
	if headerEnd > len(data) || headerEnd < 20 {
		return fmt.Errorf("%w: VCDIFF LZMA block header", ErrInvalidPatch)
	}
	flags := data[13]
	if flags&0xf0 != 0 {
		return fmt.Errorf("%w: VCDIFF LZMA block flags", ErrInvalidPatch)
	}
	off := 14
	if flags&0x40 != 0 {
		if _, err := readXZVLI(data[:headerEnd-4], &off); err != nil {
			return fmt.Errorf("%w: VCDIFF LZMA compressed size", ErrInvalidPatch)
		}
	}
	if flags&0x80 != 0 {
		if _, err := readXZVLI(data[:headerEnd-4], &off); err != nil {
			return fmt.Errorf("%w: VCDIFF LZMA uncompressed size", ErrInvalidPatch)
		}
	}
	filters := int(flags&0x03) + 1
	for i := 0; i < filters; i++ {
		id, err := readXZVLI(data[:headerEnd-4], &off)
		if err != nil {
			return fmt.Errorf("%w: VCDIFF LZMA filter", ErrInvalidPatch)
		}
		propertiesSize, err := readXZVLI(data[:headerEnd-4], &off)
		if err != nil || off > headerEnd-4 || propertiesSize > uint64(headerEnd-4-off) {
			return fmt.Errorf("%w: VCDIFF LZMA filter properties", ErrInvalidPatch)
		}
		properties := data[off : off+int(propertiesSize)]
		off += int(propertiesSize)
		if i == filters-1 && id == 0x21 && len(properties) == 1 {
			dictionary, err := lzma.DecodeDictCap(properties[0])
			if err != nil {
				return fmt.Errorf("%w: VCDIFF LZMA dictionary", ErrInvalidPatch)
			}
			if uint64(dictionary) > limit {
				return fmt.Errorf("%w: LZMA dictionary is %d bytes (limit %d)", ErrOutputTooLarge, dictionary, limit)
			}
		}
	}
	return nil
}

func (d *vcdLZMADecoder) decode(section []byte, opts ApplyOptions, sourceSize, maxDecoded uint64) ([]byte, error) {
	if err := checkCanceled(opts); err != nil {
		return nil, err
	}
	s := newDecoder(section)
	decodedSize, err := readBE7(s)
	if err != nil {
		return nil, fmt.Errorf("%w: VCDIFF LZMA section size", ErrInvalidPatch)
	}
	if decodedSize == 0 {
		return nil, fmt.Errorf("%w: VCDIFF LZMA section has zero output size", ErrInvalidPatch)
	}
	if decodedSize > maxDecoded {
		return nil, fmt.Errorf("%w: VCDIFF sections exceed %d bytes", ErrOutputTooLarge, outputSizeLimit(sourceSize, opts))
	}
	n, err := checkedInt(decodedSize)
	if err != nil {
		return nil, err
	}
	compressed, err := s.bytes(s.remaining())
	if err != nil {
		return nil, err
	}
	if d.reader != nil && d.feed.off != len(d.feed.data) {
		return nil, fmt.Errorf("%w: unread VCDIFF LZMA input", ErrInvalidPatch)
	}
	d.feed = vcdSectionFeed{ctx: contextOf(opts), data: compressed}
	if d.reader == nil {
		dictLimit := outputSizeLimit(sourceSize, opts)
		if err = validateXZDictionary(compressed, dictLimit); err != nil {
			return nil, err
		}
		if dictLimit < uint64(lzma.MinDictCap) {
			dictLimit = uint64(lzma.MinDictCap)
		}
		if dictLimit > uint64(^uint(0)>>1) {
			dictLimit = uint64(^uint(0) >> 1)
		}
		if dictLimit > uint64(lzma.MaxDictCap) {
			dictLimit = uint64(lzma.MaxDictCap)
		}
		d.reader, err = (xz.ReaderConfig{DictCap: int(dictLimit), SingleStream: true}).NewReader(&d.feed)
		if err != nil {
			if canceled := contextOf(opts).Err(); canceled != nil {
				return nil, canceled
			}
			return nil, fmt.Errorf("%w: VCDIFF LZMA stream: %v", ErrInvalidPatch, err)
		}
	}
	out := make([]byte, n)
	for off := 0; off < len(out); {
		if err := checkCanceled(opts); err != nil {
			return nil, err
		}
		end := off + 64<<10
		if end > len(out) {
			end = len(out)
		}
		got, readErr := io.ReadFull(d.reader, out[off:end])
		off += got
		if readErr != nil {
			if canceled := contextOf(opts).Err(); canceled != nil {
				return nil, canceled
			}
			return nil, fmt.Errorf("%w: VCDIFF LZMA data: %v", ErrInvalidPatch, readErr)
		}
	}
	if d.feed.off != len(d.feed.data) {
		return nil, fmt.Errorf("%w: trailing VCDIFF LZMA input", ErrInvalidPatch)
	}
	return out, nil
}

type vcdSecondaryDecoders struct {
	data, instructions, addresses vcdLZMADecoder
}
