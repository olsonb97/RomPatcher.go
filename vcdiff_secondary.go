package rompatcher

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

const (
	vcdLZMASecondaryID        = 2
	defaultLZMADictionarySize = 64 << 20
)

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
	feed      vcdSectionFeed
	reader    *xz.Reader
	validator vcdXZValidator
}

type vcdXZValidator struct {
	started, inBlock, ended bool
	checkSize               int
	blockBytes              uint64
}

func lzmaDictionaryLimit(opts ApplyOptions) uint64 {
	if opts.MaxDictionarySize != 0 {
		return opts.MaxDictionarySize
	}
	limit := uint64(defaultLZMADictionarySize)
	if opts.MaxOutputSize != 0 && opts.MaxOutputSize < limit {
		limit = opts.MaxOutputSize
	}
	return limit
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

func validateXZBlockHeader(data []byte, start int, limit uint64) (int, error) {
	if start >= len(data) {
		return 0, ErrUnexpectedEnd
	}
	headerSize := (int(data[start]) + 1) * 4
	headerEnd := start + headerSize
	if headerSize < 8 || headerEnd > len(data) {
		return 0, fmt.Errorf("%w: VCDIFF LZMA block header", ErrInvalidPatch)
	}
	flags := data[start+1]
	if flags&0x3c != 0 {
		return 0, fmt.Errorf("%w: VCDIFF LZMA block flags", ErrInvalidPatch)
	}
	off := start + 2
	if flags&0x40 != 0 {
		if _, err := readXZVLI(data[:headerEnd-4], &off); err != nil {
			return 0, fmt.Errorf("%w: VCDIFF LZMA compressed size", ErrInvalidPatch)
		}
	}
	if flags&0x80 != 0 {
		if _, err := readXZVLI(data[:headerEnd-4], &off); err != nil {
			return 0, fmt.Errorf("%w: VCDIFF LZMA uncompressed size", ErrInvalidPatch)
		}
	}
	filters := int(flags&0x03) + 1
	for i := 0; i < filters; i++ {
		id, err := readXZVLI(data[:headerEnd-4], &off)
		if err != nil {
			return 0, fmt.Errorf("%w: VCDIFF LZMA filter", ErrInvalidPatch)
		}
		propertiesSize, err := readXZVLI(data[:headerEnd-4], &off)
		if err != nil || off > headerEnd-4 || propertiesSize > uint64(headerEnd-4-off) {
			return 0, fmt.Errorf("%w: VCDIFF LZMA filter properties", ErrInvalidPatch)
		}
		properties := data[off : off+int(propertiesSize)]
		off += int(propertiesSize)
		if i == filters-1 {
			if id != 0x21 || len(properties) != 1 {
				return 0, fmt.Errorf("%w: VCDIFF LZMA final filter", ErrInvalidPatch)
			}
			dictionary, err := lzma.DecodeDictCap(properties[0])
			if err != nil {
				return 0, fmt.Errorf("%w: VCDIFF LZMA dictionary", ErrInvalidPatch)
			}
			if uint64(dictionary) > limit {
				return 0, fmt.Errorf("%w: LZMA dictionary is %d bytes (limit %d)", ErrOutputTooLarge, dictionary, limit)
			}
		}
	}
	return headerSize, nil
}

func (v *vcdXZValidator) validateSection(ctx context.Context, data []byte, dictionaryLimit uint64) (uint64, error) {
	off := 0
	if !v.started {
		if len(data) < 12 || !bytes.Equal(data[:6], []byte{0xfd, '7', 'z', 'X', 'Z', 0}) || data[6] != 0 {
			return 0, fmt.Errorf("%w: VCDIFF LZMA XZ header", ErrInvalidPatch)
		}
		switch data[7] {
		case 0:
			v.checkSize = 0
		case 1:
			v.checkSize = 4
		case 4:
			v.checkSize = 8
		case 10:
			v.checkSize = 32
		default:
			return 0, fmt.Errorf("%w: unsupported VCDIFF LZMA check type", ErrInvalidPatch)
		}
		v.started = true
		off = 12
	}
	if v.ended {
		return 0, fmt.Errorf("%w: VCDIFF LZMA data after stream end", ErrInvalidPatch)
	}
	var decoded uint64
	for off < len(data) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if !v.inBlock {
			if data[off] == 0 {
				v.ended = true
				off = len(data)
				break
			}
			headerSize, err := validateXZBlockHeader(data, off, dictionaryLimit)
			if err != nil {
				return 0, err
			}
			v.inBlock = true
			v.blockBytes = uint64(headerSize)
			off += headerSize
			continue
		}
		control := data[off]
		if control == 0 {
			off++
			v.blockBytes++
			padding := int((4 - v.blockBytes%4) % 4)
			trailer := padding + v.checkSize
			if trailer > len(data)-off {
				return 0, ErrUnexpectedEnd
			}
			for _, value := range data[off : off+padding] {
				if value != 0 {
					return 0, fmt.Errorf("%w: VCDIFF LZMA block padding", ErrInvalidPatch)
				}
			}
			off += trailer
			v.inBlock = false
			v.blockBytes = 0
			continue
		}
		var header, compressed int
		var chunk uint64
		switch {
		case control == 1 || control == 2:
			header = 3
			if off+header > len(data) {
				return 0, ErrUnexpectedEnd
			}
			chunk = uint64(data[off+1])<<8 | uint64(data[off+2])
			chunk++
			compressed = int(chunk)
		case control >= 0x80:
			header = 5
			if control >= 0xc0 {
				header++
			}
			if off+header > len(data) {
				return 0, ErrUnexpectedEnd
			}
			chunk = uint64(control&0x1f)<<16 | uint64(data[off+1])<<8 | uint64(data[off+2])
			chunk++
			compressed = int(data[off+3])<<8 | int(data[off+4])
			compressed++
		default:
			return 0, ErrInvalidPatch
		}
		if compressed > len(data)-off-header {
			return 0, ErrUnexpectedEnd
		}
		if decoded > ^uint64(0)-chunk {
			return 0, ErrInvalidPatch
		}
		decoded += chunk
		consumed := header + compressed
		v.blockBytes += uint64(consumed)
		off += consumed
	}
	return decoded, nil
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
		return nil, fmt.Errorf("%w: VCDIFF sections exceed %d bytes", ErrOutputTooLarge, vcdWindowLimit(sourceSize, opts))
	}
	n, err := checkedInt(decodedSize)
	if err != nil {
		return nil, err
	}
	compressed, err := s.bytes(s.remaining())
	if err != nil {
		return nil, err
	}
	sectionSize, err := d.validator.validateSection(contextOf(opts), compressed, lzmaDictionaryLimit(opts))
	if err != nil {
		return nil, err
	}
	if sectionSize != decodedSize {
		return nil, fmt.Errorf("%w: VCDIFF LZMA section output size", ErrInvalidPatch)
	}
	if d.reader != nil && d.feed.off != len(d.feed.data) {
		return nil, fmt.Errorf("%w: unread VCDIFF LZMA input", ErrInvalidPatch)
	}
	d.feed = vcdSectionFeed{ctx: contextOf(opts), data: compressed}
	if d.reader == nil {
		d.reader, err = (xz.ReaderConfig{DictCap: lzma.MinDictCap, SingleStream: true}).NewReader(&d.feed)
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
