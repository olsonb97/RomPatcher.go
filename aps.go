package rompatcher

import (
	"bytes"
	"fmt"
	"strings"
)

const apsGBABlockSize = 0x10000

type apsRecord struct {
	offset int
	data   []byte
	rleLen int
	rle    byte
}

// APSN64Patch is a parsed APS patch for Nintendo 64 images.
type APSN64Patch struct {
	HeaderType, Encoding byte
	PatchDescription     string
	OriginalFormat       byte
	CartID               string
	CartCRC              [8]byte
	Pad                  [5]byte
	TargetSize           uint32
	records              []apsRecord
}

func (p *APSN64Patch) validateRecords() error {
	for _, r := range p.records {
		length := len(r.data)
		if r.rleLen > 0 {
			length = r.rleLen
		}
		if r.offset < 0 || length <= 0 || uint64(r.offset) > uint64(p.TargetSize) || uint64(length) > uint64(p.TargetSize)-uint64(r.offset) {
			return fmt.Errorf("%w: APS record outside output", ErrInvalidPatch)
		}
	}
	return nil
}

// Format implements Patch.
func (*APSN64Patch) Format() Format { return FormatAPSN64 }

// Description implements Patch.
func (p *APSN64Patch) Description() string { return p.PatchDescription }

// ValidateSource implements Patch.
func (p *APSN64Patch) ValidateSource(source []byte) bool {
	if p.HeaderType != 1 {
		return true
	}
	return len(source) >= 0x3f && strings.TrimRight(string(source[0x3c:0x3f]), "\x00") == p.CartID && bytes.Equal(source[0x10:0x18], p.CartCRC[:])
}

// ValidationInfo implements Patch.
func (p *APSN64Patch) ValidationInfo() *ValidationInfo {
	if p.HeaderType != 1 {
		return nil
	}
	return &ValidationInfo{Type: "N64", Values: []string{fmt.Sprintf("%s (%x)", p.CartID, p.CartCRC)}}
}

// Apply implements Patch.
func (p *APSN64Patch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary implements Patch.
func (p *APSN64Patch) MarshalBinary() ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	out := append([]byte{}, "APS10"...)
	out = append(out, p.HeaderType, p.Encoding)
	out = append(out, fixedString(p.PatchDescription, 50)...)
	if p.HeaderType == 1 {
		out = append(out, p.OriginalFormat)
		out = append(out, fixedString(p.CartID, 3)...)
		out = append(out, p.CartCRC[:]...)
		out = append(out, p.Pad[:]...)
	}
	out = appendU32LE(out, p.TargetSize)
	for _, r := range p.records {
		if r.offset < 0 || uint64(r.offset) > uint64(^uint32(0)) {
			return nil, ErrInvalidPatch
		}
		out = appendU32LE(out, uint32(r.offset))
		if r.rleLen > 0 {
			if r.rleLen > 255 {
				return nil, ErrInvalidPatch
			}
			out = append(out, 0, r.rle, byte(r.rleLen))
		} else {
			if len(r.data) == 0 || len(r.data) > 255 {
				return nil, ErrInvalidPatch
			}
			out = append(out, byte(len(r.data)))
			out = append(out, r.data...)
		}
	}
	return out, nil
}
func parseAPSN64(data []byte) (*APSN64Patch, error) {
	d := newDecoder(data)
	if e := d.seek(5); e != nil {
		return nil, e
	}
	p := &APSN64Patch{}
	var e error
	p.HeaderType, e = d.u8()
	if e != nil {
		return nil, e
	}
	p.Encoding, e = d.u8()
	if e != nil {
		return nil, e
	}
	s, e := d.string(50)
	if e != nil {
		return nil, e
	}
	p.PatchDescription = strings.TrimRight(s, "\x00")
	if p.HeaderType == 1 {
		p.OriginalFormat, e = d.u8()
		if e != nil {
			return nil, e
		}
		s, e = d.string(3)
		if e != nil {
			return nil, e
		}
		p.CartID = strings.TrimRight(s, "\x00")
		b, e := d.bytes(8)
		if e != nil {
			return nil, e
		}
		copy(p.CartCRC[:], b)
		b, e = d.bytes(5)
		if e != nil {
			return nil, e
		}
		copy(p.Pad[:], b)
	}
	p.TargetSize, e = d.u32le()
	if e != nil {
		return nil, e
	}
	for !d.eof() {
		o, e := d.u32le()
		if e != nil {
			return nil, e
		}
		ln, e := d.u8()
		if e != nil {
			return nil, e
		}
		offset, e := checkedInt(uint64(o))
		if e != nil {
			return nil, e
		}
		r := apsRecord{offset: offset}
		if ln == 0 {
			r.rle, e = d.u8()
			if e != nil {
				return nil, e
			}
			l, e := d.u8()
			if e != nil {
				return nil, e
			}
			if l == 0 {
				return nil, ErrInvalidPatch
			}
			r.rleLen = int(l)
		} else {
			b, e := d.bytes(int(ln))
			if e != nil {
				return nil, e
			}
			r.data = append([]byte(nil), b...)
		}
		p.records = append(p.records, r)
	}
	if e := p.validateRecords(); e != nil {
		return nil, e
	}
	return p, nil
}

type apsGBARecord struct {
	offset               uint32
	sourceCRC, targetCRC uint16
	xor                  []byte
}

// APSGBAPatch is a parsed APS patch for Game Boy Advance images.
type APSGBAPatch struct {
	basePatch
	SourceSize, TargetSize uint32
	records                []apsGBARecord
}

func (p *APSGBAPatch) validateRecords() error {
	for _, r := range p.records {
		end := uint64(r.offset) + apsGBABlockSize
		if len(r.xor) != apsGBABlockSize || end > uint64(p.SourceSize) || end > uint64(p.TargetSize) {
			return fmt.Errorf("%w: APS GBA block outside file", ErrInvalidPatch)
		}
	}
	return nil
}

// Format implements Patch.
func (*APSGBAPatch) Format() Format { return FormatAPSGBA }

// ValidateSource implements Patch.
func (p *APSGBAPatch) ValidateSource(source []byte) bool {
	if len(source) != int(p.SourceSize) {
		return false
	}
	for _, r := range p.records {
		start := int(r.offset)
		if start < 0 || start > len(source)-apsGBABlockSize || CRC16(source[start:start+apsGBABlockSize]) != r.sourceCRC {
			return false
		}
	}
	return true
}

// ValidationInfo implements Patch.
func (p *APSGBAPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "size", Values: []string{fmt.Sprint(p.SourceSize)}}
}

// Apply implements Patch.
func (p *APSGBAPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary implements Patch.
func (p *APSGBAPatch) MarshalBinary() ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	out := append([]byte{}, "APS1"...)
	out = appendU32LE(out, p.SourceSize)
	out = appendU32LE(out, p.TargetSize)
	for _, r := range p.records {
		if len(r.xor) != apsGBABlockSize {
			return nil, ErrInvalidPatch
		}
		out = appendU32LE(out, r.offset)
		out = appendU16LE(out, r.sourceCRC)
		out = appendU16LE(out, r.targetCRC)
		out = append(out, r.xor...)
	}
	return out, nil
}
func parseAPSGBA(data []byte) (*APSGBAPatch, error) {
	const recSize = 4 + 2 + 2 + apsGBABlockSize
	if len(data) < 12 || (len(data)-12)%recSize != 0 {
		return nil, fmt.Errorf("%w: APS GBA length", ErrInvalidPatch)
	}
	d := newDecoder(data)
	_ = d.seek(4)
	p := &APSGBAPatch{}
	var e error
	p.SourceSize, e = d.u32le()
	if e != nil {
		return nil, e
	}
	p.TargetSize, e = d.u32le()
	if e != nil {
		return nil, e
	}
	for !d.eof() {
		r := apsGBARecord{}
		r.offset, e = d.u32le()
		if e != nil {
			return nil, e
		}
		r.sourceCRC, e = d.u16le()
		if e != nil {
			return nil, e
		}
		r.targetCRC, e = d.u16le()
		if e != nil {
			return nil, e
		}
		b, e := d.bytes(apsGBABlockSize)
		if e != nil {
			return nil, e
		}
		r.xor = append([]byte(nil), b...)
		p.records = append(p.records, r)
	}
	if e := p.validateRecords(); e != nil {
		return nil, e
	}
	return p, nil
}
