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
type APSN64Patch struct {
	HeaderType, Encoding byte
	PatchDescription     string
	OriginalFormat       byte
	CartID               string
	CartCRC              [8]byte
	Pad                  [5]byte
	TargetSize           uint32
	Records              []apsRecord
}

func (p *APSN64Patch) validateRecords() error {
	for _, r := range p.Records {
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

func (*APSN64Patch) Format() Format        { return FormatAPSN64 }
func (p *APSN64Patch) Description() string { return p.PatchDescription }
func (p *APSN64Patch) ValidateSource(source []byte) bool {
	if p.HeaderType != 1 {
		return true
	}
	return len(source) >= 0x3f && string(source[0x3c:0x3f]) == p.CartID && len(source) >= 0x18 && bytes.Equal(source[0x10:0x18], p.CartCRC[:])
}
func (p *APSN64Patch) ValidationInfo() *ValidationInfo {
	if p.HeaderType != 1 {
		return nil
	}
	return &ValidationInfo{Type: "N64", Values: []string{fmt.Sprintf("%s (%x)", p.CartID, p.CartCRC)}}
}
func (p *APSN64Patch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	if options.Validate && !p.ValidateSource(source) {
		return nil, ErrSourceMismatch
	}
	if err := checkOutputSize(uint64(p.TargetSize), len(source), options); err != nil {
		return nil, err
	}
	targetSize, e := checkedInt(uint64(p.TargetSize))
	if e != nil {
		return nil, e
	}
	out, e := resizedCopy(source, targetSize)
	if e != nil {
		return nil, e
	}
	for recordIndex, r := range p.Records {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(recordIndex), Total: int64(len(p.Records))}); err != nil {
			return nil, err
		}
		ln := len(r.data)
		if r.rleLen > 0 {
			ln = r.rleLen
		}
		if r.offset < 0 || r.offset > len(out)-ln {
			return nil, fmt.Errorf("%w: APS record outside output", ErrInvalidPatch)
		}
		if r.rleLen > 0 {
			fillBytes(out[r.offset:r.offset+r.rleLen], r.rle)
		} else {
			copy(out[r.offset:], r.data)
		}
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(len(p.Records)), Total: int64(len(p.Records))}); err != nil {
		return nil, err
	}
	return out, nil
}
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
	for _, r := range p.Records {
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
		p.Records = append(p.Records, r)
	}
	if e := p.validateRecords(); e != nil {
		return nil, e
	}
	return p, nil
}
func createAPSN64(original, modified []byte, sourceName string) *APSN64Patch {
	p := &APSN64Patch{PatchDescription: "no description", TargetSize: uint32(len(modified))}
	if len(original) >= 0x40 && bytes.Equal(original[:4], []byte{0x80, 0x37, 0x12, 0x40}) {
		p.HeaderType = 1
		p.OriginalFormat = 1
		if extension(sourceName) == "v64" {
			p.OriginalFormat = 0
		}
		p.CartID = string(original[0x3c:0x3f])
		copy(p.CartCRC[:], original[0x10:0x18])
	}
	for pos := 0; pos < len(modified); {
		var a byte
		if pos < len(original) {
			a = original[pos]
		}
		if a == modified[pos] {
			pos++
			continue
		}
		start := pos
		buf := make([]byte, 0, 255)
		first := modified[pos]
		rle := true
		for pos < len(modified) && len(buf) < 255 {
			a = 0
			if pos < len(original) {
				a = original[pos]
			}
			if a == modified[pos] {
				break
			}
			b := modified[pos]
			buf = append(buf, b)
			if b != first {
				rle = false
			}
			pos++
		}
		r := apsRecord{offset: start}
		if rle && len(buf) > 2 {
			r.rleLen = len(buf)
			r.rle = first
		} else {
			r.data = buf
		}
		p.Records = append(p.Records, r)
	}
	return p
}

type apsGBARecord struct {
	offset               uint32
	sourceCRC, targetCRC uint16
	xor                  []byte
}
type APSGBAPatch struct {
	basePatch
	SourceSize, TargetSize uint32
	Records                []apsGBARecord
}

func (p *APSGBAPatch) validateRecords() error {
	for _, r := range p.Records {
		end := uint64(r.offset) + apsGBABlockSize
		if len(r.xor) != apsGBABlockSize || end > uint64(p.SourceSize) || end > uint64(p.TargetSize) {
			return fmt.Errorf("%w: APS GBA block outside file", ErrInvalidPatch)
		}
	}
	return nil
}

func (*APSGBAPatch) Format() Format { return FormatAPSGBA }
func (p *APSGBAPatch) ValidateSource(source []byte) bool {
	if len(source) != int(p.SourceSize) {
		return false
	}
	for _, r := range p.Records {
		start := int(r.offset)
		if start < 0 || start > len(source)-apsGBABlockSize || CRC16(source[start:start+apsGBABlockSize]) != r.sourceCRC {
			return false
		}
	}
	return true
}
func (p *APSGBAPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "size", Values: []string{fmt.Sprint(p.SourceSize)}}
}
func (p *APSGBAPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	if options.Validate && !p.ValidateSource(source) {
		return nil, ErrSourceMismatch
	}
	if err := checkOutputSize(uint64(p.TargetSize), len(source), options); err != nil {
		return nil, err
	}
	targetSize, e := checkedInt(uint64(p.TargetSize))
	if e != nil {
		return nil, e
	}
	out, e := resizedCopy(source, targetSize)
	if e != nil {
		return nil, e
	}
	for recordIndex, r := range p.Records {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(recordIndex), Total: int64(len(p.Records))}); err != nil {
			return nil, err
		}
		start := int(r.offset)
		if start < 0 || start > len(out)-apsGBABlockSize || start > len(source)-apsGBABlockSize || len(r.xor) != apsGBABlockSize {
			return nil, fmt.Errorf("%w: APS GBA block outside file", ErrInvalidPatch)
		}
		for i, x := range r.xor {
			out[start+i] = source[start+i] ^ x
		}
		if options.Validate && CRC16(out[start:start+apsGBABlockSize]) != r.targetCRC {
			return nil, ErrTargetMismatch
		}
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(len(p.Records)), Total: int64(len(p.Records))}); err != nil {
		return nil, err
	}
	return out, nil
}
func (p *APSGBAPatch) MarshalBinary() ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	out := append([]byte{}, "APS1"...)
	out = appendU32LE(out, p.SourceSize)
	out = appendU32LE(out, p.TargetSize)
	for _, r := range p.Records {
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
		p.Records = append(p.Records, r)
	}
	if e := p.validateRecords(); e != nil {
		return nil, e
	}
	return p, nil
}
