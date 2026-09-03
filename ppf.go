package rompatcher

import (
	"bytes"
	"fmt"
	"strings"
)

type ppfRecord struct {
	offset     uint64
	data, undo []byte
}

// PPFPatch is a parsed PPF patch.
type PPFPatch struct {
	Version          int
	PatchDescription string
	ImageType        byte
	BlockCheck       []byte
	Undo             bool
	InputSize        uint32
	records          []ppfRecord
	FileID           string
}

// Format implements Patch.
func (*PPFPatch) Format() Format { return FormatPPF }

// Description implements Patch.
func (p *PPFPatch) Description() string { return p.PatchDescription }
func (p *PPFPatch) blockOffset() int {
	if p.Version == 3 && p.ImageType == 1 {
		return 0x80a0
	}
	return 0x9320
}
func (p *PPFPatch) undoing(source []byte) bool {
	if !p.Undo || len(p.records) == 0 {
		return false
	}
	r := p.records[0]
	return r.offset <= uint64(len(source)) && uint64(len(r.data)) <= uint64(len(source))-r.offset && bytes.Equal(source[int(r.offset):int(r.offset)+len(r.data)], r.data)
}

// ValidateSource implements Patch.
func (p *PPFPatch) ValidateSource(source []byte) bool {
	undoing := p.undoing(source)
	if !undoing {
		if p.InputSize != 0 && uint64(len(source)) != uint64(p.InputSize) {
			return false
		}
		if len(p.BlockCheck) != 0 {
			off := p.blockOffset()
			if off > len(source)-len(p.BlockCheck) || !bytes.Equal(source[off:off+len(p.BlockCheck)], p.BlockCheck) {
				return false
			}
		}
	}
	if p.Undo {
		for _, r := range p.records {
			if r.offset > uint64(len(source)) || uint64(len(r.data)) > uint64(len(source))-r.offset {
				return false
			}
			expected := r.undo
			if undoing {
				expected = r.data
			}
			if len(expected) != len(r.data) || !bytes.Equal(source[int(r.offset):int(r.offset)+len(expected)], expected) {
				return false
			}
		}
	}
	return true
}

// ValidationInfo implements Patch.
func (p *PPFPatch) ValidationInfo() *ValidationInfo {
	if p.InputSize == 0 && len(p.BlockCheck) == 0 && !p.Undo {
		return nil
	}
	values := make([]string, 0, 3)
	if p.InputSize != 0 {
		values = append(values, fmt.Sprintf("size=%d", p.InputSize))
	}
	if len(p.BlockCheck) != 0 {
		values = append(values, fmt.Sprintf("block@0x%x", p.blockOffset()))
	}
	if p.Undo {
		values = append(values, "undo-records")
	}
	return &ValidationInfo{Type: "PPF", Values: values}
}

// Apply implements Patch.
func (p *PPFPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary implements Patch.
func (p *PPFPatch) MarshalBinary() ([]byte, error) {
	if p.Version < 1 || p.Version > 3 {
		return nil, fmt.Errorf("%w: PPF version", ErrInvalidPatch)
	}
	if p.Version == 2 && len(p.BlockCheck) != 1024 {
		return nil, fmt.Errorf("%w: PPF2 requires a 1024-byte block check", ErrInvalidPatch)
	}
	if p.Version == 1 && len(p.BlockCheck) != 0 {
		return nil, fmt.Errorf("%w: PPF1 does not support block checks", ErrInvalidPatch)
	}
	if p.Version != 3 && p.Undo {
		return nil, fmt.Errorf("%w: undo data requires PPF3", ErrInvalidPatch)
	}
	if p.Version == 3 && p.ImageType > 1 {
		return nil, fmt.Errorf("%w: PPF image type", ErrInvalidPatch)
	}
	out := append([]byte{}, "PPF"...)
	out = append(out, []byte(fmt.Sprintf("%d0", p.Version))...)
	out = append(out, byte(p.Version-1))
	out = append(out, fixedString(p.PatchDescription, 50)...)
	if p.Version == 3 {
		var block, undo byte
		if len(p.BlockCheck) > 0 {
			block = 1
		}
		if p.Undo {
			undo = 1
		}
		out = append(out, p.ImageType, block, undo, 0)
	} else if p.Version == 2 {
		out = appendU32BE(out, p.InputSize)
	}
	if len(p.BlockCheck) > 0 {
		if len(p.BlockCheck) != 1024 {
			return nil, fmt.Errorf("%w: PPF block check", ErrInvalidPatch)
		}
		out = append(out, p.BlockCheck...)
	}
	for _, r := range p.records {
		if len(r.data) == 0 || len(r.data) > 255 {
			return nil, fmt.Errorf("%w: PPF record length", ErrInvalidPatch)
		}
		if p.Version < 3 && r.offset > uint64(^uint32(0)) {
			return nil, fmt.Errorf("%w: PPF offset exceeds 32 bits", ErrInvalidPatch)
		}
		out = appendU32LE(out, uint32(r.offset))
		if p.Version == 3 {
			out = appendU32LE(out, uint32(r.offset>>32))
		}
		out = append(out, byte(len(r.data)))
		out = append(out, r.data...)
		if p.Undo {
			if len(r.undo) != len(r.data) {
				return nil, fmt.Errorf("%w: PPF undo length", ErrInvalidPatch)
			}
			out = append(out, r.undo...)
		}
	}
	if p.FileID != "" {
		if p.Version == 3 && len(p.FileID) > 3072 {
			return nil, fmt.Errorf("%w: PPF FILE_ID.DIZ is too long", ErrInvalidPatch)
		}
		if p.Version < 3 && uint64(len(p.FileID)) > uint64(^uint32(0)) {
			return nil, fmt.Errorf("%w: PPF FILE_ID.DIZ is too long", ErrInvalidPatch)
		}
		out = append(out, "@BEGIN_FILE_ID.DIZ"...)
		out = append(out, p.FileID...)
		out = append(out, "@END_FILE_ID.DIZ"...)
		if p.Version == 3 {
			out = appendU16LE(out, uint16(len(p.FileID)))
		} else {
			out = appendU32LE(out, uint32(len(p.FileID)))
		}
	}
	return out, nil
}
func parsePPF(data []byte) (*PPFPatch, error) {
	if len(data) < 56 {
		return nil, fmt.Errorf("%w: PPF header", ErrInvalidPatch)
	}
	d := newDecoder(data)
	_ = d.seek(3)
	vtxt, e := d.string(2)
	if e != nil {
		return nil, e
	}
	vb, e := d.u8()
	if e != nil {
		return nil, e
	}
	if len(vtxt) != 2 || vtxt[1] != '0' || vtxt[0] < '1' || vtxt[0] > '3' || int(vtxt[0]-'0') != int(vb)+1 {
		return nil, fmt.Errorf("%w: PPF version", ErrInvalidPatch)
	}
	p := &PPFPatch{Version: int(vb) + 1}
	s, e := d.string(50)
	if e != nil {
		return nil, e
	}
	p.PatchDescription = strings.TrimRight(s, "\x00 ")
	if p.Version == 3 {
		p.ImageType, e = d.u8()
		if e != nil {
			return nil, e
		}
		b, e := d.u8()
		if e != nil {
			return nil, e
		}
		if p.ImageType > 1 || b > 1 {
			return nil, fmt.Errorf("%w: PPF3 header flags", ErrInvalidPatch)
		}
		if b != 0 {
			p.BlockCheck = make([]byte, 1024)
		}
		b, e = d.u8()
		if e != nil {
			return nil, e
		}
		if b > 1 {
			return nil, fmt.Errorf("%w: PPF3 undo flag", ErrInvalidPatch)
		}
		p.Undo = b != 0
		dummy, e := d.u8()
		if e != nil {
			return nil, e
		}
		if dummy != 0 {
			return nil, fmt.Errorf("%w: PPF3 reserved byte", ErrInvalidPatch)
		}
	} else if p.Version == 2 {
		p.BlockCheck = make([]byte, 1024)
		p.InputSize, e = d.u32be()
		if e != nil {
			return nil, e
		}
	}
	if p.BlockCheck != nil {
		b, e := d.bytes(1024)
		if e != nil {
			return nil, e
		}
		copy(p.BlockCheck, b)
	}
	for !d.eof() {
		if d.remaining() >= 18 && bytes.Equal(data[d.off:d.off+18], []byte("@BEGIN_FILE_ID.DIZ")) {
			d.off += 18
			end := bytes.Index(data[d.off:], []byte("@END_FILE_ID.DIZ"))
			if end < 0 {
				return nil, fmt.Errorf("%w: PPF FILE_ID.DIZ", ErrInvalidPatch)
			}
			p.FileID = string(data[d.off : d.off+end])
			d.off += end + len("@END_FILE_ID.DIZ")
			var declared uint32
			if p.Version == 3 {
				length, err := d.u16le()
				if err != nil {
					return nil, fmt.Errorf("%w: PPF FILE_ID.DIZ length", ErrInvalidPatch)
				}
				declared = uint32(length)
			} else {
				declared, e = d.u32le()
				if e != nil {
					return nil, fmt.Errorf("%w: PPF FILE_ID.DIZ length", ErrInvalidPatch)
				}
			}
			if uint64(declared) != uint64(len(p.FileID)) || !d.eof() {
				return nil, fmt.Errorf("%w: PPF FILE_ID.DIZ footer", ErrInvalidPatch)
			}
			return p, nil
		}
		need := 5
		if p.Version == 3 {
			need = 9
		}
		if d.remaining() < need {
			return nil, ErrUnexpectedEnd
		}
		lo, e := d.u32le()
		if e != nil {
			return nil, e
		}
		off := uint64(lo)
		if p.Version == 3 {
			hi, e := d.u32le()
			if e != nil {
				return nil, e
			}
			off |= uint64(hi) << 32
		}
		ln, e := d.u8()
		if e != nil {
			return nil, e
		}
		if ln == 0 {
			return nil, fmt.Errorf("%w: zero-length PPF record", ErrInvalidPatch)
		}
		b, e := d.bytes(int(ln))
		if e != nil {
			return nil, e
		}
		r := ppfRecord{offset: off, data: append([]byte(nil), b...)}
		if p.Undo {
			b, e = d.bytes(int(ln))
			if e != nil {
				return nil, e
			}
			r.undo = append([]byte(nil), b...)
		}
		p.records = append(p.records, r)
	}
	return p, nil
}
