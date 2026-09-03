package rompatcher

import "fmt"

const ips32MaxSize = uint64(1) << 32

// IPS32Patch is the 32-bit-offset extension of IPS. It uses an IPS32 header,
// EEOF terminator, and an optional four-byte truncate size. Use InspectParsed
// for record details.
type IPS32Patch struct {
	basePatch
	records     []ipsRecord
	Truncate    uint32
	HasTruncate bool
}

// Format implements Patch.
func (*IPS32Patch) Format() Format { return FormatIPS32 }

// Apply implements Patch.
func (p *IPS32Patch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary implements Patch.
func (p *IPS32Patch) MarshalBinary() ([]byte, error) {
	out := append([]byte{}, "IPS32"...)
	for _, r := range p.records {
		if r.offset < 0 || uint64(r.offset) >= ips32MaxSize || uint32(r.offset) == 0x45454f46 {
			return nil, fmt.Errorf("%w: IPS32 offset 0x%x", ErrInvalidPatch, r.offset)
		}
		out = appendU32BE(out, uint32(r.offset))
		if r.rleLen > 0 {
			if r.rleLen > 0xffff {
				return nil, fmt.Errorf("%w: IPS32 RLE record too long", ErrInvalidPatch)
			}
			out = appendU16BE(out, 0)
			out = appendU16BE(out, uint16(r.rleLen))
			out = append(out, r.rle)
		} else {
			if len(r.data) == 0 || len(r.data) > 0xffff {
				return nil, fmt.Errorf("%w: IPS32 record length", ErrInvalidPatch)
			}
			out = appendU16BE(out, uint16(len(r.data)))
			out = append(out, r.data...)
		}
	}
	out = append(out, "EEOF"...)
	if p.HasTruncate {
		out = appendU32BE(out, p.Truncate)
	}
	return out, nil
}

func parseIPS32(data []byte) (*IPS32Patch, error) {
	d := newDecoder(data)
	if err := d.seek(5); err != nil {
		return nil, err
	}
	p := &IPS32Patch{}
	for !d.eof() {
		o, err := d.u32be()
		if err != nil {
			return nil, fmt.Errorf("%w: IPS32 record offset", ErrInvalidPatch)
		}
		if o == 0x45454f46 {
			switch d.remaining() {
			case 0:
				return p, nil
			case 4:
				p.Truncate, err = d.u32be()
				p.HasTruncate = err == nil
				return p, err
			default:
				return nil, fmt.Errorf("%w: data after IPS32 EEOF", ErrInvalidPatch)
			}
		}
		n, err := d.u16be()
		if err != nil {
			return nil, err
		}
		offset, err := checkedInt(uint64(o))
		if err != nil {
			return nil, err
		}
		r := ipsRecord{offset: offset}
		if n == 0 {
			ln, err := d.u16be()
			if err != nil {
				return nil, err
			}
			b, err := d.u8()
			if err != nil || ln == 0 {
				return nil, fmt.Errorf("%w: IPS32 RLE record", ErrInvalidPatch)
			}
			r.rleLen, r.rle = int(ln), b
		} else {
			b, err := d.bytes(int(n))
			if err != nil {
				return nil, err
			}
			r.data = append([]byte(nil), b...)
		}
		p.records = append(p.records, r)
	}
	return nil, fmt.Errorf("%w: IPS32 EEOF marker missing", ErrInvalidPatch)
}
