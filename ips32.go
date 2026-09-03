package rompatcher

import "fmt"

const ips32MaxSize = uint64(1) << 32

// IPS32Patch is the 32-bit-offset extension of IPS. It uses an IPS32 header,
// EEOF terminator, and an optional four-byte truncate size.
type IPS32Patch struct {
	basePatch
	Records     []ipsRecord
	Truncate    uint32
	HasTruncate bool
}

func (*IPS32Patch) Format() Format { return FormatIPS32 }

func (p *IPS32Patch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	size := len(source)
	if p.HasTruncate {
		var err error
		size, err = checkedInt(uint64(p.Truncate))
		if err != nil {
			return nil, err
		}
	} else {
		for _, r := range p.Records {
			n := len(r.data)
			if r.rleLen > 0 {
				n = r.rleLen
			}
			if r.offset < 0 || n < 0 || r.offset > int(^uint(0)>>1)-n {
				return nil, ErrInvalidPatch
			}
			if r.offset+n > size {
				size = r.offset + n
			}
		}
	}
	if err := validateIPSRecords(p.Records, int64(size)); err != nil {
		return nil, err
	}
	if err := checkOutputSize(uint64(size), len(source), options); err != nil {
		return nil, err
	}
	out, err := resizedCopy(source, size)
	if err != nil {
		return nil, err
	}
	for i, r := range p.Records {
		if err := reportProgress(options, Progress{Phase: "apply", Format: FormatIPS32, Completed: int64(i), Total: int64(len(p.Records))}); err != nil {
			return nil, err
		}
		if r.rleLen > 0 {
			fillBytes(out[r.offset:r.offset+r.rleLen], r.rle)
		} else {
			copy(out[r.offset:], r.data)
		}
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: FormatIPS32, Completed: int64(len(p.Records)), Total: int64(len(p.Records))}); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *IPS32Patch) MarshalBinary() ([]byte, error) {
	out := append([]byte{}, "IPS32"...)
	for _, r := range p.Records {
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
		p.Records = append(p.Records, r)
	}
	return nil, fmt.Errorf("%w: IPS32 EEOF marker missing", ErrInvalidPatch)
}

func createIPS32(original, modified []byte) (*IPS32Patch, error) {
	if uint64(len(modified)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("files are too big for IPS32 format")
	}
	p := &IPS32Patch{}
	if len(modified) < len(original) {
		p.Truncate, p.HasTruncate = uint32(len(modified)), true
	}
	for pos := 0; pos < len(modified); {
		var old byte
		if pos < len(original) {
			old = original[pos]
		}
		if old == modified[pos] {
			pos++
			continue
		}
		start := pos
		buf := make([]byte, 0, 256)
		first, rle := modified[pos], true
		if uint64(start) == 0x45454f46 {
			start--
			first = modified[start]
			buf = append(buf, first)
		}
		for pos < len(modified) && len(buf) < 0xffff {
			old = 0
			if pos < len(original) {
				old = original[pos]
			}
			if old == modified[pos] {
				break
			}
			b := modified[pos]
			buf = append(buf, b)
			rle = rle && b == first
			pos++
		}
		r := ipsRecord{offset: start}
		if rle && len(buf) > 2 {
			r.rleLen, r.rle = len(buf), first
		} else {
			r.data = buf
		}
		p.Records = append(p.Records, r)
	}
	if len(modified) > len(original) && (len(p.Records) == 0 || recordEnd(p.Records[len(p.Records)-1]) < len(modified)) {
		p.Records = append(p.Records, ipsRecord{offset: len(modified) - 1, data: []byte{0}})
	}
	return p, nil
}

func recordEnd(r ipsRecord) int {
	if r.rleLen > 0 {
		return r.offset + r.rleLen
	}
	return r.offset + len(r.data)
}
