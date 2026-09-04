package rompatcher

import (
	"fmt"
)

type upsRecord struct {
	offset uint64
	xor    []byte
}

// UPSPatch is a parsed reversible UPS patch.
type UPSPatch struct {
	basePatch
	SourceSize, TargetSize uint64
	SourceCRC, TargetCRC   uint32
	records                []upsRecord
}

// Format implements Patch.
func (*UPSPatch) Format() Format { return FormatUPS }

// ValidateSource implements Patch and accepts either reversible endpoint.
func (p *UPSPatch) ValidateSource(source []byte) bool {
	size, sum := uint64(len(source)), CRC32(source)
	return size == p.SourceSize && sum == p.SourceCRC || size == p.TargetSize && sum == p.TargetCRC
}

// ValidationInfo implements Patch.
func (p *UPSPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "CRC32", Values: []string{fmt.Sprintf("%08x", p.SourceCRC), fmt.Sprintf("%08x", p.TargetCRC)}}
}

func (p *UPSPatch) validateRecords() error {
	maximum := p.SourceSize
	if p.TargetSize > maximum {
		maximum = p.TargetSize
	}
	var pos uint64
	for _, r := range p.records {
		if len(r.xor) == 0 || pos > ^uint64(0)-r.offset {
			return fmt.Errorf("%w: invalid UPS record", ErrInvalidPatch)
		}
		pos += r.offset
		length := uint64(len(r.xor))
		if length > maximum || pos > maximum-length {
			return fmt.Errorf("%w: UPS record outside file range", ErrInvalidPatch)
		}
		pos += length
		if pos == ^uint64(0) {
			return fmt.Errorf("%w: UPS record position overflow", ErrInvalidPatch)
		}
		pos++
	}
	return nil
}

// Apply implements Patch and automatically selects the reversible direction.
func (p *UPSPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary implements Patch.
func (p *UPSPatch) MarshalBinary() ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	out := append([]byte{}, "UPS1"...)
	out = appendBPSVLV(out, p.SourceSize)
	out = appendBPSVLV(out, p.TargetSize)
	for _, r := range p.records {
		out = appendBPSVLV(out, r.offset)
		out = append(out, r.xor...)
		out = append(out, 0)
	}
	out = appendU32LE(out, p.SourceCRC)
	out = appendU32LE(out, p.TargetCRC)
	out = appendU32LE(out, CRC32(out))
	return out, nil
}

func parseUPS(data []byte) (*UPSPatch, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("%w: UPS header", ErrInvalidPatch)
	}
	d := newDecoder(data)
	_ = d.seek(4)
	ss, err := readBPSVLV(d)
	if err != nil {
		return nil, err
	}
	ts, err := readBPSVLV(d)
	if err != nil {
		return nil, err
	}
	p := &UPSPatch{SourceSize: ss, TargetSize: ts}
	for d.off < len(data)-12 {
		o, err := readBPSVLV(d)
		if err != nil {
			return nil, err
		}
		start := d.off
		for d.off < len(data)-12 && data[d.off] != 0 {
			d.off++
		}
		if d.off >= len(data)-12 {
			return nil, fmt.Errorf("%w: unterminated UPS record", ErrInvalidPatch)
		}
		p.records = append(p.records, upsRecord{offset: o, xor: append([]byte(nil), data[start:d.off]...)})
		d.off++
	}
	if d.off != len(data)-12 {
		return nil, fmt.Errorf("%w: UPS record boundary", ErrInvalidPatch)
	}
	p.SourceCRC, err = d.u32le()
	if err != nil {
		return nil, err
	}
	p.TargetCRC, err = d.u32le()
	if err != nil {
		return nil, err
	}
	want, err := d.u32le()
	if err != nil {
		return nil, err
	}
	if got := CRC32(data[:len(data)-4]); want != got {
		return nil, checksum32Mismatch(ErrPatchMismatch, FormatUPS, "CRC32", want, got)
	}
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	return p, nil
}
