package rompatcher

import (
	"fmt"
)

type upsRecord struct {
	offset uint64
	xor    []byte
}

type UPSPatch struct {
	basePatch
	SourceSize, TargetSize uint64
	SourceCRC, TargetCRC   uint32
	Records                []upsRecord
}

func (*UPSPatch) Format() Format { return FormatUPS }
func (p *UPSPatch) ValidateSource(source []byte) bool {
	size, sum := uint64(len(source)), CRC32(source)
	return size == p.SourceSize && sum == p.SourceCRC || size == p.TargetSize && sum == p.TargetCRC
}
func (p *UPSPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "CRC32", Values: []string{fmt.Sprintf("%08x", p.SourceCRC), fmt.Sprintf("%08x", p.TargetCRC)}}
}

func (p *UPSPatch) reverseFor(size uint64, sum uint32) bool {
	return !(size == p.SourceSize && sum == p.SourceCRC) && size == p.TargetSize && sum == p.TargetCRC
}

func (p *UPSPatch) validateRecords() error {
	maximum := p.SourceSize
	if p.TargetSize > maximum {
		maximum = p.TargetSize
	}
	var pos uint64
	for _, r := range p.Records {
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

func (p *UPSPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	actualSize := uint64(len(source))
	var sum uint32
	checked := false
	if options.Validate || actualSize == p.TargetSize {
		var err error
		sum, err = crc32Cancelable(source, options)
		if err != nil {
			return nil, err
		}
		checked = true
	}
	undo := checked && p.reverseFor(actualSize, sum)
	if options.Validate && !undo && !(actualSize == p.SourceSize && sum == p.SourceCRC) {
		return nil, ErrSourceMismatch
	}
	targetSize := p.TargetSize
	if undo {
		targetSize = p.SourceSize
	} else if !options.Validate && p.SourceSize < actualSize && targetSize < actualSize {
		targetSize = actualSize
	}
	if err := checkOutputSize(targetSize, len(source), options); err != nil {
		return nil, err
	}
	n, err := checkedInt(targetSize)
	if err != nil {
		return nil, err
	}
	out, err := resizedCopy(source, n)
	if err != nil {
		return nil, err
	}
	var pos uint64
	for i, r := range p.Records {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i), Total: int64(len(p.Records))}); err != nil {
			return nil, err
		}
		pos += r.offset
		for _, x := range r.xor {
			if pos < uint64(len(out)) {
				var b byte
				if pos < actualSize {
					b = source[pos]
				}
				out[pos] = b ^ x
			}
			pos++
		}
		pos++
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(len(p.Records)), Total: int64(len(p.Records))}); err != nil {
		return nil, err
	}
	if options.Validate {
		want := p.TargetCRC
		if undo {
			want = p.SourceCRC
		}
		sum, err := crc32Cancelable(out, options)
		if err != nil {
			return nil, err
		}
		if sum != want {
			return nil, ErrTargetMismatch
		}
	}
	return out, nil
}

func (p *UPSPatch) MarshalBinary() ([]byte, error) {
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	out := append([]byte{}, "UPS1"...)
	out = appendBPSVLV(out, p.SourceSize)
	out = appendBPSVLV(out, p.TargetSize)
	for _, r := range p.Records {
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
		p.Records = append(p.Records, upsRecord{offset: o, xor: append([]byte(nil), data[start:d.off]...)})
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
	if want != CRC32(data[:len(data)-4]) {
		return nil, ErrPatchMismatch
	}
	if err := p.validateRecords(); err != nil {
		return nil, err
	}
	return p, nil
}

func createUPS(original, modified []byte) *UPSPatch {
	p := &UPSPatch{SourceSize: uint64(len(original)), TargetSize: uint64(len(modified)), SourceCRC: CRC32(original), TargetCRC: CRC32(modified)}
	previousSeek := 1
	for pos := 0; pos < len(modified); {
		var a byte
		if pos < len(original) {
			a = original[pos]
		}
		if a == modified[pos] {
			pos++
			continue
		}
		currentSeek := pos + 1
		x := make([]byte, 0, 64)
		for pos < len(modified) {
			a = 0
			if pos < len(original) {
				a = original[pos]
			}
			if a == modified[pos] {
				break
			}
			x = append(x, a^modified[pos])
			pos++
		}
		p.Records = append(p.Records, upsRecord{offset: uint64(currentSeek - previousSeek), xor: x})
		previousSeek = currentSeek + len(x) + 1
	}
	return p
}
