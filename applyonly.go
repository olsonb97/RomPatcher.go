package rompatcher

import (
	"fmt"
	"io"
)

// PMSRPatch is a parsed Star Rod PMSR mod patch.
type PMSRPatch struct {
	basePatch
	TargetSize  int
	recordCount int
	data        []byte
}

// Format implements Patch.
func (*PMSRPatch) Format() Format { return FormatPMSR }

// ValidateSource implements Patch.
func (*PMSRPatch) ValidateSource(source []byte) bool {
	return len(source) == 41943040 && CRC32(source) == 0xa7f5cd7e
}

// ValidationInfo implements Patch.
func (*PMSRPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "CRC32", Values: []string{"a7f5cd7e"}}
}

// Apply implements Patch.
func (p *PMSRPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary reports that PMSR creation is unsupported.
func (*PMSRPatch) MarshalBinary() ([]byte, error) { return nil, ErrUnsupported }
func parsePMSR(data []byte) (*PMSRPatch, error) {
	d := newDecoder(data)
	_ = d.seek(4)
	count, e := d.u32be()
	if e != nil {
		return nil, e
	}
	p := &PMSRPatch{TargetSize: 41943040, data: append([]byte(nil), data...)}
	for i := uint32(0); i < count; i++ {
		off, e := d.u32be()
		if e != nil {
			return nil, e
		}
		ln, e := d.u32be()
		if e != nil {
			return nil, e
		}
		n, e := checkedInt(uint64(ln))
		if e != nil {
			return nil, e
		}
		if e := d.skip(n); e != nil {
			return nil, e
		}
		end, e := checkedInt(uint64(off) + uint64(n))
		if e != nil {
			return nil, e
		}
		p.recordCount++
		if end > p.TargetSize {
			p.TargetSize = end
		}
	}
	if !d.eof() {
		return nil, fmt.Errorf("%w: trailing PMSR data", ErrInvalidPatch)
	}
	return p, nil
}

// BDFPatch is a parsed BSDIFF40 patch.
type BDFPatch struct {
	basePatch
	TargetSize uint64
	data       []byte
}

// Format implements Patch.
func (*BDFPatch) Format() Format { return FormatBDF }

// Apply implements Patch.
func (p *BDFPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary reports that BSDIFF creation is unsupported.
func (*BDFPatch) MarshalBinary() ([]byte, error) { return nil, ErrUnsupported }
func bsdiffInt(raw uint64) int64 {
	negative := raw&(uint64(1)<<63) != 0
	v := int64(raw &^ (uint64(1) << 63))
	if negative {
		return -v
	}
	return v
}
func readBSDiffInt(r io.Reader) (int64, error) {
	var data [8]byte
	if _, err := io.ReadFull(r, data[:]); err != nil {
		return 0, err
	}
	return bsdiffInt(uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
		uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56), nil
}

func requireCompressedEOF(r io.Reader, section string) error {
	n, err := io.Copy(io.Discard, io.LimitReader(r, 1))
	if err != nil {
		return fmt.Errorf("%w: BSDIFF %s bzip2: %v", ErrInvalidPatch, section, err)
	}
	if n != 0 {
		return fmt.Errorf("%w: unused BSDIFF %s data", ErrInvalidPatch, section)
	}
	return nil
}

func sourceSpan(position, length, sourceSize int64) (within, sourceOffset, count int64) {
	if length <= 0 || sourceSize <= 0 {
		return 0, 0, 0
	}
	if position < 0 {
		if position <= -length {
			return 0, 0, 0
		}
		within = -position
	}
	sourceOffset = position + within
	if sourceOffset >= sourceSize {
		return 0, 0, 0
	}
	count = length - within
	if sourceSize-sourceOffset < count {
		count = sourceSize - sourceOffset
	}
	return within, sourceOffset, count
}

func parseBDF(data []byte) (*BDFPatch, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("%w: BSDIFF header", ErrInvalidPatch)
	}
	d := newDecoder(data)
	_ = d.seek(8)
	cr, e := d.u64le()
	if e != nil {
		return nil, e
	}
	dr, e := d.u64le()
	if e != nil {
		return nil, e
	}
	nr, e := d.u64le()
	if e != nil {
		return nil, e
	}
	controlSize, diffSize, target := bsdiffInt(cr), bsdiffInt(dr), bsdiffInt(nr)
	if controlSize < 0 || diffSize < 0 || target < 0 || controlSize > int64(d.remaining()) || diffSize > int64(d.remaining())-controlSize {
		return nil, fmt.Errorf("%w: BSDIFF sizes", ErrInvalidPatch)
	}
	return &BDFPatch{
		TargetSize: uint64(target),
		data:       append([]byte(nil), data...),
	}, nil
}
