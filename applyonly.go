package rompatcher

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
)

type pmsrRecord struct {
	offset uint32
	data   []byte
}
type PMSRPatch struct {
	basePatch
	TargetSize int
	Records    []pmsrRecord
}

func (*PMSRPatch) Format() Format { return FormatPMSR }
func (*PMSRPatch) ValidateSource(source []byte) bool {
	return len(source) == 41943040 && CRC32(source) == 0xa7f5cd7e
}
func (*PMSRPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "CRC32", Values: []string{"a7f5cd7e"}}
}
func (p *PMSRPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	if options.Validate {
		sum, err := crc32Cancelable(source, options)
		if err != nil {
			return nil, err
		}
		if len(source) != 41943040 || sum != 0xa7f5cd7e {
			return nil, ErrSourceMismatch
		}
	}
	if p.TargetSize < 0 {
		return nil, fmt.Errorf("%w: negative PMSR target size", ErrInvalidPatch)
	}
	if err := checkOutputSize(uint64(p.TargetSize), len(source), options); err != nil {
		return nil, err
	}
	out, e := resizedCopy(source, p.TargetSize)
	if e != nil {
		return nil, e
	}
	for recordIndex, r := range p.Records {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(recordIndex), Total: int64(len(p.Records))}); err != nil {
			return nil, err
		}
		start := int(r.offset)
		if start > len(out)-len(r.data) {
			return nil, fmt.Errorf("%w: PMSR record outside output", ErrInvalidPatch)
		}
		copy(out[start:], r.data)
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(len(p.Records)), Total: int64(len(p.Records))}); err != nil {
		return nil, err
	}
	return out, nil
}
func (*PMSRPatch) MarshalBinary() ([]byte, error) { return nil, ErrUnsupported }
func parsePMSR(data []byte) (*PMSRPatch, error) {
	d := newDecoder(data)
	_ = d.seek(4)
	count, e := d.u32be()
	if e != nil {
		return nil, e
	}
	p := &PMSRPatch{TargetSize: 41943040}
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
		b, e := d.bytes(n)
		if e != nil {
			return nil, e
		}
		end, e := checkedInt(uint64(off) + uint64(n))
		if e != nil {
			return nil, e
		}
		p.Records = append(p.Records, pmsrRecord{offset: off, data: append([]byte(nil), b...)})
		if end > p.TargetSize {
			p.TargetSize = end
		}
	}
	if !d.eof() {
		return nil, fmt.Errorf("%w: trailing PMSR data", ErrInvalidPatch)
	}
	return p, nil
}

type bdfRecord struct {
	diff, extra []byte
	skip        int64
}
type BDFPatch struct {
	basePatch
	TargetSize uint64
	Records    []bdfRecord
	compressed bool
	control    []byte
	diff       []byte
	extra      []byte
}

func (*BDFPatch) Format() Format { return FormatBDF }
func (p *BDFPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	if err := checkOutputSize(p.TargetSize, len(source), options); err != nil {
		return nil, err
	}
	n, e := checkedInt(p.TargetSize)
	if e != nil {
		return nil, e
	}
	out := make([]byte, n)
	oldPos, newPos := int64(0), int64(0)
	total := int64(0)
	if !p.compressed {
		total = int64(len(p.Records))
	}
	count, err := p.walkRecords(options, uint64(len(source)), func(recordIndex int, diff io.Reader, diffLength int64, extra io.Reader, extraLength, skip int64) error {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(recordIndex), Total: total}); err != nil {
			return err
		}
		diffEnd, ok := addInt64(newPos, diffLength)
		if !ok || diffEnd > int64(len(out)) {
			return fmt.Errorf("%w: BSDIFF diff exceeds output", ErrInvalidPatch)
		}
		oldEnd, ok := addInt64(oldPos, diffLength)
		if !ok {
			return fmt.Errorf("%w: BSDIFF source position overflow", ErrInvalidPatch)
		}
		for done := int64(0); done < diffLength; {
			length := int64(fileChunkSize)
			if diffLength-done < length {
				length = diffLength - done
			}
			chunk := out[int(newPos+done):int(newPos+done+length)]
			if _, err := io.ReadFull(diff, chunk); err != nil {
				return fmt.Errorf("%w: BSDIFF diff: %v", ErrInvalidPatch, err)
			}
			segmentOld, ok := addInt64(oldPos, done)
			if !ok {
				return fmt.Errorf("%w: BSDIFF source position overflow", ErrInvalidPatch)
			}
			within, sourceOffset, count := sourceSpan(segmentOld, length, int64(len(source)))
			for i := int64(0); i < count; i++ {
				chunk[int(within+i)] += source[int(sourceOffset+i)]
			}
			done += length
			if err := checkCanceled(options); err != nil {
				return err
			}
		}
		newPos, oldPos = diffEnd, oldEnd
		extraEnd, ok := addInt64(newPos, extraLength)
		if !ok || extraEnd > int64(len(out)) {
			return fmt.Errorf("%w: BSDIFF extra exceeds output", ErrInvalidPatch)
		}
		for done := int64(0); done < extraLength; {
			length := int64(fileChunkSize)
			if extraLength-done < length {
				length = extraLength - done
			}
			if _, err := io.ReadFull(extra, out[int(newPos+done):int(newPos+done+length)]); err != nil {
				return fmt.Errorf("%w: BSDIFF extra: %v", ErrInvalidPatch, err)
			}
			done += length
			if err := checkCanceled(options); err != nil {
				return err
			}
		}
		newPos = extraEnd
		oldPos, ok = addInt64(oldPos, skip)
		if !ok {
			return fmt.Errorf("%w: BSDIFF source position overflow", ErrInvalidPatch)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(count), Total: total}); err != nil {
		return nil, err
	}
	if newPos != int64(len(out)) {
		return nil, fmt.Errorf("%w: BSDIFF output is %d bytes, expected %d", ErrInvalidPatch, newPos, len(out))
	}
	return out, nil
}
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

type bdfRecordVisitor func(index int, diff io.Reader, diffLength int64, extra io.Reader, extraLength, skip int64) error

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

func (p *BDFPatch) walkRecords(options ApplyOptions, sourceSize uint64, visit bdfRecordVisitor) (int, error) {
	if err := checkOutputSize64(p.TargetSize, sourceSize, options); err != nil {
		return 0, err
	}
	if p.TargetSize > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("%w: BSDIFF target size", ErrInvalidPatch)
	}
	target := int64(p.TargetSize)
	produced := int64(0)
	count := 0
	consume := func(dl, el, skip int64, diff, extra io.Reader) error {
		remaining := target - produced
		if dl < 0 || el < 0 || dl == 0 && el == 0 || dl > remaining || el > remaining-dl {
			return fmt.Errorf("%w: BSDIFF control values", ErrInvalidPatch)
		}
		diffLimited := &io.LimitedReader{R: diff, N: dl}
		extraLimited := &io.LimitedReader{R: extra, N: el}
		if err := visit(count, diffLimited, dl, extraLimited, el, skip); err != nil {
			return err
		}
		if diffLimited.N != 0 || extraLimited.N != 0 {
			return fmt.Errorf("%w: BSDIFF record data was not consumed", ErrInvalidPatch)
		}
		produced += dl + el
		count++
		return nil
	}
	if !p.compressed {
		for _, r := range p.Records {
			if err := checkCanceled(options); err != nil {
				return count, err
			}
			if err := consume(int64(len(r.diff)), int64(len(r.extra)), r.skip, bytes.NewReader(r.diff), bytes.NewReader(r.extra)); err != nil {
				return count, err
			}
		}
		if produced != target {
			return count, fmt.Errorf("%w: BSDIFF output is %d bytes, expected %d", ErrInvalidPatch, produced, target)
		}
		return count, nil
	}
	control := bzip2.NewReader(bytes.NewReader(p.control))
	diff := bzip2.NewReader(bytes.NewReader(p.diff))
	extra := bzip2.NewReader(bytes.NewReader(p.extra))
	for produced < target {
		if err := checkCanceled(options); err != nil {
			return count, err
		}
		dl, err := readBSDiffInt(control)
		if err != nil {
			return count, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		el, err := readBSDiffInt(control)
		if err != nil {
			return count, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		skip, err := readBSDiffInt(control)
		if err != nil {
			return count, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		if err := consume(dl, el, skip, diff, extra); err != nil {
			return count, err
		}
	}
	if err := requireCompressedEOF(control, "control"); err != nil {
		return count, err
	}
	if err := requireCompressedEOF(diff, "diff"); err != nil {
		return count, err
	}
	if err := requireCompressedEOF(extra, "extra"); err != nil {
		return count, err
	}
	return count, nil
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
	cb, e := d.bytes(int(controlSize))
	if e != nil {
		return nil, e
	}
	db, e := d.bytes(int(diffSize))
	if e != nil {
		return nil, e
	}
	eb, e := d.bytes(d.remaining())
	if e != nil {
		return nil, e
	}
	return &BDFPatch{
		TargetSize: uint64(target),
		compressed: true,
		control:    append([]byte(nil), cb...),
		diff:       append([]byte(nil), db...),
		extra:      append([]byte(nil), eb...),
	}, nil
}
