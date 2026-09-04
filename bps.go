package rompatcher

import (
	"context"
	"fmt"
	"sort"
)

const (
	bpsSourceRead = iota
	bpsTargetRead
	bpsSourceCopy
	bpsTargetCopy
)

type bpsAction struct {
	typ      int
	length   int
	data     []byte
	relative int64
}

type bpsActionState struct {
	position       uint64
	sourceRelative uint64
	targetRelative uint64
}

func addSignedOffset(position uint64, delta int64) (uint64, bool) {
	if delta >= 0 {
		amount := uint64(delta)
		return position + amount, position <= ^uint64(0)-amount
	}
	amount := uint64(-(delta + 1)) + 1
	return position - amount, position >= amount
}

func (s *bpsActionState) advance(actionType int, length uint64, relative int64, sourceSize, targetSize uint64) (uint64, error) {
	if length == 0 || actionType < bpsSourceRead || actionType > bpsTargetCopy || length > targetSize || s.position > targetSize-length {
		return 0, fmt.Errorf("%w: BPS action exceeds output", ErrInvalidPatch)
	}
	var copyPosition uint64
	switch actionType {
	case bpsSourceRead:
		copyPosition = s.position
		if length > sourceSize || copyPosition > sourceSize-length {
			return 0, fmt.Errorf("%w: BPS source read exceeds input", ErrInvalidPatch)
		}
	case bpsSourceCopy:
		var ok bool
		copyPosition, ok = addSignedOffset(s.sourceRelative, relative)
		if !ok || length > sourceSize || copyPosition > sourceSize-length {
			return 0, fmt.Errorf("%w: BPS source copy exceeds input", ErrInvalidPatch)
		}
		s.sourceRelative = copyPosition + length
	case bpsTargetCopy:
		var ok bool
		copyPosition, ok = addSignedOffset(s.targetRelative, relative)
		if !ok || copyPosition >= s.position {
			return 0, fmt.Errorf("%w: BPS target copy has no prior data", ErrInvalidPatch)
		}
		s.targetRelative = copyPosition + length
	}
	s.position += length
	return copyPosition, nil
}

func (p *BPSPatch) validateActions() error {
	state := bpsActionState{}
	for _, action := range p.actions {
		if action.length <= 0 {
			return fmt.Errorf("%w: empty BPS action", ErrInvalidPatch)
		}
		if action.typ == bpsTargetRead && len(action.data) != action.length {
			return fmt.Errorf("%w: BPS literal length", ErrInvalidPatch)
		}
		if _, err := state.advance(action.typ, uint64(action.length), action.relative, p.SourceSize, p.TargetSize); err != nil {
			return err
		}
	}
	if state.position != p.TargetSize {
		return fmt.Errorf("%w: BPS actions produce %d bytes, expected %d", ErrInvalidPatch, state.position, p.TargetSize)
	}
	return nil
}

// BPSPatch is a parsed BPS patch.
type BPSPatch struct {
	SourceSize, TargetSize         uint64
	Metadata                       string
	actions                        []bpsAction
	SourceCRC, TargetCRC, PatchCRC uint32
}

// Format implements Patch.
func (*BPSPatch) Format() Format { return FormatBPS }

// Description implements Patch.
func (p *BPSPatch) Description() string { return p.Metadata }

// ValidateSource implements Patch.
func (p *BPSPatch) ValidateSource(source []byte) bool {
	return uint64(len(source)) == p.SourceSize && CRC32(source) == p.SourceCRC
}

// ValidationInfo implements Patch.
func (p *BPSPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "CRC32", Values: []string{fmt.Sprintf("%08x", p.SourceCRC)}}
}

// Apply implements Patch.
func (p *BPSPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary implements Patch.
func (p *BPSPatch) MarshalBinary() ([]byte, error) {
	if err := p.validateActions(); err != nil {
		return nil, err
	}
	out := append([]byte{}, "BPS1"...)
	out = appendBPSVLV(out, p.SourceSize)
	out = appendBPSVLV(out, p.TargetSize)
	out = appendBPSVLV(out, uint64(len(p.Metadata)))
	out = append(out, p.Metadata...)
	for _, a := range p.actions {
		if a.length <= 0 || a.typ < bpsSourceRead || a.typ > bpsTargetCopy {
			return nil, fmt.Errorf("%w: empty BPS action", ErrInvalidPatch)
		}
		out = appendBPSVLV(out, (uint64(a.length-1)<<2)|uint64(a.typ))
		switch a.typ {
		case bpsTargetRead:
			if len(a.data) != a.length {
				return nil, ErrInvalidPatch
			}
			out = append(out, a.data...)
		case bpsSourceCopy, bpsTargetCopy:
			if a.relative == -int64(^uint64(0)>>1)-1 {
				return nil, fmt.Errorf("%w: BPS relative offset", ErrInvalidPatch)
			}
			v := uint64(a.relative)
			if a.relative < 0 {
				v = uint64(-a.relative)<<1 | 1
			} else {
				v <<= 1
			}
			out = appendBPSVLV(out, v)
		}
	}
	out = appendU32LE(out, p.SourceCRC)
	out = appendU32LE(out, p.TargetCRC)
	crc := CRC32(out)
	out = appendU32LE(out, crc)
	return out, nil
}

func parseBPS(data []byte) (*BPSPatch, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("%w: BPS header", ErrInvalidPatch)
	}
	d := newDecoder(data)
	_ = d.seek(4)
	ss, e := readBPSVLV(d)
	if e != nil {
		return nil, e
	}
	ts, e := readBPSVLV(d)
	if e != nil {
		return nil, e
	}
	ml, e := readBPSVLV(d)
	if e != nil {
		return nil, e
	}
	mn, e := checkedInt(ml)
	if e != nil {
		return nil, e
	}
	meta, e := d.string(mn)
	if e != nil {
		return nil, e
	}
	p := &BPSPatch{SourceSize: ss, TargetSize: ts, Metadata: meta}
	for d.off < len(data)-12 {
		v, e := readBPSVLV(d)
		if e != nil {
			return nil, e
		}
		ln, e := checkedInt((v >> 2) + 1)
		if e != nil {
			return nil, e
		}
		a := bpsAction{typ: int(v & 3), length: ln}
		switch a.typ {
		case bpsTargetRead:
			b, e := d.bytes(ln)
			if e != nil {
				return nil, e
			}
			a.data = append([]byte(nil), b...)
		case bpsSourceCopy, bpsTargetCopy:
			r, e := readBPSVLV(d)
			if e != nil {
				return nil, e
			}
			a.relative = int64(r >> 1)
			if r&1 != 0 {
				a.relative = -a.relative
			}
		}
		if d.off > len(data)-12 {
			return nil, ErrUnexpectedEnd
		}
		p.actions = append(p.actions, a)
	}
	if d.off != len(data)-12 {
		return nil, fmt.Errorf("%w: BPS footer boundary", ErrInvalidPatch)
	}
	p.SourceCRC, e = d.u32le()
	if e != nil {
		return nil, e
	}
	p.TargetCRC, e = d.u32le()
	if e != nil {
		return nil, e
	}
	p.PatchCRC, e = d.u32le()
	if e != nil {
		return nil, e
	}
	if got := CRC32(data[:len(data)-4]); got != p.PatchCRC {
		return nil, checksum32Mismatch(ErrPatchMismatch, FormatBPS, "CRC32", p.PatchCRC, got)
	}
	if err := p.validateActions(); err != nil {
		return nil, err
	}
	return p, nil
}

func createBPSDeltaPatch(original, modified []byte, opts CreateOptions) (*BPSPatch, error) {
	ctx := createContext(opts)
	actions, err := createBPSDelta(ctx, original, modified, func(completed, total int64) error {
		return reportCreate(opts, FormatBPS, completed, total)
	})
	if err != nil {
		return nil, err
	}
	p := &BPSPatch{SourceSize: uint64(len(original)), TargetSize: uint64(len(modified)), Metadata: opts.Description, SourceCRC: CRC32(original), TargetCRC: CRC32(modified), actions: actions}
	return p, nil
}

func bpsSymbol(data []byte, off int) uint16 {
	v := uint16(data[off])
	if off+1 < len(data) {
		v |= uint16(data[off+1]) << 8
	}
	return v
}

// bestBPSMatch examines positions nearest the current output offset. Repeated
// data can contain millions of identical two-byte symbols; scanning every
// occurrence makes otherwise small BPS creation quadratic without improving
// the result once a nearby long match is available.
func bestBPSMatch(ctx context.Context, haystack, target []byte, targetOffset int, positions []int, bestLength int) (length, offset int, err error) {
	const candidateLimit = 64
	length = bestLength
	center := sort.SearchInts(positions, targetOffset)
	left, right := center-1, center
	for examined := 0; examined < candidateLimit && (left >= 0 || right < len(positions)); examined++ {
		if examined&7 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, 0, err
			}
		}
		var candidate int
		if left >= 0 && (right >= len(positions) || targetOffset-positions[left] <= positions[right]-targetOffset) {
			candidate = positions[left]
			left--
		} else {
			candidate = positions[right]
			right++
		}
		x, y, n := candidate, targetOffset, 0
		for x < len(haystack) && y < len(target) && haystack[x] == target[y] {
			x++
			y++
			n++
			if n&((64<<10)-1) == 0 {
				if err := ctx.Err(); err != nil {
					return 0, 0, err
				}
			}
		}
		if n > length {
			length, offset = n, candidate
			if length == len(target)-targetOffset {
				break
			}
		}
	}
	return length, offset, nil
}

func createBPSDelta(ctx context.Context, source, target []byte, progress func(int64, int64) error) ([]bpsAction, error) {
	total := int64(len(source)) + int64(len(target))
	sourceTree := make(map[uint16][]int)
	for i := range source {
		if i&(fileChunkSize-1) == 0 {
			if err := progress(int64(i), total); err != nil {
				return nil, err
			}
		}
		sym := bpsSymbol(source, i)
		sourceTree[sym] = append(sourceTree[sym], i)
	}
	targetTree := make(map[uint16][]int)
	actions := make([]bpsAction, 0)
	output, sourceRel, targetRel, readStart := 0, 0, 0, -1
	flush := func() {
		if readStart >= 0 {
			data := append([]byte(nil), target[readStart:output]...)
			actions = append(actions, bpsAction{typ: bpsTargetRead, length: len(data), data: data})
			readStart = -1
		}
	}
	for output < len(target) {
		if output&(fileChunkSize-1) == 0 {
			if err := progress(int64(len(source)+output), total); err != nil {
				return nil, err
			}
		}
		maxLen, maxOff, mode := 0, 0, bpsTargetRead
		sym := bpsSymbol(target, output)
		ln := 0
		for output+ln < len(source) && output+ln < len(target) && source[output+ln] == target[output+ln] {
			ln++
		}
		if ln > maxLen {
			maxLen, mode = ln, bpsSourceRead
		}
		positions := sourceTree[sym]
		if length, offset, err := bestBPSMatch(ctx, source, target, output, positions, maxLen); err != nil {
			return nil, err
		} else if length > maxLen {
			maxLen, maxOff, mode = length, offset, bpsSourceCopy
		}
		positions = targetTree[sym]
		if length, offset, err := bestBPSMatch(ctx, target, target, output, positions, maxLen); err != nil {
			return nil, err
		} else if length > maxLen {
			maxLen, maxOff, mode = length, offset, bpsTargetCopy
		}
		targetTree[sym] = append(targetTree[sym], output)
		if maxLen < 4 {
			maxLen = 1
			mode = bpsTargetRead
		}
		if mode != bpsTargetRead {
			flush()
		}
		switch mode {
		case bpsSourceRead:
			actions = append(actions, bpsAction{typ: mode, length: maxLen})
		case bpsTargetRead:
			if readStart < 0 {
				readStart = output
			}
		case bpsSourceCopy:
			actions = append(actions, bpsAction{typ: mode, length: maxLen, relative: int64(maxOff - sourceRel)})
			sourceRel = maxOff + maxLen
		case bpsTargetCopy:
			actions = append(actions, bpsAction{typ: mode, length: maxLen, relative: int64(maxOff - targetRel)})
			targetRel = maxOff + maxLen
		}
		output += maxLen
	}
	flush()
	if err := progress(total, total); err != nil {
		return nil, err
	}
	return actions, nil
}
