package rompatcher

import (
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

type BPSPatch struct {
	SourceSize, TargetSize         uint64
	Metadata                       string
	Actions                        []bpsAction
	SourceCRC, TargetCRC, PatchCRC uint32
}

func (*BPSPatch) Format() Format        { return FormatBPS }
func (p *BPSPatch) Description() string { return p.Metadata }
func (p *BPSPatch) ValidateSource(source []byte) bool {
	return uint64(len(source)) == p.SourceSize && CRC32(source) == p.SourceCRC
}
func (p *BPSPatch) ValidationInfo() *ValidationInfo {
	return &ValidationInfo{Type: "CRC32", Values: []string{fmt.Sprintf("%08x", p.SourceCRC)}}
}

func (p *BPSPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	if options.Validate {
		sum, err := crc32Cancelable(source, options)
		if err != nil {
			return nil, err
		}
		if uint64(len(source)) != p.SourceSize || sum != p.SourceCRC {
			return nil, ErrSourceMismatch
		}
	}
	if err := checkOutputSize(p.TargetSize, len(source), options); err != nil {
		return nil, err
	}
	n, err := checkedInt(p.TargetSize)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	pos := 0
	var sourceRel, targetRel int64
	for i, a := range p.Actions {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i), Total: int64(len(p.Actions))}); err != nil {
			return nil, err
		}
		if a.length <= 0 || pos > len(out)-a.length {
			return nil, fmt.Errorf("%w: BPS action exceeds output", ErrInvalidPatch)
		}
		switch a.typ {
		case bpsSourceRead:
			if pos > len(source)-a.length {
				return nil, fmt.Errorf("%w: BPS source read exceeds input", ErrInvalidPatch)
			}
			copy(out[pos:pos+a.length], source[pos:pos+a.length])
			pos += a.length
		case bpsTargetRead:
			if len(a.data) != a.length {
				return nil, ErrInvalidPatch
			}
			copy(out[pos:], a.data)
			pos += a.length
		case bpsSourceCopy:
			var ok bool
			sourceRel, ok = addInt64(sourceRel, a.relative)
			if !ok || sourceRel < 0 || int64(a.length) > int64(len(source))-sourceRel {
				return nil, fmt.Errorf("%w: BPS source copy exceeds input", ErrInvalidPatch)
			}
			copy(out[pos:pos+a.length], source[int(sourceRel):int(sourceRel)+a.length])
			sourceRel += int64(a.length)
			pos += a.length
		case bpsTargetCopy:
			var ok bool
			targetRel, ok = addInt64(targetRel, a.relative)
			if !ok || targetRel < 0 || targetRel >= int64(pos) {
				return nil, fmt.Errorf("%w: invalid BPS target copy", ErrInvalidPatch)
			}
			if !copyOverlapping(out, pos, int(targetRel), a.length) {
				return nil, fmt.Errorf("%w: invalid BPS target copy", ErrInvalidPatch)
			}
			pos += a.length
			targetRel += int64(a.length)
		default:
			return nil, fmt.Errorf("%w: BPS action type", ErrInvalidPatch)
		}
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(len(p.Actions)), Total: int64(len(p.Actions))}); err != nil {
		return nil, err
	}
	if pos != len(out) {
		return nil, fmt.Errorf("%w: BPS output is %d bytes, expected %d", ErrInvalidPatch, pos, len(out))
	}
	if options.Validate {
		sum, err := crc32Cancelable(out, options)
		if err != nil {
			return nil, err
		}
		if sum != p.TargetCRC {
			return nil, ErrTargetMismatch
		}
	}
	return out, nil
}

func (p *BPSPatch) MarshalBinary() ([]byte, error) {
	out := append([]byte{}, "BPS1"...)
	out = appendBPSVLV(out, p.SourceSize)
	out = appendBPSVLV(out, p.TargetSize)
	out = appendBPSVLV(out, uint64(len(p.Metadata)))
	out = append(out, p.Metadata...)
	for _, a := range p.Actions {
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
		p.Actions = append(p.Actions, a)
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
	if CRC32(data[:len(data)-4]) != p.PatchCRC {
		return nil, ErrPatchMismatch
	}
	return p, nil
}

func createBPS(original, modified []byte, delta bool) *BPSPatch {
	p := &BPSPatch{SourceSize: uint64(len(original)), TargetSize: uint64(len(modified)), SourceCRC: CRC32(original), TargetCRC: CRC32(modified)}
	if delta {
		p.Actions = createBPSDelta(original, modified)
	} else {
		p.Actions = createBPSLinear(original, modified)
	}
	b, _ := p.MarshalBinary()
	p.PatchCRC = CRC32(b[:len(b)-4])
	return p
}

func createBPSLinear(source, target []byte) []bpsAction {
	actions := make([]bpsAction, 0)
	output, targetRelative, readStart := 0, 0, -1
	flush := func() {
		if readStart >= 0 {
			data := append([]byte(nil), target[readStart:output]...)
			actions = append(actions, bpsAction{typ: bpsTargetRead, length: len(data), data: data})
			readStart = -1
		}
	}
	for output < len(target) {
		sourceLen := 0
		for output+sourceLen < len(source) && output+sourceLen < len(target) && source[output+sourceLen] == target[output+sourceLen] {
			sourceLen++
		}
		rleLen := 0
		for output+rleLen+1 < len(target) && target[output] == target[output+rleLen+1] {
			rleLen++
		}
		if rleLen >= 4 {
			if readStart < 0 {
				readStart = output
			}
			output++
			flush()
			start := output - 1
			actions = append(actions, bpsAction{typ: bpsTargetCopy, length: rleLen, relative: int64(start - targetRelative)})
			output += rleLen
			targetRelative = output - 1
		} else if sourceLen >= 4 {
			flush()
			actions = append(actions, bpsAction{typ: bpsSourceRead, length: sourceLen})
			output += sourceLen
		} else {
			if readStart < 0 {
				readStart = output
			}
			output++
		}
	}
	flush()
	return actions
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
func bestBPSMatch(haystack, target []byte, targetOffset int, positions []int, bestLength int) (length, offset int) {
	const candidateLimit = 64
	length = bestLength
	center := sort.SearchInts(positions, targetOffset)
	left, right := center-1, center
	for examined := 0; examined < candidateLimit && (left >= 0 || right < len(positions)); examined++ {
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
		}
		if n > length {
			length, offset = n, candidate
			if length == len(target)-targetOffset {
				break
			}
		}
	}
	return length, offset
}

func createBPSDelta(source, target []byte) []bpsAction {
	sourceTree := make(map[uint16][]int)
	for i := range source {
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
		if length, offset := bestBPSMatch(source, target, output, positions, maxLen); length > maxLen {
			maxLen, maxOff, mode = length, offset, bpsSourceCopy
		}
		positions = targetTree[sym]
		if length, offset := bestBPSMatch(target, target, output, positions, maxLen); length > maxLen {
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
	return actions
}
