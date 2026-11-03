package rompatcher

import (
	"bytes"
	"context"
	"fmt"
)

const (
	vcdDecompress = 0x01
	vcdCodeTable  = 0x02
	vcdAppHeader  = 0x04
	vcdSource     = 0x01
	vcdTarget     = 0x02
	vcdAdler32    = 0x04
	vcdNoop       = 0
	vcdAdd        = 1
	vcdRun        = 2
	vcdCopy       = 3
)

type vcdInstruction struct{ typ, size, mode int }
type vcdWindow struct {
	indicator                                    byte
	deltaIndicator                               byte
	sourceLength, sourcePosition, targetLength   int
	dataLength, instructionLength, addressLength int
	adler                                        *uint32
}

// VCDIFFPatch is a parsed VCDIFF/xdelta patch.
type VCDIFFPatch struct {
	basePatch
	data        []byte
	table       [256][2]vcdInstruction
	nearSize    int
	sameSize    int
	secondaryID byte
	windowCount int
}

func vcdSecondaryName(id byte) string {
	switch id {
	case 1:
		return "DJW"
	case 2:
		return "LZMA"
	case 16:
		return "FGK"
	default:
		return "unknown"
	}
}

func (p *VCDIFFPatch) unsupportedSecondary(flags byte) error {
	return fmt.Errorf("%w: VCDIFF uses %s secondary compression (ID %d, section flags 0x%02x)", ErrUnsupported, vcdSecondaryName(p.secondaryID), p.secondaryID, flags)
}

// Format implements Patch.
func (*VCDIFFPatch) Format() Format { return FormatVCDIFF }

// MarshalBinary reports that VCDIFF creation is unsupported.
func (*VCDIFFPatch) MarshalBinary() ([]byte, error) { return nil, ErrUnsupported }

func parseVCDIFFWithOptions(data []byte, opts ApplyOptions) (*VCDIFFPatch, error) {
	ctx := contextOf(opts)
	header, err := parseVCDStreamHeader(ctx, bytes.NewReader(data), int64(len(data)), opts, 0)
	if err != nil {
		return nil, err
	}
	p := &VCDIFFPatch{table: header.table, nearSize: header.nearSize, sameSize: header.sameSize, secondaryID: header.secondaryID}
	windows := newReaderDecoder(ctx, bytes.NewReader(data), int64(len(data)))
	if err := windows.seek(header.headerEnd); err != nil {
		return nil, err
	}
	for !windows.eof() {
		w, end, err := decodeVCDWindowReader(windows)
		if err != nil {
			return nil, err
		}
		if w.deltaIndicator != 0 && p.secondaryID == 0 {
			return nil, fmt.Errorf("%w: VCDIFF compressed section without a secondary compressor", ErrInvalidPatch)
		}
		if err := windows.seek(end); err != nil {
			return nil, err
		}
		p.windowCount++
	}
	p.data = make([]byte, len(data))
	if err := copyBytesContext(ctx, p.data, data); err != nil {
		return nil, err
	}
	return p, nil
}

type addressCache struct {
	near   []int
	same   []int
	next   int
	stream *decoder
}

func newAddressCache(stream *decoder, nearSize, sameSize int) *addressCache {
	return &addressCache{near: make([]int, nearSize), same: make([]int, sameSize*256), stream: stream}
}
func (c *addressCache) decode(here, mode int) (int, error) {
	var addr int
	switch {
	case mode == 0:
		v, e := readBE7(c.stream)
		if e != nil {
			return 0, e
		}
		n, e := checkedInt(v)
		if e != nil {
			return 0, e
		}
		addr = n
	case mode == 1:
		v, e := readBE7(c.stream)
		if e != nil {
			return 0, e
		}
		n, e := checkedInt(v)
		if e != nil {
			return 0, e
		}
		addr = here - n
	case mode-2 < len(c.near):
		v, e := readBE7(c.stream)
		if e != nil {
			return 0, e
		}
		n, e := checkedInt(v)
		if e != nil {
			return 0, e
		}
		base := c.near[mode-2]
		if n > int(^uint(0)>>1)-base {
			return 0, fmt.Errorf("%w: VCDIFF address overflow", ErrInvalidPatch)
		}
		addr = base + n
	default:
		m := mode - (2 + len(c.near))
		if m < 0 || m >= len(c.same)/256 {
			return 0, fmt.Errorf("%w: VCDIFF address mode", ErrInvalidPatch)
		}
		b, e := c.stream.u8()
		if e != nil {
			return 0, e
		}
		addr = c.same[m*256+int(b)]
	}
	if addr < 0 {
		return 0, fmt.Errorf("%w: negative VCDIFF address", ErrInvalidPatch)
	}
	if len(c.near) > 0 {
		c.near[c.next] = addr
		c.next = (c.next + 1) % len(c.near)
	}
	if len(c.same) > 0 {
		c.same[addr%len(c.same)] = addr
	}
	return addr, nil
}

func defaultVCDTable() [256][2]vcdInstruction {
	var table [256][2]vcdInstruction
	i := 0
	add := func(a, b vcdInstruction) {
		if i >= 256 {
			panic("invalid VCDIFF table")
		}
		table[i] = [2]vcdInstruction{a, b}
		i++
	}
	empty := vcdInstruction{typ: vcdNoop}
	add(vcdInstruction{typ: vcdRun}, empty)
	for size := 0; size < 18; size++ {
		add(vcdInstruction{typ: vcdAdd, size: size}, empty)
	}
	for mode := 0; mode < 9; mode++ {
		add(vcdInstruction{typ: vcdCopy, mode: mode}, empty)
		for size := 4; size < 19; size++ {
			add(vcdInstruction{typ: vcdCopy, size: size, mode: mode}, empty)
		}
	}
	for mode := 0; mode < 6; mode++ {
		for as := 1; as < 5; as++ {
			for cs := 4; cs < 7; cs++ {
				add(vcdInstruction{typ: vcdAdd, size: as}, vcdInstruction{typ: vcdCopy, size: cs, mode: mode})
			}
		}
	}
	for mode := 6; mode < 9; mode++ {
		for as := 1; as < 5; as++ {
			add(vcdInstruction{typ: vcdAdd, size: as}, vcdInstruction{typ: vcdCopy, size: 4, mode: mode})
		}
	}
	for mode := 0; mode < 9; mode++ {
		add(vcdInstruction{typ: vcdCopy, size: 4, mode: mode}, vcdInstruction{typ: vcdAdd, size: 1})
	}
	return table
}

var vcdTable = defaultVCDTable()

func encodeVCDTable(table [256][2]vcdInstruction) []byte {
	out := make([]byte, 0, 256*6)
	for field := 0; field < 6; field++ {
		for i := 0; i < 256; i++ {
			ins := table[i][field%2]
			switch field / 2 {
			case 0:
				out = append(out, byte(ins.typ))
			case 1:
				out = append(out, byte(ins.size))
			case 2:
				out = append(out, byte(ins.mode))
			}
		}
	}
	return out
}

func decodeVCDCodeTable(ctx context.Context, encoded []byte, depth int, opts ApplyOptions) ([256][2]vcdInstruction, error) {
	var table [256][2]vcdInstruction
	if err := ctx.Err(); err != nil {
		return table, err
	}
	data := encoded
	if len(data) < 5 || data[0] != 0xd6 || data[1] != 0xc3 || data[2] != 0xc4 {
		var err error
		data, err = appendContext(ctx, []byte{0xd6, 0xc3, 0xc4, 0, 0}, data)
		if err != nil {
			return table, err
		}
	}
	// Table sections have their own budget; the engine checks the exact 1536-byte
	// output bound before allocating a window. Inherit the caller's dictionary
	// ceiling before replacing the final-output limit.
	nested := ApplyOptions{Context: ctx, MaxOutputSize: 64 << 20, MaxWindowSize: opts.MaxWindowSize, MaxDictionarySize: lzmaDictionaryLimit(opts)}
	source := encodeVCDTable(vcdTable)
	output := &memoryFile{data: make([]byte, 0, 256*6)}
	size, err := applyVCDIFFStreamDepth(ctx, bytes.NewReader(source), int64(len(source)), bytes.NewReader(data), int64(len(data)), output, output, nested, depth)
	if err != nil {
		return table, fmt.Errorf("VCDIFF custom code table: %w", err)
	}
	if size != 256*6 {
		return table, fmt.Errorf("%w: VCDIFF custom code table output", ErrInvalidPatch)
	}
	raw := output.data
	for field := 0; field < 6; field++ {
		for i := 0; i < 256; i++ {
			value := int(raw[field*256+i])
			ins := &table[i][field%2]
			switch field / 2 {
			case 0:
				if value < vcdNoop || value > vcdCopy {
					return table, fmt.Errorf("%w: VCDIFF code table instruction", ErrInvalidPatch)
				}
				ins.typ = value
			case 1:
				ins.size = value
			case 2:
				ins.mode = value
			}
		}
	}
	return table, nil
}

func validateVCDTable(table [256][2]vcdInstruction, nearSize, sameSize int) error {
	maxMode := 2 + nearSize + sameSize
	for _, pair := range table {
		for _, ins := range pair {
			switch ins.typ {
			case vcdNoop:
				if ins.size != 0 {
					return fmt.Errorf("%w: VCDIFF NOOP with size", ErrInvalidPatch)
				}
			case vcdAdd, vcdRun:
				if ins.mode != 0 {
					return fmt.Errorf("%w: VCDIFF non-COPY mode", ErrInvalidPatch)
				}
			case vcdCopy:
				if ins.mode < 0 || ins.mode >= maxMode {
					return fmt.Errorf("%w: VCDIFF COPY mode", ErrInvalidPatch)
				}
			default:
				return fmt.Errorf("%w: VCDIFF instruction", ErrInvalidPatch)
			}
		}
	}
	return nil
}

type vcdExternalReader func(dst []byte, offset int64, target bool) error

func (p *VCDIFFPatch) decodeTargetWindow(w vcdWindow, dataSection, instSection, addrSection []byte, targetPosition, sourceSize int64, readExternal vcdExternalReader, options ApplyOptions) ([]byte, error) {
	sourceLength, sourcePosition := int64(w.sourceLength), int64(w.sourcePosition)
	switch {
	case w.indicator&vcdSource != 0:
		if sourceLength > sourceSize || sourcePosition > sourceSize-sourceLength {
			return nil, fmt.Errorf("%w: VCDIFF source segment", ErrSourceMismatch)
		}
	case w.indicator&vcdTarget != 0:
		if sourceLength > targetPosition || sourcePosition > targetPosition-sourceLength {
			return nil, fmt.Errorf("%w: VCDIFF target source segment", ErrInvalidPatch)
		}
	}
	window := make([]byte, w.targetLength)
	dataStream, instStream, addrStream := newDecoder(dataSection), newDecoder(instSection), newDecoder(addrSection)
	cache := newAddressCache(addrStream, p.nearSize, p.sameSize)
	produced := 0
	for !instStream.eof() {
		code, err := instStream.u8()
		if err != nil {
			return nil, err
		}
		for _, ins := range p.table[code] {
			size := ins.size
			if size == 0 && ins.typ != vcdNoop {
				v, err := readBE7(instStream)
				if err != nil {
					return nil, err
				}
				size, err = checkedInt(v)
				if err != nil {
					return nil, err
				}
			}
			if size < 0 || size > w.targetLength-produced {
				return nil, fmt.Errorf("%w: VCDIFF instruction exceeds window", ErrInvalidPatch)
			}
			switch ins.typ {
			case vcdNoop:
				continue
			case vcdAdd:
				b, err := dataStream.bytes(size)
				if err != nil {
					return nil, err
				}
				copy(window[produced:], b)
				produced += size
			case vcdRun:
				b, err := dataStream.u8()
				if err != nil {
					return nil, err
				}
				fillBytes(window[produced:produced+size], b)
				produced += size
			case vcdCopy:
				if produced > int(^uint(0)>>1)-w.sourceLength {
					return nil, fmt.Errorf("%w: VCDIFF address overflow", ErrInvalidPatch)
				}
				addr, err := cache.decode(w.sourceLength+produced, ins.mode)
				if err != nil {
					return nil, err
				}
				remaining := size
				if addr < w.sourceLength {
					n := remaining
					if w.sourceLength-addr < n {
						n = w.sourceLength - addr
					}
					if err := readExternal(window[produced:produced+n], sourcePosition+int64(addr), w.indicator&vcdTarget != 0); err != nil {
						return nil, err
					}
					produced, addr, remaining = produced+n, addr+n, remaining-n
				}
				if remaining > 0 {
					from := addr - w.sourceLength
					if !copyOverlapping(window, produced, from, remaining) {
						return nil, fmt.Errorf("%w: VCDIFF target copy address", ErrInvalidPatch)
					}
					produced += remaining
				}
			default:
				return nil, fmt.Errorf("%w: VCDIFF instruction", ErrInvalidPatch)
			}
		}
		if err := checkCanceled(options); err != nil {
			return nil, err
		}
	}
	if produced != w.targetLength {
		return nil, fmt.Errorf("%w: VCDIFF window produced %d of %d bytes", ErrInvalidPatch, produced, w.targetLength)
	}
	if !dataStream.eof() || !addrStream.eof() {
		return nil, fmt.Errorf("%w: unused VCDIFF section data", ErrInvalidPatch)
	}
	if options.Validate && w.adler != nil {
		sum, err := adler32Cancelable(window, options)
		if err != nil {
			return nil, err
		}
		if sum != *w.adler {
			return nil, checksum32Mismatch(ErrTargetMismatch, FormatVCDIFF, "Adler-32", *w.adler, sum)
		}
	}
	return window, nil
}

// Apply implements Patch.
func (p *VCDIFFPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}
