package rompatcher

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type rupRecord struct {
	offset uint64
	xor    []byte
}
type rupFile struct {
	FileName               string
	ROMType                byte
	SourceSize, TargetSize uint64
	SourceMD5, TargetMD5   string
	OverflowMode           byte
	Overflow               []byte
	Records                []rupRecord
}
type RUPPatch struct {
	TextEncoding                                                         byte
	Author, Version, Title, Genre, Language, Date, Web, PatchDescription string
	Files                                                                []rupFile
}

func (*RUPPatch) Format() Format        { return FormatRUP }
func (p *RUPPatch) Description() string { return p.PatchDescription }
func (p *RUPPatch) ValidateSource(source []byte) bool {
	sum := MD5(source)
	for _, f := range p.Files {
		if sum == f.SourceMD5 || sum == f.TargetMD5 {
			return true
		}
	}
	return false
}
func (p *RUPPatch) ValidationInfo() *ValidationInfo {
	v := make([]string, 0, len(p.Files)*2)
	for _, f := range p.Files {
		v = append(v, f.SourceMD5, f.TargetMD5)
	}
	return &ValidationInfo{Type: "MD5", Values: v}
}

func (p *RUPPatch) matchingFile(sum string) (file *rupFile, undo bool) {
	for i := range p.Files {
		if sum == p.Files[i].SourceMD5 || sum == p.Files[i].TargetMD5 {
			return &p.Files[i], sum == p.Files[i].TargetMD5
		}
	}
	return nil, false
}

func validateRUPFile(f *rupFile) error {
	var maximum, overflowSize uint64
	switch {
	case f.SourceSize < f.TargetSize:
		maximum, overflowSize = f.TargetSize, f.TargetSize-f.SourceSize
		if f.OverflowMode != 'A' {
			return fmt.Errorf("%w: RUP append overflow mode", ErrInvalidPatch)
		}
	case f.SourceSize > f.TargetSize:
		maximum, overflowSize = f.SourceSize, f.SourceSize-f.TargetSize
		if f.OverflowMode != 'M' {
			return fmt.Errorf("%w: RUP minify overflow mode", ErrInvalidPatch)
		}
	default:
		maximum = f.SourceSize
		if f.OverflowMode != 0 || len(f.Overflow) != 0 {
			return fmt.Errorf("%w: unexpected RUP overflow data", ErrInvalidPatch)
		}
	}
	// Some real-world NINJA2 writers encode all or part of the resized tail as
	// XOR records and leave the overflow block shorter than the size delta.
	if uint64(len(f.Overflow)) > overflowSize {
		return fmt.Errorf("%w: RUP overflow length", ErrInvalidPatch)
	}
	for _, r := range f.Records {
		length := uint64(len(r.xor))
		if length == 0 || length > maximum || r.offset > maximum-length {
			return fmt.Errorf("%w: RUP record outside file range", ErrInvalidPatch)
		}
	}
	return nil
}
func (p *RUPPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	sum, err := md5Cancelable(source, options)
	if err != nil {
		return nil, err
	}
	f, undo := p.matchingFile(sum)
	if f == nil {
		if options.Validate {
			return nil, ErrSourceMismatch
		}
		if len(p.Files) == 0 {
			return nil, fmt.Errorf("%w: RUP has no files", ErrInvalidPatch)
		}
		f = &p.Files[0]
	}
	if e := validateRUPFile(f); e != nil {
		return nil, e
	}
	size := f.TargetSize
	if undo {
		size = f.SourceSize
	}
	if err := checkOutputSize(size, len(source), options); err != nil {
		return nil, err
	}
	n, e := checkedInt(size)
	if e != nil {
		return nil, e
	}
	out, e := resizedCopy(source, n)
	if e != nil {
		return nil, e
	}
	for recordIndex, r := range f.Records {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(recordIndex), Total: int64(len(f.Records))}); err != nil {
			return nil, err
		}
		start, e := checkedInt(r.offset)
		if e != nil {
			return nil, e
		}
		if start >= len(out) {
			continue
		}
		length := len(r.xor)
		if len(out)-start < length {
			length = len(out) - start
		}
		for i, x := range r.xor[:length] {
			var b byte
			if start+i < len(source) {
				b = source[start+i]
			}
			out[start+i] = b ^ x
		}
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(len(f.Records)), Total: int64(len(f.Records))}); err != nil {
		return nil, err
	}
	if f.OverflowMode == 'A' && !undo {
		start, e := checkedInt(f.SourceSize)
		if e != nil {
			return nil, e
		}
		if start > len(out)-len(f.Overflow) {
			return nil, ErrInvalidPatch
		}
		for i, b := range f.Overflow {
			out[start+i] = b ^ 0xff
		}
	} else if f.OverflowMode == 'M' && undo {
		start, e := checkedInt(f.TargetSize)
		if e != nil {
			return nil, e
		}
		if start > len(out)-len(f.Overflow) {
			return nil, ErrInvalidPatch
		}
		for i, b := range f.Overflow {
			out[start+i] = b ^ 0xff
		}
	}
	if options.Validate {
		want := f.TargetMD5
		if undo {
			want = f.SourceMD5
		}
		sum, err := md5Cancelable(out, options)
		if err != nil {
			return nil, err
		}
		if sum != want {
			return nil, ErrTargetMismatch
		}
	}
	return out, nil
}

func readRUPVLV(d *decoder) (uint64, error) {
	n, e := d.u8()
	if e != nil {
		return 0, e
	}
	if n > 8 {
		return 0, fmt.Errorf("%w: RUP integer too long", ErrInvalidPatch)
	}
	var v uint64
	for i := 0; i < int(n); i++ {
		b, e := d.u8()
		if e != nil {
			return 0, e
		}
		v |= uint64(b) << (8 * i)
	}
	return v, nil
}
func appendRUPVLV(dst []byte, v uint64) []byte {
	n := 0
	for x := v; x > 0; x >>= 8 {
		n++
	}
	dst = append(dst, byte(n))
	for i := 0; i < n; i++ {
		dst = append(dst, byte(v>>(8*i)))
	}
	return dst
}
func readFixed(d *decoder, n int) (string, error) {
	s, e := d.string(n)
	return strings.TrimRight(s, "\x00"), e
}
func md5Bytes(s string) ([]byte, error) {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 16 {
		return nil, fmt.Errorf("%w: invalid RUP MD5", ErrInvalidPatch)
	}
	return b, nil
}

func (p *RUPPatch) MarshalBinary() ([]byte, error) {
	if len(p.Files) == 0 {
		return nil, fmt.Errorf("%w: RUP has no files", ErrInvalidPatch)
	}
	out := append([]byte{}, "NINJA2"...)
	out = append(out, p.TextEncoding)
	out = append(out, fixedString(p.Author, 84)...)
	out = append(out, fixedString(p.Version, 11)...)
	out = append(out, fixedString(p.Title, 256)...)
	out = append(out, fixedString(p.Genre, 48)...)
	out = append(out, fixedString(p.Language, 48)...)
	out = append(out, fixedString(p.Date, 8)...)
	out = append(out, fixedString(p.Web, 512)...)
	out = append(out, fixedString(strings.ReplaceAll(p.PatchDescription, "\n", "\\n"), 1074)...)
	if len(out) != 0x800 {
		return nil, fmt.Errorf("%w: RUP header size", ErrInvalidPatch)
	}
	for _, f := range p.Files {
		if e := validateRUPFile(&f); e != nil {
			return nil, e
		}
		out = append(out, 1)
		out = appendRUPVLV(out, uint64(len(f.FileName)))
		out = append(out, f.FileName...)
		out = append(out, f.ROMType)
		out = appendRUPVLV(out, f.SourceSize)
		out = appendRUPVLV(out, f.TargetSize)
		b, e := md5Bytes(f.SourceMD5)
		if e != nil {
			return nil, e
		}
		out = append(out, b...)
		b, e = md5Bytes(f.TargetMD5)
		if e != nil {
			return nil, e
		}
		out = append(out, b...)
		if f.SourceSize != f.TargetSize {
			if f.OverflowMode != 'A' && f.OverflowMode != 'M' {
				return nil, fmt.Errorf("%w: RUP overflow mode", ErrInvalidPatch)
			}
			out = append(out, f.OverflowMode)
			out = appendRUPVLV(out, uint64(len(f.Overflow)))
			out = append(out, f.Overflow...)
		}
		for _, r := range f.Records {
			out = append(out, 2)
			out = appendRUPVLV(out, r.offset)
			out = appendRUPVLV(out, uint64(len(r.xor)))
			out = append(out, r.xor...)
		}
	}
	out = append(out, 0)
	return out, nil
}

func parseRUP(data []byte) (*RUPPatch, error) {
	if len(data) < 0x801 {
		return nil, fmt.Errorf("%w: RUP header", ErrInvalidPatch)
	}
	d := newDecoder(data)
	_ = d.seek(6)
	p := &RUPPatch{}
	var e error
	p.TextEncoding, e = d.u8()
	if e != nil {
		return nil, e
	}
	if p.Author, e = readFixed(d, 84); e != nil {
		return nil, e
	}
	if p.Version, e = readFixed(d, 11); e != nil {
		return nil, e
	}
	if p.Title, e = readFixed(d, 256); e != nil {
		return nil, e
	}
	if p.Genre, e = readFixed(d, 48); e != nil {
		return nil, e
	}
	if p.Language, e = readFixed(d, 48); e != nil {
		return nil, e
	}
	if p.Date, e = readFixed(d, 8); e != nil {
		return nil, e
	}
	if p.Web, e = readFixed(d, 512); e != nil {
		return nil, e
	}
	if p.PatchDescription, e = readFixed(d, 1074); e != nil {
		return nil, e
	}
	p.PatchDescription = strings.ReplaceAll(p.PatchDescription, "\\n", "\n")
	_ = d.seek(0x800)
	var current *rupFile
	for !d.eof() {
		cmd, e := d.u8()
		if e != nil {
			return nil, e
		}
		switch cmd {
		case 0:
			if current != nil {
				if e := validateRUPFile(current); e != nil {
					return nil, e
				}
				p.Files = append(p.Files, *current)
			}
			if !d.eof() {
				return nil, fmt.Errorf("%w: data after RUP end command", ErrInvalidPatch)
			}
			if len(p.Files) == 0 {
				return nil, fmt.Errorf("%w: RUP has no files", ErrInvalidPatch)
			}
			return p, nil
		case 1:
			if current != nil {
				if e := validateRUPFile(current); e != nil {
					return nil, e
				}
				p.Files = append(p.Files, *current)
			}
			current = &rupFile{}
			ln, e := readRUPVLV(d)
			if e != nil {
				return nil, e
			}
			n, e := checkedInt(ln)
			if e != nil {
				return nil, e
			}
			current.FileName, e = d.string(n)
			if e != nil {
				return nil, e
			}
			current.ROMType, e = d.u8()
			if e != nil {
				return nil, e
			}
			current.SourceSize, e = readRUPVLV(d)
			if e != nil {
				return nil, e
			}
			current.TargetSize, e = readRUPVLV(d)
			if e != nil {
				return nil, e
			}
			b, e := d.bytes(16)
			if e != nil {
				return nil, e
			}
			current.SourceMD5 = hex.EncodeToString(b)
			b, e = d.bytes(16)
			if e != nil {
				return nil, e
			}
			current.TargetMD5 = hex.EncodeToString(b)
			if current.SourceSize != current.TargetSize {
				current.OverflowMode, e = d.u8()
				if e != nil {
					return nil, e
				}
				if current.OverflowMode != 'A' && current.OverflowMode != 'M' {
					return nil, fmt.Errorf("%w: RUP overflow mode", ErrInvalidPatch)
				}
				ln, e = readRUPVLV(d)
				if e != nil {
					return nil, e
				}
				n, e = checkedInt(ln)
				if e != nil {
					return nil, e
				}
				b, e = d.bytes(n)
				if e != nil {
					return nil, e
				}
				current.Overflow = append([]byte(nil), b...)
			}
		case 2:
			if current == nil {
				return nil, fmt.Errorf("%w: RUP record before file", ErrInvalidPatch)
			}
			off, e := readRUPVLV(d)
			if e != nil {
				return nil, e
			}
			ln, e := readRUPVLV(d)
			if e != nil {
				return nil, e
			}
			n, e := checkedInt(ln)
			if e != nil {
				return nil, e
			}
			b, e := d.bytes(n)
			if e != nil {
				return nil, e
			}
			current.Records = append(current.Records, rupRecord{offset: off, xor: append([]byte(nil), b...)})
		default:
			return nil, fmt.Errorf("%w: RUP command 0x%02x", ErrInvalidPatch, cmd)
		}
	}
	return nil, fmt.Errorf("%w: RUP end command missing", ErrInvalidPatch)
}

func createRUP(original, modified []byte, description string) *RUPPatch {
	p := &RUPPatch{Date: time.Now().Format("20060102"), PatchDescription: description}
	f := rupFile{SourceSize: uint64(len(original)), TargetSize: uint64(len(modified)), SourceMD5: MD5(original), TargetMD5: MD5(modified)}
	a, b := original, modified
	if len(a) < len(b) {
		f.OverflowMode = 'A'
		f.Overflow = make([]byte, len(b)-len(a))
		for i, x := range b[len(a):] {
			f.Overflow[i] = x ^ 0xff
		}
		b = b[:len(a)]
	} else if len(a) > len(b) {
		f.OverflowMode = 'M'
		f.Overflow = make([]byte, len(a)-len(b))
		for i, x := range a[len(b):] {
			f.Overflow[i] = x ^ 0xff
		}
		a = a[:len(b)]
	}
	for pos := 0; pos < len(b); {
		if a[pos] == b[pos] {
			pos++
			continue
		}
		start := pos
		x := make([]byte, 0, 64)
		for pos < len(b) && a[pos] != b[pos] {
			x = append(x, a[pos]^b[pos])
			pos++
		}
		f.Records = append(f.Records, rupRecord{offset: uint64(start), xor: x})
	}
	p.Files = []rupFile{f}
	return p
}
