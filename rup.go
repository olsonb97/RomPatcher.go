package rompatcher

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
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
	records                []rupRecord
}

// RUPPatch is a parsed reversible NINJA2 RUP patch.
type RUPPatch struct {
	TextEncoding                                                         byte
	Author, Version, Title, Genre, Language, Date, Web, PatchDescription string
	files                                                                []rupFile
}

// Format implements Patch.
func (*RUPPatch) Format() Format { return FormatRUP }

// Description implements Patch.
func (p *RUPPatch) Description() string { return p.PatchDescription }

// ValidateSource implements Patch and accepts either reversible endpoint.
func (p *RUPPatch) ValidateSource(source []byte) bool {
	valid, _ := p.validateSourceContext(context.Background(), source, ApplyDirectionAuto)
	return valid
}

func (p *RUPPatch) validateSourceContext(ctx context.Context, source []byte, direction ApplyDirection) (bool, error) {
	h := md5.New()
	if err := hashBytesContext(ctx, h, source); err != nil {
		return false, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	size := uint64(len(source))
	for _, f := range p.files {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		forward, reverse := matchReversibleEndpoints(size, f.SourceSize, f.TargetSize, sum, f.SourceMD5, f.TargetMD5)
		if acceptsEndpoint(direction, forward, reverse) {
			return true, nil
		}
	}
	return false, nil
}

// ValidationInfo implements Patch.
func (p *RUPPatch) ValidationInfo() *ValidationInfo {
	v := make([]string, 0, len(p.files)*2)
	for _, f := range p.files {
		v = append(v, f.SourceMD5, f.TargetMD5)
	}
	return &ValidationInfo{Type: "MD5", Values: v}
}

func validateRUPFile(ctx context.Context, f *rupFile) error {
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
	for _, r := range f.records {
		if err := ctx.Err(); err != nil {
			return err
		}
		length := uint64(len(r.xor))
		if length == 0 || length > maximum || r.offset > maximum-length {
			return fmt.Errorf("%w: RUP record outside file range", ErrInvalidPatch)
		}
	}
	return nil
}

// Apply implements Patch and automatically selects the reversible direction.
func (p *RUPPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
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

// MarshalBinary implements Patch.
func (p *RUPPatch) MarshalBinary() ([]byte, error) {
	return p.marshalBinaryContext(context.Background())
}

func (p *RUPPatch) marshalBinaryContext(ctx context.Context) ([]byte, error) {
	var err error
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p.files) == 0 {
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
	out = append(out, fixedString(strings.ReplaceAll(p.PatchDescription[:min(len(p.PatchDescription), 1074)], "\n", "\\n"), 1074)...)
	if len(out) != 0x800 {
		return nil, fmt.Errorf("%w: RUP header size", ErrInvalidPatch)
	}
	for _, f := range p.files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e := validateRUPFile(ctx, &f); e != nil {
			return nil, e
		}
		out = append(out, 1)
		out = appendRUPVLV(out, uint64(len(f.FileName)))
		out, err = appendContext(ctx, out, f.FileName)
		if err != nil {
			return nil, err
		}
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
			out, err = appendContext(ctx, out, f.Overflow)
			if err != nil {
				return nil, err
			}
		}
		for _, r := range f.records {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			out = append(out, 2)
			out = appendRUPVLV(out, r.offset)
			out = appendRUPVLV(out, uint64(len(r.xor)))
			out, err = appendContext(ctx, out, r.xor)
			if err != nil {
				return nil, err
			}
		}
	}
	out = append(out, 0)
	return out, ctx.Err()
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
				if e := validateRUPFile(context.Background(), current); e != nil {
					return nil, e
				}
				p.files = append(p.files, *current)
			}
			if !d.eof() {
				return nil, fmt.Errorf("%w: data after RUP end command", ErrInvalidPatch)
			}
			if len(p.files) == 0 {
				return nil, fmt.Errorf("%w: RUP has no files", ErrInvalidPatch)
			}
			return p, nil
		case 1:
			if current != nil {
				if e := validateRUPFile(context.Background(), current); e != nil {
					return nil, e
				}
				p.files = append(p.files, *current)
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
			current.records = append(current.records, rupRecord{offset: off, xor: append([]byte(nil), b...)})
		default:
			return nil, fmt.Errorf("%w: RUP command 0x%02x", ErrInvalidPatch, cmd)
		}
	}
	return nil, fmt.Errorf("%w: RUP end command missing", ErrInvalidPatch)
}
