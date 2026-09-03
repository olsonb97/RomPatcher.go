package rompatcher

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const ipsMaxSize = 0x1000000

type ipsRecord struct {
	offset int
	data   []byte
	rleLen int
	rle    byte
}

// IPSPatch is a parsed IPS or EBP patch. Use InspectParsed for record details.
type IPSPatch struct {
	basePatch
	records     []ipsRecord
	Truncate    int
	HasTruncate bool
	Metadata    map[string]string
}

// Format implements Patch.
func (p *IPSPatch) Format() Format {
	if p.Metadata != nil {
		return FormatEBP
	}
	return FormatIPS
}

// Description implements Patch.
func (p *IPSPatch) Description() string {
	if p.Metadata == nil {
		return ""
	}
	keys := make([]string, 0, len(p.Metadata))
	for k := range p.Metadata {
		if k != "" && strings.ToLower(k) != "patcher" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		_, size := utf8.DecodeRuneInString(k)
		lines = append(lines, strings.ToUpper(k[:size])+k[size:]+": "+p.Metadata[k])
	}
	return strings.Join(lines, "\n")
}

// Apply implements Patch.
func (p *IPSPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	return ApplyParsedWithOptions(source, p, options)
}

// MarshalBinary implements Patch.
func (p *IPSPatch) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, 8+len(p.records)*8)
	out = append(out, "PATCH"...)
	for _, r := range p.records {
		if r.offset < 0 || r.offset >= ipsMaxSize || r.offset == 0x454f46 {
			return nil, fmt.Errorf("%w: IPS offset 0x%x", ErrInvalidPatch, r.offset)
		}
		out = appendU24BE(out, uint32(r.offset))
		if r.rleLen > 0 {
			if r.rleLen > 0xffff {
				return nil, fmt.Errorf("%w: IPS RLE record too long", ErrInvalidPatch)
			}
			out = appendU16BE(out, 0)
			out = appendU16BE(out, uint16(r.rleLen))
			out = append(out, r.rle)
		} else {
			if len(r.data) == 0 || len(r.data) > 0xffff {
				return nil, fmt.Errorf("%w: IPS record length", ErrInvalidPatch)
			}
			out = appendU16BE(out, uint16(len(r.data)))
			out = append(out, r.data...)
		}
	}
	out = append(out, "EOF"...)
	if p.HasTruncate && p.Metadata == nil {
		if p.Truncate < 0 || p.Truncate >= ipsMaxSize {
			return nil, fmt.Errorf("%w: IPS truncate size", ErrInvalidPatch)
		}
		out = appendU24BE(out, uint32(p.Truncate))
	} else if p.Metadata != nil {
		b, err := json.Marshal(p.Metadata)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func parseIPS(data []byte) (*IPSPatch, error) {
	d := newDecoder(data)
	if err := d.seek(5); err != nil {
		return nil, err
	}
	p := &IPSPatch{}
	for !d.eof() {
		o, err := d.u24be()
		if err != nil {
			return nil, fmt.Errorf("%w: IPS record offset", ErrInvalidPatch)
		}
		if o == 0x454f46 {
			switch d.remaining() {
			case 0:
				return p, nil
			case 3:
				n, err := d.u24be()
				if err != nil {
					return nil, err
				}
				p.Truncate = int(n)
				p.HasTruncate = true
				return p, nil
			default:
				if d.remaining() > 0 && d.b[d.off] == '{' {
					if err := json.Unmarshal(d.b[d.off:], &p.Metadata); err != nil {
						return nil, fmt.Errorf("%w: EBP metadata: %v", ErrInvalidPatch, err)
					}
					if p.Metadata == nil {
						return nil, fmt.Errorf("%w: EBP metadata must be an object", ErrInvalidPatch)
					}
					return p, nil
				}
				return nil, fmt.Errorf("%w: unsupported data after IPS EOF", ErrInvalidPatch)
			}
		}
		n, err := d.u16be()
		if err != nil {
			return nil, fmt.Errorf("%w: IPS record size", ErrInvalidPatch)
		}
		r := ipsRecord{offset: int(o)}
		if n == 0 {
			l, err := d.u16be()
			if err != nil {
				return nil, err
			}
			b, err := d.u8()
			if err != nil {
				return nil, err
			}
			if l == 0 {
				return nil, fmt.Errorf("%w: zero-length IPS RLE record", ErrInvalidPatch)
			}
			r.rleLen, r.rle = int(l), b
		} else {
			b, err := d.bytes(int(n))
			if err != nil {
				return nil, err
			}
			r.data = append([]byte(nil), b...)
		}
		p.records = append(p.records, r)
	}
	return nil, fmt.Errorf("%w: IPS EOF marker missing", ErrInvalidPatch)
}
