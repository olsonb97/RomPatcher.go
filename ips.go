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

type IPSPatch struct {
	basePatch
	Records     []ipsRecord
	Truncate    int
	HasTruncate bool
	Metadata    map[string]string
}

func (p *IPSPatch) Format() Format {
	if p.Metadata != nil {
		return FormatEBP
	}
	return FormatIPS
}

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

func (p *IPSPatch) Apply(source []byte, options ApplyOptions) ([]byte, error) {
	size := len(source)
	if p.HasTruncate && p.Metadata == nil {
		size = p.Truncate
	} else {
		for _, r := range p.Records {
			n := len(r.data)
			if r.rleLen > 0 {
				n = r.rleLen
			}
			if r.offset < 0 || n < 0 || r.offset > int(^uint(0)>>1)-n {
				return nil, ErrInvalidPatch
			}
			if r.offset+n > size {
				size = r.offset + n
			}
		}
	}
	if err := validateIPSRecords(p.Records, int64(size)); err != nil {
		return nil, err
	}
	if err := checkOutputSize(uint64(size), len(source), options); err != nil {
		return nil, err
	}
	out, err := resizedCopy(source, size)
	if err != nil {
		return nil, err
	}
	for i, r := range p.Records {
		if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(i), Total: int64(len(p.Records))}); err != nil {
			return nil, err
		}
		if r.rleLen > 0 {
			fillBytes(out[r.offset:r.offset+r.rleLen], r.rle)
		} else {
			copy(out[r.offset:], r.data)
		}
	}
	if err := reportProgress(options, Progress{Phase: "apply", Format: p.Format(), Completed: int64(len(p.Records)), Total: int64(len(p.Records))}); err != nil {
		return nil, err
	}
	return out, nil
}

func validateIPSRecords(records []ipsRecord, targetSize int64) error {
	if targetSize < 0 {
		return ErrInvalidPatch
	}
	for _, r := range records {
		length := len(r.data)
		if r.rleLen > 0 {
			length = r.rleLen
		}
		if r.offset < 0 || length <= 0 || int64(r.offset) > targetSize-int64(length) {
			return fmt.Errorf("%w: IPS record outside output", ErrInvalidPatch)
		}
	}
	return nil
}

func (p *IPSPatch) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, 8+len(p.Records)*8)
	out = append(out, "PATCH"...)
	for _, r := range p.Records {
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
		p.Records = append(p.Records, r)
	}
	return nil, fmt.Errorf("%w: IPS EOF marker missing", ErrInvalidPatch)
}

func createIPS(original, modified []byte, metadata map[string]string) (*IPSPatch, error) {
	if metadata != nil && len(modified) < len(original) {
		return nil, fmt.Errorf("%w: EBP cannot represent a smaller output", ErrUnsupported)
	}
	p := &IPSPatch{}
	if metadata != nil {
		p.Metadata = map[string]string{"patcher": "EBPatcher"}
		if len(metadata) == 0 {
			p.Metadata["Author"], p.Metadata["Title"], p.Metadata["Description"] = "Unknown", "Untitled", "No description"
		} else {
			for k, v := range metadata {
				p.Metadata[k] = v
			}
		}
	} else if len(modified) < len(original) {
		p.Truncate = len(modified)
		p.HasTruncate = true
	}

	var previous *ipsRecord
	for pos := 0; pos < len(modified); {
		ob := byte(0)
		if pos < len(original) {
			ob = original[pos]
		}
		if ob == modified[pos] {
			pos++
			continue
		}
		start := pos
		buf := make([]byte, 0, 256)
		rle := true
		first := modified[pos]
		if start == 0x454f46 {
			start--
			first = modified[start]
			buf = append(buf, first)
		}
		for pos < len(modified) && len(buf) < 0xffff {
			ob = 0
			if pos < len(original) {
				ob = original[pos]
			}
			if ob == modified[pos] {
				break
			}
			b := modified[pos]
			buf = append(buf, b)
			if b != first {
				rle = false
			}
			pos++
		}
		distance := int(^uint(0) >> 1)
		if previous != nil {
			distance = start - (previous.offset + len(previous.data))
		}
		if previous != nil && previous.rleLen == 0 && distance >= 0 && distance < 6 && len(previous.data)+distance+len(buf) < 0xffff && !(rle && len(buf) > 6) {
			previous.data = append(previous.data, modified[previous.offset+len(previous.data):start]...)
			previous.data = append(previous.data, buf...)
			continue
		}
		if start >= ipsMaxSize {
			return nil, fmt.Errorf("files are too big for %s format", p.Format())
		}
		r := ipsRecord{offset: start}
		if rle && len(buf) > 2 {
			r.rleLen, r.rle = len(buf), first
		} else {
			r.data = append([]byte(nil), buf...)
		}
		p.Records = append(p.Records, r)
		previous = &p.Records[len(p.Records)-1]
	}
	if len(modified) > len(original) {
		last := 0
		if len(p.Records) > 0 {
			r := p.Records[len(p.Records)-1]
			last = r.offset + len(r.data)
			if r.rleLen > 0 {
				last = r.offset + r.rleLen
			}
		}
		if last < len(modified) {
			p.Records = append(p.Records, ipsRecord{offset: len(modified) - 1, data: []byte{0}})
		}
	}
	return p, nil
}
