package rompatcher

import "fmt"

func readBPSVLV(d *decoder) (uint64, error) {
	var value, shift uint64 = 0, 1
	for i := 0; i < 10; i++ {
		x, err := d.u8()
		if err != nil {
			return 0, err
		}
		add := uint64(x&0x7f) * shift
		if value > ^uint64(0)-add {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		value += add
		if x&0x80 != 0 {
			return value, nil
		}
		if shift > ^uint64(0)>>7 {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		shift <<= 7
		if value > ^uint64(0)-shift {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		value += shift
	}
	return 0, fmt.Errorf("%w: variable integer too long", ErrInvalidPatch)
}

func appendBPSVLV(dst []byte, value uint64) []byte {
	for {
		x := byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			return append(dst, 0x80|x)
		}
		dst = append(dst, x)
		value--
	}
}

// VCDIFF uses a conventional big-endian base-128 integer.
func readBE7(d *decoder) (uint64, error) {
	var value uint64
	for i := 0; i < 10; i++ {
		x, err := d.u8()
		if err != nil {
			return 0, err
		}
		if value > ^uint64(0)>>7 {
			return 0, fmt.Errorf("%w: variable integer overflow", ErrInvalidPatch)
		}
		value = value<<7 | uint64(x&0x7f)
		if x&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("%w: variable integer too long", ErrInvalidPatch)
}
