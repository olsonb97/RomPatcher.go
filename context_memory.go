package rompatcher

import (
	"context"
	"hash"
	"hash/crc32"
	"slices"
)

// Appends, copies, and scans memory in bounded chunks so cancellation does not require
// an extra pass over the data.
func appendContext[T ~[]byte | ~string](ctx context.Context, dst []byte, src T) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(src) > int(^uint(0)>>1)-len(dst) {
		return nil, ErrOutputTooLarge
	}
	if ctx.Done() == nil {
		return append(dst, src...), nil
	}
	start := len(dst)
	dst = slices.Grow(dst, len(src))[:start+len(src)]
	err := copyBytesContext(ctx, dst[start:], src)
	return dst, err
}

func copyBytesContext[T ~[]byte | ~string](ctx context.Context, dst []byte, src T) error {
	for len(src) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(src), fileChunkSize)
		copy(dst[:n], src[:n])
		dst, src = dst[n:], src[n:]
	}
	return ctx.Err()
}

func hashBytesContext(ctx context.Context, h hash.Hash, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(data), checksumChunkSize)
		_, _ = h.Write(data[:n])
		data = data[n:]
	}
	return ctx.Err()
}

func crc32BytesContext(ctx context.Context, data []byte) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if ctx.Done() == nil {
		return CRC32(data), nil
	}
	var sum uint32
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n := min(len(data), checksumChunkSize)
		sum = crc32.Update(sum, crc32.IEEETable, data[:n])
		data = data[n:]
	}
	return sum, ctx.Err()
}

type contextMarshaler interface {
	marshalBinaryContext(context.Context) ([]byte, error)
}

func marshalPatchContext(ctx context.Context, p Patch) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p, ok := p.(contextMarshaler); ok {
		return p.marshalBinaryContext(ctx)
	}
	// External Patch implementations own their serialization. Check both
	// boundaries; the Patch interface has no cancellation parameter.
	data, err := p.MarshalBinary()
	if canceled := ctx.Err(); canceled != nil {
		return nil, canceled
	}
	return data, err
}
