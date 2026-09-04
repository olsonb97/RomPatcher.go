package rompatcher

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
)

func crc32PatchRange(ctx context.Context, r io.ReaderAt, offset, size int64) (uint32, error) {
	h := crc32.NewIEEE()
	buf := make([]byte, checksumChunkSize)
	for done := int64(0); done < size; {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n := int64(len(buf))
		if size-done < n {
			n = size - done
		}
		if err := readAtFull(r, buf[:n], offset+done); err != nil {
			return 0, err
		}
		_, _ = h.Write(buf[:n])
		done += n
	}
	return h.Sum32(), nil
}

func readPatchFooter(patch io.ReaderAt, patchSize int64) ([3]uint32, error) {
	var result [3]uint32
	var footer [12]byte
	if patchSize < int64(len(footer)) {
		return result, ErrUnexpectedEnd
	}
	if err := readAtFull(patch, footer[:], patchSize-int64(len(footer))); err != nil {
		return result, err
	}
	for i := range result {
		result[i] = binary.LittleEndian.Uint32(footer[i*4 : i*4+4])
	}
	return result, nil
}
