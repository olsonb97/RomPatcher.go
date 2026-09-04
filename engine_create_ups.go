package rompatcher

import (
	"hash/crc32"
	"io"
)

func createUPSReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	header := append([]byte("UPS1"), appendBPSVLV(nil, uint64(originalSize))...)
	header = append(header, appendBPSVLV(nil, uint64(modifiedSize))...)
	if err := w.write(header); err != nil {
		return err
	}
	oldChunk, newChunk := make([]byte, fileChunkSize), make([]byte, fileChunkSize)
	sourceHash, targetHash := crc32.NewIEEE(), crc32.NewIEEE()
	scanSize := modifiedSize
	if originalSize > scanSize {
		scanSize = originalSize
	}
	previousSeek, runStart, runLength := int64(1), int64(-1), int64(0)
	for offset := int64(0); offset < scanSize; {
		n := int64(fileChunkSize)
		if scanSize-offset < n {
			n = scanSize - offset
		}
		oldData, newData := oldChunk[:n], newChunk[:n]
		if err := readRange(original, originalSize, offset, oldData); err != nil {
			return err
		}
		if err := readRange(modified, modifiedSize, offset, newData); err != nil {
			return err
		}
		if sourceLength := min64(n, max(int64(0), originalSize-offset)); sourceLength > 0 {
			_, _ = sourceHash.Write(oldData[:sourceLength])
		}
		if targetLength := min64(n, max(int64(0), modifiedSize-offset)); targetLength > 0 {
			_, _ = targetHash.Write(newData[:targetLength])
		}
		segmentStart := -1
		flushSegment := func(end int) error {
			if segmentStart < 0 {
				return nil
			}
			for i := segmentStart; i < end; i++ {
				oldData[i] ^= newData[i]
			}
			err := w.write(oldData[segmentStart:end])
			segmentStart = -1
			return err
		}
		for i := range newData {
			position := offset + int64(i)
			if oldData[i] != newData[i] {
				if runStart < 0 {
					runStart = position
					currentSeek := runStart + 1
					if currentSeek < previousSeek {
						return ErrInvalidPatch
					}
					if err := w.write(appendBPSVLV(nil, uint64(currentSeek-previousSeek))); err != nil {
						return err
					}
				}
				if segmentStart < 0 {
					segmentStart = i
				}
				runLength++
				continue
			}
			if err := flushSegment(i); err != nil {
				return err
			}
			if runStart >= 0 {
				if err := w.write([]byte{0}); err != nil {
					return err
				}
				previousSeek = runStart + 1 + runLength + 1
				runStart, runLength = -1, 0
			}
		}
		if err := flushSegment(len(newData)); err != nil {
			return err
		}
		offset += n
		if err := reportCreate(opts, FormatUPS, offset, scanSize); err != nil {
			return err
		}
	}
	if runStart >= 0 {
		if err := w.write([]byte{0}); err != nil {
			return err
		}
	}
	footer := appendU32LE(nil, sourceHash.Sum32())
	footer = appendU32LE(footer, targetHash.Sum32())
	if err := w.write(footer); err != nil {
		return err
	}
	return w.write(appendU32LE(nil, w.hash.Sum32()))
}
