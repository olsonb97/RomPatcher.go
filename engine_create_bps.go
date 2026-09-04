package rompatcher

import (
	"hash/crc32"
	"io"
)

func createBPSReaderAt(original io.ReaderAt, originalSize int64, modified io.ReaderAt, modifiedSize int64, w *patchStreamWriter, opts CreateOptions) error {
	header := append([]byte("BPS1"), appendBPSVLV(nil, uint64(originalSize))...)
	header = append(header, appendBPSVLV(nil, uint64(modifiedSize))...)
	header = append(header, appendBPSVLV(nil, uint64(len(opts.Description)))...)
	header = append(header, opts.Description...)
	if err := w.write(header); err != nil {
		return err
	}
	oldChunk, newChunk := make([]byte, fileChunkSize), make([]byte, fileChunkSize)
	sourceHash, targetHash := crc32.NewIEEE(), crc32.NewIEEE()
	state := byte(0xff)
	runLength := 0
	targetRelative := int64(0)
	literals := make([]byte, 0, createRecordBuffer)
	flush := func() error {
		if state == 0xff || runLength == 0 {
			return nil
		}
		action := (uint64(runLength-1) << 2) | uint64(state)
		if err := w.write(appendBPSVLV(nil, action)); err != nil {
			return err
		}
		if state == bpsTargetRead {
			if err := w.write(literals); err != nil {
				return err
			}
		}
		runLength = 0
		literals = literals[:0]
		return nil
	}
	scanSize := originalSize
	if modifiedSize > scanSize {
		scanSize = modifiedSize
	}
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
		sourceLength := min64(n, max(int64(0), originalSize-offset))
		targetLength := min64(n, max(int64(0), modifiedSize-offset))
		if sourceLength > 0 {
			_, _ = sourceHash.Write(oldData[:sourceLength])
		}
		if targetLength > 0 {
			_, _ = targetHash.Write(newData[:targetLength])
		}
		for i := 0; i < int(targetLength); {
			b := newData[i]
			sourceEqual := offset+int64(i) < originalSize && oldData[i] == b
			if !sourceEqual && i+4 < int(targetLength) && newData[i+1] == b && newData[i+2] == b && newData[i+3] == b && newData[i+4] == b {
				rleLength := 5
				for i+rleLength < int(targetLength) && newData[i+rleLength] == b {
					rleLength++
				}
				firstState := byte(bpsTargetRead)
				if state != firstState || runLength == createRecordBuffer {
					if err := flush(); err != nil {
						return err
					}
					state = firstState
				}
				runLength++
				if firstState == bpsTargetRead {
					literals = append(literals, b)
				}
				if err := flush(); err != nil {
					return err
				}
				copyLength := rleLength - 1
				if err := w.write(appendBPSVLV(nil, uint64(copyLength-1)<<2|bpsTargetCopy)); err != nil {
					return err
				}
				runStart := offset + int64(i)
				if runStart < targetRelative {
					return ErrInvalidPatch
				}
				if err := w.write(appendBPSVLV(nil, uint64(runStart-targetRelative)<<1)); err != nil {
					return err
				}
				targetRelative = runStart + int64(rleLength) - 1
				i += rleLength
				continue
			}
			next := byte(bpsTargetRead)
			if sourceEqual {
				next = bpsSourceRead
			}
			if state != next || runLength == createRecordBuffer {
				if err := flush(); err != nil {
					return err
				}
				state = next
			}
			runLength++
			if next == bpsTargetRead {
				literals = append(literals, b)
			}
			i++
		}
		offset += n
		if err := reportCreate(opts, FormatBPS, offset, scanSize); err != nil {
			return err
		}
	}
	if err := flush(); err != nil {
		return err
	}
	footer := appendU32LE(nil, sourceHash.Sum32())
	footer = appendU32LE(footer, targetHash.Sum32())
	if err := w.write(footer); err != nil {
		return err
	}
	return w.write(appendU32LE(nil, w.hash.Sum32()))
}
