package rompatcher

import (
	"compress/bzip2"
	"context"
	"fmt"
	"io"
)

func applyBDFStream(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	if patchSize < 32 {
		return 0, fmt.Errorf("%w: BSDIFF header", ErrInvalidPatch)
	}
	d := newReaderDecoder(ctx, patch, patchSize)
	_ = d.seek(8)
	controlRaw, err := d.u64le()
	if err != nil {
		return 0, err
	}
	diffRaw, err := d.u64le()
	if err != nil {
		return 0, err
	}
	targetRaw, err := d.u64le()
	if err != nil {
		return 0, err
	}
	controlSize, diffSize, targetSize := bsdiffInt(controlRaw), bsdiffInt(diffRaw), bsdiffInt(targetRaw)
	if controlSize < 0 || diffSize < 0 || targetSize < 0 || controlSize > patchSize-32 || diffSize > patchSize-32-controlSize {
		return 0, fmt.Errorf("%w: BSDIFF sizes", ErrInvalidPatch)
	}
	if err := checkOutputSize64(uint64(targetSize), uint64(sourceSize), opts); err != nil {
		return 0, err
	}
	control := bzip2.NewReader(sectionReader(patch, 32, controlSize))
	diff := bzip2.NewReader(sectionReader(patch, 32+controlSize, diffSize))
	extraSize := patchSize - 32 - controlSize - diffSize
	extra := bzip2.NewReader(sectionReader(patch, 32+controlSize+diffSize, extraSize))
	oldPosition, newPosition, records := int64(0), int64(0), int64(0)
	diffBuf, oldBuf := make([]byte, fileChunkSize), make([]byte, fileChunkSize)
	for newPosition < targetSize {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		diffLength, err := readBSDiffInt(control)
		if err != nil {
			return 0, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		extraLength, err := readBSDiffInt(control)
		if err != nil {
			return 0, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		skip, err := readBSDiffInt(control)
		if err != nil {
			return 0, fmt.Errorf("%w: BSDIFF control tuple: %v", ErrInvalidPatch, err)
		}
		if diffLength < 0 || extraLength < 0 || diffLength == 0 && extraLength == 0 || diffLength > targetSize-newPosition || extraLength > targetSize-newPosition-diffLength {
			return 0, fmt.Errorf("%w: BSDIFF control values", ErrInvalidPatch)
		}
		for done := int64(0); done < diffLength; {
			n := int64(len(diffBuf))
			if diffLength-done < n {
				n = diffLength - done
			}
			buf := diffBuf[:n]
			if _, err := io.ReadFull(diff, buf); err != nil {
				return 0, fmt.Errorf("%w: BSDIFF diff: %v", ErrInvalidPatch, err)
			}
			diffPosition, ok := addInt64(oldPosition, done)
			if !ok {
				return 0, ErrInvalidPatch
			}
			within, sourceOffset, count := sourceSpan(diffPosition, n, sourceSize)
			if count > 0 {
				old := oldBuf[:count]
				if err := readAtFull(source, old, sourceOffset); err != nil {
					return 0, err
				}
				for i, value := range old {
					buf[int(within)+i] += value
				}
			}
			if err := writeAtFull(output, buf, newPosition+done); err != nil {
				return 0, err
			}
			done += n
		}
		newPosition += diffLength
		var ok bool
		oldPosition, ok = addInt64(oldPosition, diffLength)
		if !ok {
			return 0, ErrInvalidPatch
		}
		for done := int64(0); done < extraLength; {
			n := int64(len(diffBuf))
			if extraLength-done < n {
				n = extraLength - done
			}
			buf := diffBuf[:n]
			if _, err := io.ReadFull(extra, buf); err != nil {
				return 0, fmt.Errorf("%w: BSDIFF extra: %v", ErrInvalidPatch, err)
			}
			if err := writeAtFull(output, buf, newPosition+done); err != nil {
				return 0, err
			}
			done += n
		}
		newPosition += extraLength
		oldPosition, ok = addInt64(oldPosition, skip)
		if !ok {
			return 0, ErrInvalidPatch
		}
		records++
		if err := reportProgress(opts, Progress{Phase: "apply", Format: FormatBDF, Completed: records}); err != nil {
			return 0, err
		}
	}
	if err := requireCompressedEOF(control, "control"); err != nil {
		return 0, err
	}
	if err := requireCompressedEOF(diff, "diff"); err != nil {
		return 0, err
	}
	if err := requireCompressedEOF(extra, "extra"); err != nil {
		return 0, err
	}
	return targetSize, nil
}
