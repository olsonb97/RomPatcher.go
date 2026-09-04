package rompatcher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
)

func detectFormatReaderAt(patch io.ReaderAt, patchSize int64) (Format, error) {
	if patchSize < 3 {
		return "", ErrUnknownFormat
	}
	length := patchSize
	if length > 8 {
		length = 8
	}
	var storage [8]byte
	magic := storage[:int(length)]
	if err := readAtFull(patch, magic, 0); err != nil {
		return "", err
	}
	switch {
	case bytes.HasPrefix(magic, []byte("PATCH")):
		return FormatIPS, nil
	case bytes.HasPrefix(magic, []byte("IPS32")):
		return FormatIPS32, nil
	case bytes.HasPrefix(magic, []byte("UPS1")):
		return FormatUPS, nil
	case bytes.HasPrefix(magic, []byte("BPS1")):
		return FormatBPS, nil
	case bytes.HasPrefix(magic, []byte("APS10")):
		return FormatAPSN64, nil
	case bytes.HasPrefix(magic, []byte("APS1")):
		return FormatAPSGBA, nil
	case bytes.HasPrefix(magic, []byte("NINJA2")):
		return FormatRUP, nil
	case bytes.HasPrefix(magic, []byte("PPF")):
		return FormatPPF, nil
	case bytes.HasPrefix(magic, []byte("BSDIFF40")):
		return FormatBDF, nil
	case bytes.HasPrefix(magic, []byte("PMSR")):
		return FormatPMSR, nil
	case len(magic) >= 3 && magic[0] == 0xd6 && magic[1] == 0xc3 && magic[2] == 0xc4:
		return FormatVCDIFF, nil
	default:
		return "", ErrUnknownFormat
	}
}

func formatReaderAt(ctx context.Context, patch io.ReaderAt, patchSize int64) (Format, error) {
	format, err := detectFormatReaderAt(patch, patchSize)
	if err != nil || format != FormatIPS {
		return format, err
	}
	info, err := scanIPSStream(ctx, patch, patchSize, 0, false)
	return info.format, err
}

func applyPatchReaderAt(ctx context.Context, source io.ReaderAt, sourceSize int64, patch io.ReaderAt, patchSize int64, output io.WriterAt, opts ApplyOptions) (int64, error) {
	format, err := detectFormatReaderAt(patch, patchSize)
	if err != nil {
		return 0, err
	}
	direction, err := ParseApplyDirection(string(opts.Direction))
	if err != nil {
		return 0, err
	}
	if direction != ApplyDirectionAuto && format != FormatUPS && format != FormatRUP {
		return 0, fmt.Errorf("%w: %s patches do not support explicit direction", ErrUnsupported, strings.ToUpper(string(format)))
	}
	opts.Direction = direction
	readOutput, outputReadable := output.(io.ReaderAt)
	switch format {
	case FormatIPS:
		return applyIPSStream(ctx, source, sourceSize, patch, patchSize, output, false, opts)
	case FormatIPS32:
		return applyIPSStream(ctx, source, sourceSize, patch, patchSize, output, true, opts)
	case FormatUPS:
		if opts.Validate && !outputReadable {
			return 0, outputReaderAtError(FormatUPS)
		}
		return applyUPSStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	case FormatBPS:
		if !outputReadable {
			return 0, outputReaderAtError(FormatBPS)
		}
		return applyBPSStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	case FormatAPSN64:
		return applyAPSN64Stream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatAPSGBA:
		return applyAPSGBAStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatRUP:
		if opts.Validate && !outputReadable {
			return 0, outputReaderAtError(FormatRUP)
		}
		return applyRUPStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	case FormatPPF:
		return applyPPFStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatBDF:
		return applyBDFStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatPMSR:
		return applyPMSRStream(ctx, source, sourceSize, patch, patchSize, output, opts)
	case FormatVCDIFF:
		if !outputReadable {
			return 0, outputReaderAtError(FormatVCDIFF)
		}
		return applyVCDIFFStream(ctx, source, sourceSize, patch, patchSize, readOutput, output, opts)
	default:
		return 0, ErrUnknownFormat
	}
}

func outputReaderAtError(format Format) error {
	return fmt.Errorf("%w: %s output must implement io.ReaderAt", ErrUnsupported, format)
}

func writePatchRange(ctx context.Context, patch io.ReaderAt, patchOffset int64, output io.WriterAt, outputOffset, length int64, buf []byte) error {
	for done := int64(0); done < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int64(len(buf))
		if length-done < n {
			n = length - done
		}
		if err := readAtFull(patch, buf[:n], patchOffset+done); err != nil {
			return err
		}
		if err := writeAtFull(output, buf[:n], outputOffset+done); err != nil {
			return err
		}
		done += n
	}
	return nil
}

func fillValueAt(ctx context.Context, output io.WriterAt, offset, length int64, value byte, buf []byte) error {
	if len(buf) == 0 {
		return ErrInvalidPatch
	}
	fillBytes(buf, value)
	for done := int64(0); done < length; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int64(len(buf))
		if length-done < n {
			n = length - done
		}
		if err := writeAtFull(output, buf[:n], offset+done); err != nil {
			return err
		}
		done += n
	}
	return nil
}
