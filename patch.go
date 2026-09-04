package rompatcher

import (
	"bytes"
	"context"
	"fmt"
	"strings"
)

// Format identifies a supported patch encoding.
type Format string

func normalizeFormat(format Format) Format {
	return Format(strings.ToLower(strings.TrimSpace(string(format))))
}

const (
	// FormatIPS identifies classic IPS patches.
	FormatIPS Format = "ips"
	// FormatIPS32 identifies 32-bit IPS patches.
	FormatIPS32 Format = "ips32"
	// FormatEBP identifies EarthBound Patch format files.
	FormatEBP Format = "ebp"
	// FormatUPS identifies UPS patches.
	FormatUPS Format = "ups"
	// FormatAPSN64 identifies APS patches for Nintendo 64 images.
	FormatAPSN64 Format = "aps"
	// FormatAPSGBA identifies APS patches for Game Boy Advance images.
	FormatAPSGBA Format = "aps-gba"
	// FormatBPS identifies BPS patches.
	FormatBPS Format = "bps"
	// FormatRUP identifies NINJA2 RUP patches.
	FormatRUP Format = "rup"
	// FormatPPF identifies PPF patches.
	FormatPPF Format = "ppf"
	// FormatBDF identifies BSDIFF40 patches.
	FormatBDF Format = "bdf"
	// FormatPMSR identifies Star Rod PMSR mod patches.
	FormatPMSR Format = "mod"
	// FormatVCDIFF identifies VCDIFF/xdelta patches.
	FormatVCDIFF Format = "vcdiff"
)

// ApplyDirection selects an endpoint for reversible patch formats. Automatic
// direction detection remains the default.
type ApplyDirection string

const (
	// ApplyDirectionAuto selects the endpoint from source size and checksum.
	ApplyDirectionAuto ApplyDirection = ""
	// ApplyDirectionForward applies the patch from its source to its target.
	ApplyDirectionForward ApplyDirection = "forward"
	// ApplyDirectionReverse applies a reversible patch from target to source.
	ApplyDirectionReverse ApplyDirection = "reverse"
)

// ParseApplyDirection parses auto, forward, or reverse application direction.
func ParseApplyDirection(value string) (ApplyDirection, error) {
	direction := ApplyDirection(strings.ToLower(strings.TrimSpace(value)))
	switch direction {
	case "auto":
		return ApplyDirectionAuto, nil
	case ApplyDirectionAuto, ApplyDirectionForward, ApplyDirectionReverse:
		return direction, nil
	default:
		return "", fmt.Errorf("invalid apply direction %q: use auto, forward, or reverse", value)
	}
}

// ValidationInfo describes checksums accepted as source validation.
type ValidationInfo struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

// Patch is a parsed patch that can be inspected, applied, or serialized.
type Patch interface {
	Format() Format
	Apply(source []byte, options ApplyOptions) ([]byte, error)
	ValidateSource(source []byte) bool
	ValidationInfo() *ValidationInfo
	Description() string
	MarshalBinary() ([]byte, error)
}

// ApplyOptions controls validation, ROM transforms, limits, and progress.
type ApplyOptions struct {
	// Validate enables source and generated-output checks supported by the format.
	Validate bool
	// Direction optionally selects forward or reverse application. Auto is the
	// default and uses endpoint checksums, then unique endpoint sizes when
	// validation is disabled. Reverse is supported by UPS and RUP.
	Direction ApplyDirection
	// RemoveHeader temporarily removes a recognized copier or container header.
	RemoveHeader bool
	// AddHeader temporarily prepends header-sized compatibility data. Generated
	// bytes are intended for patch offsets and may not form complete container
	// metadata; they are removed from the finished output.
	AddHeader bool
	// FixChecksum repairs a recognized internal ROM checksum after patching.
	FixChecksum bool
	// SourceName supplies the filename extension used for ROM-specific handling.
	SourceName string
	// Context cancels long-running patch operations. Nil means context.Background.
	Context context.Context
	// Progress receives coarse progress updates. Callbacks must return quickly;
	// they run synchronously with patching.
	Progress func(Progress)
	// MaxOutputSize caps allocations from untrusted patches. Zero chooses a
	// source-relative default (64 MiB plus twice the source size).
	MaxOutputSize uint64
}

// Progress describes a synchronous operation progress update.
type Progress struct {
	Phase     string `json:"phase"`
	Format    Format `json:"format,omitempty"`
	Completed int64  `json:"completed"`
	Total     int64  `json:"total,omitempty"`
}

func contextOf(opts ApplyOptions) context.Context {
	if opts.Context != nil {
		return opts.Context
	}
	return context.Background()
}

func checkCanceled(opts ApplyOptions) error {
	select {
	case <-contextOf(opts).Done():
		return contextOf(opts).Err()
	default:
		return nil
	}
}

func reportProgress(opts ApplyOptions, p Progress) error {
	if err := checkCanceled(opts); err != nil {
		return err
	}
	if opts.Progress != nil {
		opts.Progress(p)
	}
	return checkCanceled(opts)
}

func withoutProgressPhase(opts ApplyOptions, phase string) ApplyOptions {
	callback := opts.Progress
	if callback != nil {
		opts.Progress = func(progress Progress) {
			if progress.Phase != phase {
				callback(progress)
			}
		}
	}
	return opts
}

// CreateOptions controls patch metadata, limits, and progress during creation.
type CreateOptions struct {
	// Metadata supplies EBP metadata fields.
	Metadata map[string]string
	// Description supplies the description or metadata field where supported.
	Description string
	// SourceName supplies the filename extension used for format metadata.
	SourceName string
	// BPSDelta forces the memory-intensive delta matcher. Create uses it by
	// default for inputs up to 4 MiB; CreateReaderAt uses it only when requested.
	BPSDelta bool
	// Context cancels creation. Nil means context.Background.
	Context context.Context
	// Progress receives coarse creation updates.
	Progress func(Progress)
	// MaxPatchSize limits patch output. Zero chooses a default of
	// 64 MiB plus twice the larger input size.
	MaxPatchSize uint64
}

// Parse detects and decodes a patch held in memory.
func Parse(data []byte) (Patch, error) {
	switch {
	case len(data) >= 5 && string(data[:5]) == "PATCH":
		return parseIPS(data)
	case len(data) >= 5 && string(data[:5]) == "IPS32":
		return parseIPS32(data)
	case len(data) >= 4 && string(data[:4]) == "UPS1":
		return parseUPS(data)
	case len(data) >= 5 && string(data[:5]) == "APS10":
		return parseAPSN64(data)
	case len(data) >= 4 && string(data[:4]) == "APS1":
		return parseAPSGBA(data)
	case len(data) >= 4 && string(data[:4]) == "BPS1":
		return parseBPS(data)
	case len(data) >= 6 && string(data[:6]) == "NINJA2":
		return parseRUP(data)
	case len(data) >= 3 && string(data[:3]) == "PPF":
		return parsePPF(data)
	case len(data) >= 8 && string(data[:8]) == "BSDIFF40":
		return parseBDF(data)
	case len(data) >= 4 && string(data[:4]) == "PMSR":
		return parsePMSR(data)
	case len(data) >= 3 && data[0] == 0xd6 && data[1] == 0xc3 && data[2] == 0xc4:
		return parseVCDIFF(data)
	default:
		return nil, ErrUnknownFormat
	}
}

// Create builds an in-memory patch from original and modified data.
func Create(original, modified []byte, format Format, opts *CreateOptions) (Patch, error) {
	format = normalizeFormat(format)
	if format == FormatBPS {
		local := CreateOptions{}
		if opts != nil {
			local = *opts
		}
		delta := len(original) <= 4<<20 && len(modified) <= 4<<20
		if local.BPSDelta {
			delta = true
		}
		if delta {
			p, err := createBPSDeltaPatch(original, modified, local)
			if err != nil {
				return nil, err
			}
			encoded, err := p.MarshalBinary()
			if err != nil {
				return nil, err
			}
			limit := patchSizeLimit(int64(len(original)), int64(len(modified)), local)
			if uint64(len(encoded)) > limit {
				return nil, fmt.Errorf("%w: patch exceeds %d bytes", ErrOutputTooLarge, limit)
			}
			if err := reportCreatePhase(local, "complete", format, int64(len(encoded)), int64(len(encoded))); err != nil {
				return nil, err
			}
			return parseBPS(encoded)
		}
	}
	var encoded bytes.Buffer
	ctx := context.Background()
	if opts != nil && opts.Context != nil {
		ctx = opts.Context
	}
	if _, err := CreateReaderAt(ctx, bytes.NewReader(original), int64(len(original)), bytes.NewReader(modified), int64(len(modified)), &encoded, format, opts); err != nil {
		return nil, err
	}
	return Parse(encoded.Bytes())
}

// Apply parses patchData and applies it to source in memory.
func Apply(source, patchData []byte, options ApplyOptions) ([]byte, error) {
	return applyEncodedWithOptions(source, patchData, options)
}

func checkOutputSize(size uint64, sourceSize int, options ApplyOptions) error {
	return checkOutputSize64(size, uint64(sourceSize), options)
}

func checkOutputSize64(size, sourceSize uint64, options ApplyOptions) error {
	limit := outputSizeLimit(sourceSize, options)
	if size > limit {
		return fmt.Errorf("%w: %d bytes (limit %d)", ErrOutputTooLarge, size, limit)
	}
	return nil
}

func outputSizeLimit(sourceSize uint64, options ApplyOptions) uint64 {
	limit := options.MaxOutputSize
	if limit == 0 {
		limit = 64 << 20
		if sourceSize <= (^uint64(0)-limit)/2 {
			limit += sourceSize * 2
		} else {
			limit = ^uint64(0)
		}
	}
	return limit
}

type basePatch struct{}

// ValidateSource accepts any source when a format has no source signature.
func (basePatch) ValidateSource([]byte) bool { return true }

// ValidationInfo returns nil when a format has no source signature.
func (basePatch) ValidationInfo() *ValidationInfo { return nil }

// Description returns an empty string when a format has no description field.
func (basePatch) Description() string { return "" }
