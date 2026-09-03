package rompatcher

import (
	"context"
	"fmt"
	"strings"
)

type Format string

const (
	FormatIPS    Format = "ips"
	FormatIPS32  Format = "ips32"
	FormatEBP    Format = "ebp"
	FormatUPS    Format = "ups"
	FormatAPSN64 Format = "aps"
	FormatAPSGBA Format = "aps-gba"
	FormatBPS    Format = "bps"
	FormatRUP    Format = "rup"
	FormatPPF    Format = "ppf"
	FormatBDF    Format = "bdf"
	FormatPMSR   Format = "mod"
	FormatVCDIFF Format = "vcdiff"
)

type ValidationInfo struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

type Patch interface {
	Format() Format
	Apply(source []byte, options ApplyOptions) ([]byte, error)
	ValidateSource(source []byte) bool
	ValidationInfo() *ValidationInfo
	Description() string
	MarshalBinary() ([]byte, error)
}

type ApplyOptions struct {
	Validate, RemoveHeader, AddHeader, FixChecksum bool
	SourceName                                     string
	// Context cancels long-running patch operations. Nil means context.Background.
	Context context.Context
	// Progress receives coarse, monotonic progress updates. Callbacks must return
	// quickly; they run synchronously with patching.
	Progress func(Progress)
	// MaxOutputSize caps allocations from untrusted patches. Zero chooses a
	// source-relative default (64 MiB plus twice the source size).
	MaxOutputSize uint64
}

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

type CreateOptions struct {
	Metadata    map[string]string
	Description string
	SourceName  string
	// BPSDelta forces delta matching. By default it is used for files up to 4 MiB.
	BPSDelta bool
}

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

func Create(original, modified []byte, format Format, opts *CreateOptions) (Patch, error) {
	switch Format(strings.ToLower(strings.TrimSpace(string(format)))) {
	case FormatIPS:
		return createIPS(original, modified, nil)
	case FormatIPS32:
		return createIPS32(original, modified)
	case FormatEBP:
		metadata := map[string]string{}
		if opts != nil {
			for k, v := range opts.Metadata {
				metadata[k] = v
			}
		}
		return createIPS(original, modified, metadata)
	case FormatUPS:
		return createUPS(original, modified), nil
	case FormatAPSN64:
		if uint64(len(modified)) > uint64(^uint32(0)) {
			return nil, fmt.Errorf("%w: APS output exceeds 32-bit size", ErrUnsupported)
		}
		name := ""
		if opts != nil {
			name = opts.SourceName
		}
		return createAPSN64(original, modified, name), nil
	case FormatBPS:
		delta := len(original) <= 4<<20
		if opts != nil && opts.BPSDelta {
			delta = true
		}
		return createBPS(original, modified, delta), nil
	case FormatRUP:
		desc := ""
		if opts != nil {
			desc = opts.Description
		}
		return createRUP(original, modified, desc), nil
	case FormatPPF:
		if len(modified) < len(original) {
			return nil, fmt.Errorf("%w: PPF cannot represent a smaller output", ErrUnsupported)
		}
		return createPPF(original, modified), nil
	default:
		return nil, fmt.Errorf("%w: cannot create %q patches", ErrUnsupported, format)
	}
}

func Apply(source, patchData []byte, options ApplyOptions) ([]byte, error) {
	p, err := Parse(patchData)
	if err != nil {
		return nil, err
	}
	return ApplyParsedWithOptions(source, p, options)
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

func (basePatch) ValidateSource([]byte) bool      { return true }
func (basePatch) ValidationInfo() *ValidationInfo { return nil }
func (basePatch) Description() string             { return "" }
