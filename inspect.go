package rompatcher

import "fmt"

type ArtifactInfo struct {
	Size   *uint64           `json:"size,omitempty"`
	Hashes map[string]string `json:"hashes,omitempty"`
}

type Inspection struct {
	Format      Format          `json:"format"`
	Description string          `json:"description,omitempty"`
	Source      ArtifactInfo    `json:"source,omitempty"`
	Target      ArtifactInfo    `json:"target,omitempty"`
	Validation  *ValidationInfo `json:"validation,omitempty"`
	Reversible  bool            `json:"reversible"`
	CanCreate   bool            `json:"canCreate"`
	RecordCount int             `json:"recordCount,omitempty"`
	// RecordCountKnown distinguishes a valid empty patch from a lazily decoded
	// format whose record count is unavailable without applying it.
	RecordCountKnown bool              `json:"recordCountKnown"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	Limitations      []string          `json:"limitations,omitempty"`
}

type DryRunResult struct {
	Inspection  Inspection   `json:"inspection"`
	SourceValid *bool        `json:"sourceValid,omitempty"`
	Output      ArtifactInfo `json:"output"`
}

func sizePtr(n uint64) *uint64 { return &n }

func Inspect(data []byte) (Inspection, error) {
	p, err := Parse(data)
	if err != nil {
		return Inspection{}, err
	}
	return InspectParsed(p), nil
}

func InspectParsed(p Patch) Inspection {
	i := Inspection{Format: p.Format(), Description: p.Description(), Validation: p.ValidationInfo()}
	switch p.Format() {
	case FormatIPS, FormatIPS32, FormatEBP, FormatUPS, FormatBPS, FormatAPSN64, FormatRUP, FormatPPF:
		i.CanCreate = true
	}
	switch x := p.(type) {
	case *IPSPatch:
		i.RecordCountKnown = true
		i.RecordCount = len(x.Records)
		i.Metadata = x.Metadata
		if x.HasTruncate {
			i.Target.Size = sizePtr(uint64(x.Truncate))
		}
	case *IPS32Patch:
		i.RecordCountKnown = true
		i.RecordCount = len(x.Records)
		if x.HasTruncate {
			i.Target.Size = sizePtr(uint64(x.Truncate))
		}
	case *UPSPatch:
		i.RecordCountKnown = true
		i.RecordCount = len(x.Records)
		i.Reversible = true
		i.Source.Size, i.Target.Size = sizePtr(x.SourceSize), sizePtr(x.TargetSize)
		i.Source.Hashes = map[string]string{"crc32": fmt.Sprintf("%08x", x.SourceCRC)}
		i.Target.Hashes = map[string]string{"crc32": fmt.Sprintf("%08x", x.TargetCRC)}
	case *BPSPatch:
		i.RecordCountKnown = true
		i.RecordCount = len(x.Actions)
		i.Source.Size, i.Target.Size = sizePtr(x.SourceSize), sizePtr(x.TargetSize)
		i.Source.Hashes = map[string]string{"crc32": fmt.Sprintf("%08x", x.SourceCRC)}
		i.Target.Hashes = map[string]string{"crc32": fmt.Sprintf("%08x", x.TargetCRC)}
	case *APSN64Patch:
		i.RecordCountKnown = true
		i.RecordCount = len(x.Records)
		i.Target.Size = sizePtr(uint64(x.TargetSize))
	case *APSGBAPatch:
		i.RecordCountKnown = true
		i.RecordCount = len(x.Records)
		i.Source.Size, i.Target.Size = sizePtr(uint64(x.SourceSize)), sizePtr(uint64(x.TargetSize))
	case *RUPPatch:
		i.RecordCountKnown = true
		i.Reversible = true
		for _, f := range x.Files {
			i.RecordCount += len(f.Records)
		}
		if len(x.Files) == 1 {
			f := x.Files[0]
			i.Source.Size, i.Target.Size = sizePtr(f.SourceSize), sizePtr(f.TargetSize)
			i.Source.Hashes = map[string]string{"md5": f.SourceMD5}
			i.Target.Hashes = map[string]string{"md5": f.TargetMD5}
		}
	case *PPFPatch:
		i.RecordCountKnown = true
		i.RecordCount, i.Reversible = len(x.Records), x.Undo
		if x.InputSize != 0 {
			i.Source.Size = sizePtr(uint64(x.InputSize))
		}
	case *BDFPatch:
		i.RecordCountKnown = !x.compressed
		i.RecordCount, i.Target.Size = len(x.Records), sizePtr(x.TargetSize)
		i.Limitations = []string{"creation is not supported"}
		if x.compressed {
			i.Limitations = append(i.Limitations, "record count is decoded during application")
		}
	case *PMSRPatch:
		i.RecordCountKnown = true
		i.RecordCount, i.Target.Size = len(x.Records), sizePtr(uint64(x.TargetSize))
		i.Limitations = []string{"creation is not supported"}
	case *VCDIFFPatch:
		i.RecordCountKnown, i.RecordCount = true, x.windowCount
		i.Limitations = []string{"creation is not supported"}
		if x.secondaryID != 0 {
			i.Metadata = map[string]string{
				"secondaryCompressor":   vcdSecondaryName(x.secondaryID),
				"secondaryCompressorID": fmt.Sprintf("%d", x.secondaryID),
			}
			if x.secondaryID != vcdLZMASecondaryID {
				i.Limitations = append([]string{vcdSecondaryName(x.secondaryID) + " secondary compression is not supported"}, i.Limitations...)
			}
		}
	}
	return i
}

func DryRun(source, patchData []byte, opts ApplyOptions) (DryRunResult, error) {
	p, err := Parse(patchData)
	if err != nil {
		return DryRunResult{}, err
	}
	result := DryRunResult{Inspection: InspectParsed(p)}
	if p.ValidationInfo() != nil {
		valid := p.ValidateSource(source)
		result.SourceValid = &valid
	}
	out, err := ApplyParsedWithOptions(source, p, opts)
	if err != nil {
		return result, err
	}
	hashes := HashBytes(out)
	result.Output.Size = sizePtr(uint64(hashes.Size))
	result.Output.Hashes = map[string]string{
		"crc32": hashes.CRC32,
		"md5":   hashes.MD5,
		"sha1":  hashes.SHA1,
	}
	return result, nil
}
