package rompatcher

import "fmt"

type ChainStep struct {
	Index      int          `json:"index"`
	Inspection Inspection   `json:"inspection"`
	Output     ArtifactInfo `json:"output"`
}

type ChainResult struct {
	Output []byte      `json:"-"`
	Steps  []ChainStep `json:"steps"`
}

// ApplyChain applies patches in order. Each patch receives the exact output of
// the previous patch, so validation catches an incorrectly ordered chain.
func ApplyChain(source []byte, patches [][]byte, opts ApplyOptions) (ChainResult, error) {
	if len(patches) == 0 {
		return ChainResult{}, fmt.Errorf("patch chain is empty")
	}
	current := source
	result := ChainResult{Steps: make([]ChainStep, 0, len(patches))}
	for index, data := range patches {
		if err := reportProgress(opts, Progress{Phase: "chain", Completed: int64(index), Total: int64(len(patches))}); err != nil {
			return result, err
		}
		p, err := Parse(data)
		if err != nil {
			return result, fmt.Errorf("patch %d: %w", index+1, err)
		}
		stepOptions := opts
		// Internal checksum repair is a final-output transformation. Applying it
		// between patches can invalidate the next patch's expected source bytes.
		if index+1 < len(patches) {
			stepOptions.FixChecksum = false
		}
		current, err = ApplyParsedWithOptions(current, p, stepOptions)
		if err != nil {
			return result, fmt.Errorf("patch %d (%s): %w", index+1, p.Format(), err)
		}
		hashes := HashBytes(current)
		result.Steps = append(result.Steps, ChainStep{
			Index: index + 1, Inspection: InspectParsed(p),
			Output: ArtifactInfo{Size: sizePtr(uint64(len(current))), Hashes: map[string]string{"crc32": hashes.CRC32, "sha1": hashes.SHA1}},
		})
	}
	result.Output = current
	if err := reportProgress(opts, Progress{Phase: "chain", Completed: int64(len(patches)), Total: int64(len(patches))}); err != nil {
		return result, err
	}
	return result, nil
}
