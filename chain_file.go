package rompatcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ApplyFileChain applies patch files in order using temporary files for every
// intermediate result. The final output is published atomically and is never
// allowed to replace an existing file. Result.Output is intentionally nil.
func ApplyFileChain(sourcePath string, patchPaths []string, outputPath string, opts ApplyOptions) (ChainResult, error) {
	return ApplyFileChainContext(contextOf(opts), sourcePath, patchPaths, outputPath, opts)
}

// ApplyFileChainContext is ApplyFileChain with explicit cancellation.
func ApplyFileChainContext(ctx context.Context, sourcePath string, patchPaths []string, outputPath string, opts ApplyOptions) (result ChainResult, err error) {
	if len(patchPaths) == 0 {
		return result, fmt.Errorf("patch chain is empty")
	}
	opts, err = normalizeChainOptions(len(patchPaths), opts)
	if err != nil {
		return result, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opts.Context = ctx
	if outputPath == "" {
		outputPath = DefaultPatchedPath(sourcePath)
	}
	if opts.SourceName == "" {
		opts.SourceName = sourcePath
	}
	destinationDir := filepath.Dir(outputPath)
	current, err := os.Open(sourcePath)
	if err != nil {
		return result, fmt.Errorf("open source: %w", err)
	}
	currentPath, currentOwned := sourcePath, false
	defer func() {
		_ = current.Close()
		if currentOwned {
			_ = os.Remove(currentPath)
		}
	}()
	currentInfo, err := current.Stat()
	if err != nil {
		return result, fmt.Errorf("stat source: %w", err)
	}
	if err := ensureOutputAbsent(outputPath); err != nil {
		return result, err
	}
	currentSize := currentInfo.Size()
	result.Steps = make([]ChainStep, 0, len(patchPaths))

	for index, patchPath := range patchPaths {
		if err := reportProgress(opts, Progress{Phase: "chain", Completed: int64(index), Total: int64(len(patchPaths))}); err != nil {
			return result, err
		}
		stepOptions := opts
		if index+1 < len(patchPaths) {
			stepOptions.FixChecksum = false
		}
		step, stepErr := applyFileChainStep(ctx, current, currentSize, patchPath, destinationDir, stepOptions, index+1)
		if stepErr != nil {
			return result, stepErr
		}
		result.Steps = append(result.Steps, step.result(index+1))

		if index+1 == len(patchPaths) {
			defer os.Remove(step.path)
			if err := reportProgress(opts, Progress{Phase: "chain", Completed: int64(len(patchPaths)), Total: int64(len(patchPaths))}); err != nil {
				return result, err
			}
			if err := publishTemp(step.path, outputPath); err != nil {
				return result, err
			}
			return result, nil
		}

		if err := current.Close(); err != nil {
			_ = os.Remove(step.path)
			return result, fmt.Errorf("close chain input: %w", err)
		}
		if currentOwned {
			_ = os.Remove(currentPath)
		}
		current, err = os.Open(step.path)
		if err != nil {
			_ = os.Remove(step.path)
			return result, fmt.Errorf("open intermediate output: %w", err)
		}
		currentPath, currentOwned, currentSize = step.path, true, step.size
	}
	return result, nil
}

type appliedChainFile struct {
	path   string
	size   int64
	format Format
	hashes HashInfo
}

func (step appliedChainFile) result(index int) ChainStep {
	return ChainStep{
		Index:      index,
		Inspection: Inspection{Format: step.format},
		Output: ArtifactInfo{Size: sizePtr(uint64(step.size)), Hashes: map[string]string{
			"crc32": step.hashes.CRC32,
			"sha1":  step.hashes.SHA1,
		}},
	}
}

func applyFileChainStep(ctx context.Context, source *os.File, sourceSize int64, patchPath, destinationDir string, opts ApplyOptions, index int) (step appliedChainFile, err error) {
	patch, err := os.Open(patchPath)
	if err != nil {
		return step, fmt.Errorf("patch %d: open: %w", index, err)
	}
	defer patch.Close()
	patchInfo, err := patch.Stat()
	if err != nil {
		return step, fmt.Errorf("patch %d: stat: %w", index, err)
	}
	step.format, err = formatReaderAt(ctx, patch, patchInfo.Size())
	if err != nil {
		return step, fmt.Errorf("patch %d: %w", index, err)
	}

	temporary, err := os.CreateTemp(destinationDir, ".rompatcher-chain-*")
	if err != nil {
		return step, fmt.Errorf("patch %d: create temporary output: %w", index, err)
	}
	step.path = temporary.Name()
	keepTemporary := false
	defer func() {
		_ = temporary.Close()
		if !keepTemporary {
			_ = os.Remove(step.path)
		}
	}()

	step.size, err = ApplyReaderAt(ctx, source, sourceSize, patch, patchInfo.Size(), temporary, opts)
	if err != nil {
		return step, fmt.Errorf("patch %d (%s): %w", index, step.format, err)
	}
	if err := temporary.Truncate(step.size); err != nil {
		return step, fmt.Errorf("patch %d: truncate output: %w", index, err)
	}
	if err := temporary.Sync(); err != nil {
		return step, fmt.Errorf("patch %d: sync output: %w", index, err)
	}
	if err := temporary.Close(); err != nil {
		return step, fmt.Errorf("patch %d: close output: %w", index, err)
	}

	verify, err := os.Open(step.path)
	if err != nil {
		return step, fmt.Errorf("patch %d: open output for verification: %w", index, err)
	}
	step.hashes, err = HashReader(ctx, verify)
	_ = verify.Close()
	if err != nil {
		return step, fmt.Errorf("patch %d: hash output: %w", index, err)
	}
	keepTemporary = true
	return step, nil
}
