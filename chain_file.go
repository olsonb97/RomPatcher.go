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
		return result, err
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
		patch, openErr := os.Open(patchPath)
		if openErr != nil {
			return result, fmt.Errorf("patch %d: open: %w", index+1, openErr)
		}
		patchInfo, statErr := patch.Stat()
		if statErr != nil {
			_ = patch.Close()
			return result, fmt.Errorf("patch %d: stat: %w", index+1, statErr)
		}
		format, formatErr := formatReaderAt(ctx, patch, patchInfo.Size())
		if formatErr != nil {
			_ = patch.Close()
			return result, fmt.Errorf("patch %d: %w", index+1, formatErr)
		}
		tmp, createErr := os.CreateTemp(destinationDir, ".rompatcher-chain-*")
		if createErr != nil {
			_ = patch.Close()
			return result, fmt.Errorf("patch %d: create temporary output: %w", index+1, createErr)
		}
		tmpPath := tmp.Name()
		keepTemp := false
		func() {
			defer func() {
				_ = tmp.Close()
				_ = patch.Close()
				if !keepTemp {
					_ = os.Remove(tmpPath)
				}
			}()
			stepOptions := opts
			stepOptions.Context = ctx
			if index+1 < len(patchPaths) {
				stepOptions.FixChecksum = false
			}
			var size int64
			size, err = ApplyReaderAt(ctx, current, currentSize, patch, patchInfo.Size(), tmp, stepOptions)
			if err != nil {
				err = fmt.Errorf("patch %d (%s): %w", index+1, format, err)
				return
			}
			if err = tmp.Truncate(size); err != nil {
				err = fmt.Errorf("patch %d: truncate output: %w", index+1, err)
				return
			}
			if err = tmp.Sync(); err != nil {
				err = fmt.Errorf("patch %d: sync output: %w", index+1, err)
				return
			}
			if err = tmp.Close(); err != nil {
				err = fmt.Errorf("patch %d: close output: %w", index+1, err)
				return
			}
			var verify *os.File
			verify, err = os.Open(tmpPath)
			if err != nil {
				return
			}
			var hashes HashInfo
			hashes, err = HashReader(ctx, verify)
			_ = verify.Close()
			if err != nil {
				return
			}
			result.Steps = append(result.Steps, ChainStep{
				Index:      index + 1,
				Inspection: Inspection{Format: format},
				Output: ArtifactInfo{Size: sizePtr(uint64(size)), Hashes: map[string]string{
					"crc32": hashes.CRC32,
					"sha1":  hashes.SHA1,
				}},
			})
			if index+1 == len(patchPaths) {
				if err = reportProgress(opts, Progress{Phase: "chain", Completed: int64(len(patchPaths)), Total: int64(len(patchPaths))}); err != nil {
					return
				}
				if err = publishTemp(tmpPath, outputPath); err != nil {
					return
				}
				return
			}
			if closeErr := current.Close(); closeErr != nil {
				err = closeErr
				return
			}
			if currentOwned {
				_ = os.Remove(currentPath)
			}
			current, err = os.Open(tmpPath)
			if err != nil {
				return
			}
			currentPath, currentOwned, currentSize = tmpPath, true, size
			keepTemp = true
		}()
		if err != nil {
			return result, err
		}
	}
	return result, nil
}
