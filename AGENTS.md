# RomPatcher.go Engineering Guidelines

These rules apply to all work in this repository.

## Project scope

- Keep this repository focused on the Go patching library, CLI, tests, and
  release tooling. Do not restore the former web frontend or JavaScript engine.
- Preserve compatibility with supported real-world patch formats. Patch
  creation is in scope where the format is supported.
- Prefer the Go standard library. A third-party dependency is acceptable only
  when it provides substantial format compatibility and its license is
  compatible, documented, and included in release archives.
- Do not add CI workflows, SBOM generation, telemetry, or unrelated tooling
  unless explicitly requested.

## Architecture and maintainability

- Maintain one canonical implementation for each operation. Memory APIs should
  adapt to the file-backed engine rather than duplicate patch logic.
- Fix patterns, not isolated symptoms. Put shared lifecycle, validation,
  progress, hashing, I/O, and publication behavior in reusable helpers.
- Keep format-specific behavior inside the relevant format engine. Generalize
  closely related formats when doing so removes duplication without obscuring
  their specifications.
- Avoid parallel implementations, temporary compatibility layers, and copied
  algorithms. Refactor existing code before adding another path.
- Keep responsibilities clear: parsing validates structure, engines apply or
  create data, file APIs manage files, and the CLI handles user interaction.
- Prefer small, explicit interfaces built around `io.ReaderAt`, `io.WriterAt`,
  and `io.Writer`.

## Performance and scalability

- File-backed application and creation are the default. Do not load complete
  ROMs or patches into memory unless the operation explicitly requires it.
- Treat BPS delta matching and ROM header/checksum compatibility transforms as
  explicit memory-backed exceptions.
- Keep memory bounded independently of input size. Reuse scratch buffers and
  avoid allocations inside record, byte, and window loops.
- Stream hashing and validation. Do not add an extra full-file pass when the
  same result can be collected during an existing scan.
- Preserve useful sequential access patterns and reasonably sized buffers.
- Optimize based on benchmarks, allocation measurements, profiles, or a clear
  complexity improvement. Never trade correctness or readability for a
  speculative micro-optimization.
- Prevent quadratic behavior on repeated or adversarial input. Apply explicit
  limits to expensive searches and decompression.
- Batch operations may remain sequential unless parallelism demonstrates a
  meaningful real-world benefit without excessive memory or complexity.

## Correctness and safety

- Treat patch files and archives as untrusted input.
- Validate signatures, lengths, flags, checksums, offsets, integer conversions,
  arithmetic overflow, output bounds, decompression limits, and trailing data.
- Malformed input must return a useful error, never panic or silently truncate.
- Honor `context.Context` throughout long reads, writes, scans, hashing,
  matching, decompression, and record processing.
- Keep progress phases consistent. Report `complete` only after all output has
  been successfully written.
- File outputs must use a temporary file, sync successfully, and be published
  atomically without replacing an existing destination.
- Resolve and verify exact paths before destructive cleanup. Never modify or
  redistribute users' ROMs or third-party test patches.

## Public API and CLI

- Keep exported APIs idiomatic, documented, and usable without access to
  private record types. Return independent inspection data rather than aliases
  to mutable internal state.
- Preserve consistent behavior between memory-backed and file-backed APIs.
- Use short, related CLI flags and plain command names. Reject conflicting or
  format-specific options before expensive I/O.
- Keep human output concise and send machine-readable JSON only when requested.
- Preserve stdin/stdout support where the command can implement it safely.
- Existing files must never be overwritten implicitly.

## Testing and verification

- Format changed Go files with `gofmt`.
- Run `go test -count=1 ./...`, `go test -race -count=1 ./...`, `go vet ./...`,
  `go mod verify`, and `git diff --check` after meaningful engine changes.
- Add regression tests for every bug fix and for shared behavior introduced by
  a refactor.
- Use fuzzing for parsers and file-backed application after decoder changes.
- Benchmark performance-sensitive work with `-benchmem`; record meaningful
  before/after results.
- Verify apply compatibility and creator round trips with the external test
  corpus when available. Never add game files to the repository.
- Ensure tests and production binaries compile for every advertised release
  target. Verify release checksums and bundled license files.

## Repository hygiene

- Do not commit, stage, push, tag, create releases, or rewrite history unless
  the user explicitly requests that exact action.
- Preserve user changes and avoid touching unrelated files.
- Do not leave audit binaries, temporary outputs, caches, local paths, email
  addresses, credentials, or other personal information in the repository.
- Keep required attribution to RomPatcher.js and all dependency notices intact.
- Keep documentation accurate when behavior, flags, formats, or limitations
  change.
