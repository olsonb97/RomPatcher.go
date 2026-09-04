# RomPatcher.go

A native Go library and command-line ROM patcher, rewritten from
[RomPatcher.js](https://github.com/marcrobledo/RomPatcher.js) by Marc Robledo.
This repository contains the patching engine and CLI only; it has no web
frontend. Building from source requires Go 1.21 or newer. Prebuilt binaries are
self-contained and do not require a Go installation.

## AI-assisted development

This Go rewrite was developed with substantial assistance from OpenAI Codex.
Although it has been reviewed and tested, AI-assisted code can contain mistakes.
Users should independently evaluate and test it for their use case.

## Format support

| Format | Apply | Create | Source/target validation |
| --- | --- | --- | --- |
| IPS / IPS32 / EBP | Yes | Yes | — |
| UPS | Yes, forward or reverse | Yes | Size + source/target CRC32 |
| BPS | Yes | Yes | Size + source/target CRC32 |
| APS (N64) | Yes | Yes | N64 cart ID + stored header CRC |
| APS (GBA) | Yes | No | Source size + per-block CRC16 |
| RUP / NINJA2 | Yes, forward or reverse | Yes | Source/target MD5 |
| PPF 1–3 | Yes, including undo when present | Yes | Size, block check, and undo records when present |
| BSDIFF40 (`.bdf` / `.bspatch`) | Yes | No | — |
| Paper Mario Star Rod (`.mod`) | Yes | No | Fixed source size + CRC32 |
| VCDIFF / xdelta | Yes, including xdelta3 LZMA | No | Optional per-window Adler-32 |

Validation refers to checks enabled by `ApplyOptions.Validate` or CLI `-v`.
Invalid headers, payloads, and embedded patch checksums are rejected as they
are decoded.
PPF creation cannot represent an output smaller than its input.

VCDIFF supports RFC 3284 default and custom code tables, source/target windows,
configurable address caches, Adler-32 validation, and xdelta3's common LZMA
secondary compression through the pure-Go `github.com/ulikunitz/xz` package.
DJW and FGK secondary compression are detected and reported as unsupported.

## Installation

Download a platform archive from
[GitHub Releases](https://github.com/olsonb97/RomPatcher.go/releases/latest), or
install the latest version with Go:

```console
go install github.com/olsonb97/RomPatcher.go/cmd/rompatcher@latest
```

## Library

```go
output, err := rompatcher.Apply(sourceBytes, patchBytes,
    rompatcher.ApplyOptions{Validate: true})

// Select an endpoint explicitly when automatic UPS/RUP detection is ambiguous.
output, err = rompatcher.Apply(sourceBytes, patchBytes,
    rompatcher.ApplyOptions{Direction: rompatcher.ApplyDirectionReverse})

created, err := rompatcher.Create(original, modified, rompatcher.FormatBPS, nil)
patchBytes, err := created.MarshalBinary()

// Cancellable, bounded-memory patching and creation.
size, err := rompatcher.ApplyReaderAt(ctx, source, sourceSize, patchFile,
    patchSize, output, options)
size, err = rompatcher.CreateReaderAt(ctx, originalFile, originalSize,
    modifiedFile, modifiedSize, patchOutput, rompatcher.FormatBPS, nil)
```

`ApplyOptions` supports cancellation, progress callbacks, an output-size limit,
explicit UPS/RUP direction, temporary iNES, FDS, Lynx, or SNES header-sized
compatibility data, and Game Boy or Mega Drive/Genesis internal checksum repair.
`CanAddHeaderSize` and `DetectHeaderSize` expose size-only header checks for
file-backed callers. The default output limit is 64 MiB plus twice the source
size.

`ApplyReaderAt` and `ApplyFile` keep the source and output file-backed for every
supported format and decode patch records incrementally. `CreateReaderAt` and
`CreateFile` also keep both input files out of memory unless BPS delta matching
is explicitly enabled. VCDIFF retains only the current target window. Header
and checksum compatibility transformations use the memory-backed path.
`ApplyFileChain` uses temporary files between patches. `Inspect`, `DryRun`, and
`ApplyChain` provide their in-memory counterparts.

## CLI

```console
rompatcher apply game.sfc translation.bps -v -o game-patched.sfc
rompatcher apply patched.gba translation.ups -d reverse -o original.gba
rompatcher apply --dry-run --json game.sfc translation.bps
rompatcher apply games.zip patch.bps -s "region/game.sfc" -o game.sfc
rompatcher apply game.sfc base.bps addon.ips -v -o final.sfc
rompatcher archive games.zip
rompatcher create original.sfc modified.sfc -f bps -o patch.bps
rompatcher inspect --json patch.bps
rompatcher hash game.sfc
rompatcher batch jobs.json
rompatcher version
```

### Applying patches

`rompatcher apply SOURCE PATCH [PATCH...]` applies patches from left to right.
Useful options are `-o` for output, `-v` to validate, `-n` for a dry run, `-j`
for JSON, and `-d` for UPS/RUP direction. Run `rompatcher apply --help` for the
rest. Explicit direction accepts `forward` or `reverse` and requires one patch.

ZIP files are supported, but 7z files are not. If a ZIP contains multiple
choices, run `rompatcher archive FILE.zip`, then select one with `-s` for the
source or `-e` for a patch. Use `-` for stdin or stdout where applicable.
Existing output files are never overwritten.

### Batch manifests

`rompatcher batch jobs.json` accepts this structure:

```json
{
  "jobs": [{
    "source": "games.zip",
    "sourceEntry": "region/game.sfc",
    "patches": [{"path": "translation.bps"}, {"path": "fix.ips"}],
    "output": "game-patched.sfc",
    "validate": true,
    "removeHeader": false,
    "addHeader": false,
    "fixChecksum": true
  }]
}
```

Each job requires `source`, `patches`, and `output`; `output` is optional with
`batch -n`. Optional fields are `sourceEntry`, `validate`, `removeHeader`,
`addHeader`, `fixChecksum`, `direction`, and `maxOutput`. Direction accepts
`auto`, `forward`, or `reverse` and requires one patch. Each patch requires
`path` and may include `entry` for ZIP selection.

## Building release archives

The build script requires Python 3 and Go. With no `-t` options it builds all
nine targets:

```console
python build_release.py 1.0.1
```

Use `-t` to select one or more targets:

```console
python build_release.py 1.0.1 -t windows/amd64
python build_release.py 1.0.1 -t windows/amd64,linux/amd64
python build_release.py --list-targets
```

Use `-o DIR` to change the output directory. Archives include the license files,
and their SHA-256 hashes are written to `checksums.txt`.

## License

RomPatcher.go is MIT-licensed and retains the original RomPatcher.js copyright
and license notice. Its pure-Go XZ dependency and the Go standard library are
BSD-3-Clause; the exact required attributions are tracked in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and bundled in every release
archive alongside [`LICENSE`](LICENSE).

## Verification

```console
go test ./...
go vet ./...
go test -bench . -benchmem
```

The tests cover every supported apply format and every supported creator,
malformed-input safety, resizing, cancellation, atomic output, ZIP ambiguity,
chains, custom VCDIFF tables, LZMA secondary compression, reversible UPS and
RUP, header handling, and known patch checksums. An optional real-world corpus
harness provides broader compatibility coverage without redistributing
third-party patches or game data.
