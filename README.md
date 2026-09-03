# RomPatcher.go

A native, lightweight Go rewrite of
[RomPatcher.js](https://github.com/marcrobledo/RomPatcher.js) by Marc Robledo,
providing the patching engine and CLI without the web frontend.
The library requires Go 1.21 or newer; release binaries require no Go runtime.

## AI-assisted development

This Go rewrite was developed with substantial assistance from OpenAI Codex.
Although it has been reviewed and tested, AI-assisted code can contain mistakes.
Users should independently evaluate and test it for their use case.

## Format support

| Format | Apply | Create | Validation |
| --- | --- | --- | --- |
| IPS / IPS32 / EBP | Yes | Yes | — |
| UPS | Yes, bidirectional | Yes | CRC32 |
| BPS | Yes | Yes | CRC32 |
| APS (N64) | Yes | Yes | N64 cart ID + CRC |
| APS (GBA) | Yes | No (reference engine is also apply-only) | CRC16 |
| RUP / NINJA2 | Yes, including undo | Yes | MD5 |
| PPF 1–3 | Yes, including undo data | Yes | Size, block check, and undo records when present |
| BSDIFF40 (`.bdf` / `.bspatch`) | Yes | No (reference engine is also apply-only) | — |
| Paper Mario Star Rod (`.mod`) | Yes | No (reference engine is also apply-only) | CRC32 |
| VCDIFF / xdelta | Yes, including xdelta3 LZMA | No (reference engine is also apply-only) | Adler-32 windows |

VCDIFF supports RFC 3284 default and custom code tables, source/target windows,
configurable address caches, Adler-32 validation, and xdelta3's common LZMA
secondary compression through the pure-Go `github.com/ulikunitz/xz` package.
The uncommon DJW and FGK secondary compressors remain unsupported.

## Library

```go
patch, err := rompatcher.Parse(patchBytes)
output, err := patch.Apply(sourceBytes, rompatcher.ApplyOptions{Validate: true})

created, err := rompatcher.Create(original, modified, rompatcher.FormatBPS, nil)
patchBytes, err := created.MarshalBinary()

// Cancellable random-access file patching for every supported format.
size, err := rompatcher.ApplyReaderAt(ctx, source, sourceSize, patchFile,
    patchSize, output, options)
```

`ApplyWithOptions` also supports temporary copier-header removal/addition and
Game Boy or Mega Drive/Genesis internal checksum repair. `ApplyOptions` accepts
a `context.Context` and progress callback. File-backed patching keeps source and
output data out of memory; VCDIFF retains only the current target window.
Temporary header/checksum transformations use the compatibility memory path.
`Inspect`, `DryRun`, and `ApplyChain` provide structured metadata, validation
previews, and ordered patch chains.

## CLI

```console
go install github.com/olsonb97/RomPatcher.go/cmd/rompatcher@latest
rompatcher apply game.sfc translation.bps -v -o game-patched.sfc
rompatcher apply --dry-run --json game.sfc translation.bps
rompatcher apply games.zip patch.bps -s "region/game.sfc" -o game.sfc
rompatcher apply game.sfc base.bps addon.ips -v -o final.sfc
rompatcher archive games.zip
rompatcher create original.sfc modified.sfc -f bps -o patch.bps
rompatcher inspect --json patch.bps
rompatcher hash game.sfc
rompatcher version
```

Use `-` for stdin or stdout. ZIP archives use Go's built-in `archive/zip`; when
multiple ROM or patch candidates exist, the CLI refuses to guess and requires
`--source-entry` or `--patch-entry`. Outputs are written to a temporary file,
synced, and atomically published only after patching succeeds; existing outputs are preserved.
Common options have matching short forms: `-o/--output`, `-v/--validate`,
`-n/--dry-run`, `-j/--json`, `-p/--progress`, and `-m/--max-output`. Options
work before or after filenames. Supplying multiple patches to `apply` creates
an ordered chain; `chain` remains as a readable alias.

Batch mode accepts a JSON manifest:

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

The `cmd/releasepack` helper packages a manually built release binary with the
project and dependency licenses, a SHA-256 checksum, and an SPDX 2.3 SBOM.

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
```

The tests cover every format, malformed-input safety, resizing, cancellation,
atomic output, ZIP ambiguity, chains, custom VCDIFF tables, reversible RUP,
header handling, and exact known patch checksums. An optional real-world corpus
harness provides broader compatibility coverage without redistributing
third-party patches or game data.
