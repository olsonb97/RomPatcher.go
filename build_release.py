#!/usr/bin/env python3
"""Build and package RomPatcher.go release binaries."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


TARGETS = {
    "windows/amd64": ("windows", "amd64", None, "amd64", "zip", "rompatcher.exe"),
    "windows/386": ("windows", "386", None, "386", "zip", "rompatcher.exe"),
    "windows/arm64": ("windows", "arm64", None, "arm64", "zip", "rompatcher.exe"),
    "linux/amd64": ("linux", "amd64", None, "amd64", "tar.gz", "rompatcher"),
    "linux/386": ("linux", "386", None, "386", "tar.gz", "rompatcher"),
    "linux/arm64": ("linux", "arm64", None, "arm64", "tar.gz", "rompatcher"),
    "linux/armv7": ("linux", "arm", "7", "armv7", "tar.gz", "rompatcher"),
    "darwin/amd64": ("darwin", "amd64", None, "amd64", "tar.gz", "rompatcher"),
    "darwin/arm64": ("darwin", "arm64", None, "arm64", "tar.gz", "rompatcher"),
}
VERSION_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cross-compile and package RomPatcher.go releases."
    )
    parser.add_argument(
        "version",
        nargs="?",
        help="release version, such as 1.0.1 or v1.0.1",
    )
    parser.add_argument(
        "-t",
        "--target",
        action="append",
        default=[],
        metavar="OS/ARCH",
        help="target to build; repeat or comma-separate (default: all)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="DIR",
        help="output directory (default: dist/vVERSION)",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="print supported targets and exit",
    )
    return parser.parse_args()


def selected_targets(values: list[str]) -> list[str]:
    if not values:
        return list(TARGETS)
    selected: list[str] = []
    for value in values:
        for target in value.split(","):
            target = target.strip().lower()
            if not target:
                continue
            if target not in TARGETS:
                raise ValueError(
                    f"unknown target {target!r}; use --list-targets to see valid targets"
                )
            if target not in selected:
                selected.append(target)
    if not selected:
        raise ValueError("at least one non-empty target is required")
    return selected


def run(command: list[str], root: Path, env: dict[str, str]) -> None:
    subprocess.run(command, cwd=root, env=env, check=True)


def main() -> int:
    args = parse_args()
    if args.list_targets:
        print("\n".join(TARGETS))
        return 0
    if not args.version:
        print("error: VERSION is required unless --list-targets is used", file=sys.stderr)
        return 2
    match = VERSION_RE.fullmatch(args.version)
    if not match:
        print("error: VERSION must look like 1.2.3 or v1.2.3-beta.1", file=sys.stderr)
        return 2
    try:
        targets = selected_targets(args.target)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if shutil.which("go") is None:
        print("error: Go is not installed or is not on PATH", file=sys.stderr)
        return 1

    root = Path(__file__).resolve().parent
    version_number = match.group(1)
    display_version = f"v{version_number}"
    output = (
        args.output.expanduser().resolve()
        if args.output
        else root / "dist" / display_version
    )
    if output.exists():
        print(f"error: output directory already exists: {output}", file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=".rompatcher-release-", dir=output.parent)
    )
    work = staging / ".work"
    work.mkdir()

    base_env = os.environ.copy()
    for name in ("GOOS", "GOARCH", "GOARM"):
        base_env.pop(name, None)
    base_env["CGO_ENABLED"] = "0"
    releasepack = work / ("releasepack.exe" if os.name == "nt" else "releasepack")

    try:
        run(
            ["go", "build", "-trimpath", "-o", str(releasepack), "./cmd/releasepack"],
            root,
            base_env,
        )
        checksums: list[str] = []
        for target_name in targets:
            goos, goarch, goarm, label, archive_type, binary_name = TARGETS[target_name]
            print(f"Building {target_name}...", flush=True)
            target_env = base_env.copy()
            target_env.update({"GOOS": goos, "GOARCH": goarch})
            if goarm:
                target_env["GOARM"] = goarm
            else:
                target_env.pop("GOARM", None)

            target_work = work / target_name.replace("/", "-")
            target_work.mkdir()
            binary = target_work / binary_name
            artifact = f"rompatcher_{version_number}_{goos}_{label}"
            archive = staging / f"{artifact}.{archive_type}"
            run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-ldflags",
                    f"-s -w -X main.version={display_version}",
                    "-o",
                    str(binary),
                    "./cmd/rompatcher",
                ],
                root,
                target_env,
            )
            run(
                [
                    str(releasepack),
                    "-binary",
                    str(binary),
                    "-output",
                    str(archive),
                ],
                root,
                base_env,
            )
            checksum_file = Path(f"{archive}.sha256")
            checksums.append(checksum_file.read_text(encoding="ascii").strip())
            checksum_file.unlink()

        (staging / "checksums.txt").write_text(
            "\n".join(sorted(checksums, key=lambda line: line.split(maxsplit=1)[1]))
            + "\n",
            encoding="ascii",
        )
        shutil.rmtree(work)
        staging.rename(output)
    except KeyboardInterrupt:
        shutil.rmtree(staging, ignore_errors=True)
        print("error: release build interrupted", file=sys.stderr)
        return 130
    except (OSError, subprocess.CalledProcessError) as error:
        shutil.rmtree(staging, ignore_errors=True)
        print(f"error: release build failed: {error}", file=sys.stderr)
        return 1

    print(f"Release files created in {output}")
    for path in sorted(output.iterdir()):
        if path.is_file():
            print(f"  {path.name} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
