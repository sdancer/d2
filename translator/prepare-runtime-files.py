#!/usr/bin/env python3
"""Prepare the directly translated Diablo II runtime filesystem."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path


MPQ_FILES = {
    "File00000023.mpq": "d2char.mpq",
    "File00000025.mpq": "d2data.mpq",
    "File00000032.mpq": "d2music.mpq",
    "File00000034.mpq": "d2sfx.mpq",
    "File00000036.mpq": "d2speech.mpq",
    "File00000544.mpq": "patch_d2.mpq",
}


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Map extracted Diablo II demo files into the direct runtime layout",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=root.parent / "extracted",
        help="directory containing FileNNNNNNNN PE/MPQ objects or already-named files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=root / "build" / "runtime-files" / "diablo2",
        help="directory exposed as C:\\Diablo II by the direct Win32 runtime",
    )
    parser.add_argument(
        "--filename-map",
        type=Path,
        default=root / "filename-map.json",
        help="JSON mapping extracted PE object names to their runtime names",
    )
    return parser.parse_args()


def load_mapping(path: Path) -> dict[str, str]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read filename map {path}: {error}") from error
    if not isinstance(value, dict) or not all(
        isinstance(source, str) and isinstance(destination, str)
        for source, destination in value.items()
    ):
        raise ValueError(f"filename map must be a JSON string-to-string object: {path}")

    mapping = dict(value)
    mapping.update(MPQ_FILES)
    folded_destinations: dict[str, str] = {}
    for source, destination in mapping.items():
        previous = folded_destinations.setdefault(destination.casefold(), source)
        if previous != source:
            raise ValueError(
                f"runtime destination collision: {previous} and {source} both map to {destination}"
            )
    return mapping


def locate_source(source_dir: Path, object_name: str, runtime_name: str) -> Path | None:
    for candidate in (source_dir / object_name, source_dir / runtime_name):
        if candidate.is_file():
            return candidate
    return None


def main() -> int:
    args = parse_args()
    source_dir = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()

    if not source_dir.is_dir():
        print(f"source directory does not exist: {source_dir}", file=sys.stderr)
        return 2

    try:
        mapping = load_mapping(args.filename_map.resolve())
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    resolved: list[tuple[Path, str]] = []
    missing: list[tuple[str, str]] = []
    for object_name, runtime_name in mapping.items():
        source = locate_source(source_dir, object_name, runtime_name)
        if source is None:
            missing.append((object_name, runtime_name))
        else:
            resolved.append((source, runtime_name))

    if missing:
        print(f"missing {len(missing)} required demo files in {source_dir}:", file=sys.stderr)
        for object_name, runtime_name in missing:
            print(f"  {object_name} (or {runtime_name})", file=sys.stderr)
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    byte_count = 0
    for source, runtime_name in resolved:
        destination = output_dir / runtime_name
        temporary = output_dir / f".{runtime_name}.tmp"
        try:
            shutil.copy2(source, temporary)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        byte_count += destination.stat().st_size

    print(
        f"Prepared {len(resolved)} files / {byte_count} bytes in {output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
