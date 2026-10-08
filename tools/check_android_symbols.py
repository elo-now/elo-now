#!/usr/bin/env python3
"""Verify that a release APK and separate Rust symbols describe the same ELF.

This checks build artifacts, not successful processing of a crash by Firebase.
Use llvm-readelf from the NDK selected by the Android build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def verify(apk: Path, unstripped: Path, symbols: Path, readelf: Path, abi: str):
    def inspect(path: Path, option: str) -> str:
        return subprocess.check_output([str(readelf), option, str(path)], text=True)

    def build_id(path: Path) -> str:
        match = re.search(r"Build ID: ([0-9a-f]+)", inspect(path, "-n"))
        if not match:
            raise ValueError(f"Missing GNU build ID in {path.name}")
        return match[1]

    def has_line_tables(path: Path) -> bool:
        return bool(re.search(r"\s\.debug_line\s", inspect(path, "-SW")))

    with tempfile.TemporaryDirectory(prefix="elo-android-symbols-") as directory:
        packaged = Path(directory) / "packaged.so"
        detached = Path(directory) / "separate.so.dbg"
        entry = f"lib/{abi}/libelo_app_lib.so"
        symbol_entry = f"{abi}/libelo_app_lib.so.dbg"
        with zipfile.ZipFile(apk) as archive:
            if archive.namelist().count(entry) != 1:
                raise ValueError("APK must contain exactly one Rust library for the ABI")
            packaged.write_bytes(archive.read(entry))
        with zipfile.ZipFile(symbols) as archive:
            if archive.namelist().count(symbol_entry) != 1:
                raise ValueError("Native symbol archive is missing the matching Rust entry")
            detached.write_bytes(archive.read(symbol_entry))
        if re.search(r"\s\.debug_(?:info|line)\s", inspect(packaged, "-SW")):
            raise ValueError("Release APK contains private Rust debug information")
        if not has_line_tables(unstripped) or not has_line_tables(detached):
            raise ValueError("Both unstripped and detached symbols need Rust line tables")
        identifiers = [build_id(path) for path in (packaged, unstripped, detached)]
        if len(set(identifiers)) != 1:
            raise ValueError("Packaged, unstripped and detached ELF build IDs differ")
        return {
            "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
            "apk_bytes": apk.stat().st_size,
            "abi": abi,
            "build_id": identifiers[0],
            "build_ids_match": True,
            "apk_debug_sections_absent": True,
            "private_line_tables_present": True,
            "separate_native_symbols_entry": symbol_entry,
            "packaged_rust_bytes": packaged.stat().st_size,
            "unstripped_rust_bytes": unstripped.stat().st_size,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--unstripped", type=Path, required=True)
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--readelf", type=Path, required=True)
    parser.add_argument("--abi", choices=["arm64-v8a", "armeabi-v7a", "x86", "x86_64"], default="arm64-v8a")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.apk, args.unstripped, args.symbols, args.readelf, args.abi), indent=2))
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Symbol verification failed: {error}\n")
