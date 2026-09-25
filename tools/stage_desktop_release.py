#!/usr/bin/env python3
"""Stage only final desktop installers and their byte-for-byte SHA256 checksums."""
import argparse
import hashlib
from pathlib import Path
import shutil


def stage(bundle: Path, output: Path) -> None:
    files = sorted(p for p in bundle.rglob("*") if p.is_file() and p.suffix in {".dmg", ".exe", ".deb", ".AppImage"})
    if not files or len({p.name for p in files}) != len(files):
        raise ValueError("Expected uniquely named desktop installers")
    # A fresh directory prevents checksums/attestations from including stale builds.
    output.mkdir(parents=True, exist_ok=False)
    checksums = []
    for source in files:
        if source.is_symlink() or not source.resolve().is_relative_to(bundle.resolve()):
            raise ValueError("Installer must be inside the build output")
        destination = output / source.name
        shutil.copyfile(source, destination)
        with destination.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        checksums.append(f"{digest}  {destination.name}\n")
    (output / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    stage(args.bundle, args.output)
