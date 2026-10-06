#!/usr/bin/env python3
"""Reject dependency changes while Cargo removes client-only feature edges."""

from pathlib import Path
import sys
import tomllib


def verify(original, normalized):
    def packages(path):
        return {(value["name"], value["version"], value.get("source"), value.get("checksum"))
                for value in tomllib.loads(path.read_text())["package"]}
    before, after = packages(original), packages(normalized)
    if not after <= before:
        raise ValueError("Server lock introduced a dependency version/source/checksum absent from the reviewed workspace lock.")
    names = {value[0] for value in after}
    if not {"elo-core", "elo-team", "elo-witness", "elo-storage", "elo-wake", "elo-call-service"} <= names:
        raise ValueError("Server lock is missing a required workspace package.")


if __name__ == "__main__":
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
