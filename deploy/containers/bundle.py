#!/usr/bin/env python3
"""Create a server-only Docker context; never send a working checkout to Docker."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import tomllib

SERVERS = ("elo-core", "elo-team", "elo-witness", "elo-storage")
EXTENSIONS = {".rs", ".toml", ".sql", ".html"}


def locked_servers(text):
    """Keep the original locked versions/checksums and their transitive closure."""
    blocks = text.split("[[package]]")
    packages = [tomllib.loads("[[package]]" + block)["package"][0] for block in blocks[1:]]
    pending = [i for i, package in enumerate(packages) if package["name"] in SERVERS]
    selected = set()
    while pending:
        index = pending.pop()
        if index in selected:
            continue
        selected.add(index)
        for dependency in packages[index].get("dependencies", []):
            parts = dependency.split(" ")
            matches = [i for i, package in enumerate(packages)
                       if package["name"] == parts[0]
                       and (len(parts) == 1 or package["version"] == parts[1])
                       and (len(parts) < 3 or "(" + package.get("source", "") + ")" == parts[2])]
            if len(matches) != 1:
                raise ValueError("Ambiguous or missing locked dependency: " + dependency)
            pending.extend(matches)
    return blocks[0] + "".join("[[package]]" + blocks[i + 1] for i in sorted(selected))


def bundle(source, output):
    source = source.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise ValueError("Output must not exist; contexts are never overwritten.")
    output = output.absolute()
    if output.is_relative_to(source):
        raise ValueError("Create the context outside the source checkout.")
    paths = [Path(name) for name in ("rust-toolchain.toml", "LICENSE", "protocol/reactions.json")]
    for name in SERVERS:
        root = source / "crates" / name
        for path in root.rglob("*"):
            relative = path.relative_to(source)
            if any(part.startswith(".") or part in {"target", "build", "runtime", "credentials"}
                   for part in relative.parts):
                continue
            if path.suffix in EXTENSIONS and (relative.name == "Cargo.toml" or "src" in relative.parts):
                paths.append(relative)
    paths.extend(path.relative_to(source) for path in (source / "migrations").glob("*.sql"))
    paths.extend(Path("protocol/fixtures") / name for name in
                 ("chat-message-v1.record.bin", "chat-message-v1.expected.json", "chat-message-v1.body.json"))
    paths.extend(Path("deploy/containers") / name for name in
                 ("Dockerfile", ".dockerignore", "Dockerfile.dockerignore", "entrypoint.sh", "activate.py", "verify_lock.py"))
    # Reject links before copying anything. Only enumerated source files enter the context.
    for relative in paths:
        path = source / relative
        for ancestor in (path, *path.parents):
            if ancestor == source:
                break
            if ancestor.is_symlink():
                raise ValueError("Symlink rejected: " + str(relative))
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("Not a regular source file: " + str(relative))
    manifest = (source / "Cargo.toml").read_text()
    manifest = re.sub(r"^members = .*?$", "members = " + json.dumps(["crates/" + name for name in SERVERS]),
                      manifest, count=1, flags=re.MULTILINE)
    # Every current patch is client-only; server builds must not include vendored mobile code.
    manifest = manifest.split("[patch.crates-io]", 1)[0]
    if tomllib.loads(manifest)["workspace"]["members"] != ["crates/" + name for name in SERVERS]:
        raise ValueError("Workspace layout changed; review the context builder.")
    lock = locked_servers((source / "Cargo.lock").read_text())
    output.mkdir(mode=0o700, parents=False)
    for relative in sorted(set(paths)):
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, destination)
    (output / "Cargo.toml").write_text(manifest)
    (output / "Cargo.lock").write_text(lock)
    shutil.copyfile(output / "deploy/containers/.dockerignore", output / ".dockerignore")
    inventory = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(output.rglob("*")) if path.is_file()}
    (output / "source-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    return len(inventory)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(f"Created context with {bundle(args.source, args.output)} source files: {args.output}")
